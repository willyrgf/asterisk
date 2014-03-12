/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * Mark Michelson <mmichelson@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "asterisk.h"

#include <pjsip.h>
#include <pjlib.h>

#include "asterisk/res_pjsip.h"
#include "include/res_pjsip_private.h"
#include "asterisk/sorcery.h"
#include "asterisk/ast_version.h"
#include "asterisk/dns.h"

#define DEFAULT_MAX_FORWARDS 70
#define DEFAULT_USERAGENT_PREFIX "Asterisk PBX"
#define DEFAULT_OUTBOUND_ENDPOINT "default_outbound_endpoint"
#define DEFAULT_NAMESERVERS "auto"

static char default_useragent[128];

struct global_config {
	SORCERY_OBJECT(details);
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(useragent);
		AST_STRING_FIELD(default_outbound_endpoint);
		/*! Debug logging yes|no|host */
		AST_STRING_FIELD(debug);
		/*! Nameservers for DNS */
		AST_STRING_FIELD(nameservers);
	);
	/* Value to put in Max-Forwards header */
	unsigned int max_forwards;
};

static void global_destructor(void *obj)
{
	struct global_config *cfg = obj;

	ast_string_field_free_memory(cfg);
}

static void *global_alloc(const char *name)
{
	struct global_config *cfg = ast_sorcery_generic_alloc(sizeof(*cfg), global_destructor);

	if (!cfg || ast_string_field_init(cfg, 80)) {
		return NULL;
	}

	return cfg;
}

static int global_apply(const struct ast_sorcery *sorcery, void *obj)
{
	struct global_config *cfg = obj;
	char max_forwards[10];

	snprintf(max_forwards, sizeof(max_forwards), "%u", cfg->max_forwards);

	ast_sip_add_global_request_header("Max-Forwards", max_forwards, 1);
	ast_sip_add_global_request_header("User-Agent", cfg->useragent, 1);
	ast_sip_add_global_response_header("Server", cfg->useragent, 1);
	return 0;
}

static struct global_config *get_global_cfg(void)
{
	RAII_VAR(struct ao2_container *, globals, ast_sorcery_retrieve_by_fields(
			 ast_sip_get_sorcery(), "global", AST_RETRIEVE_FLAG_MULTIPLE,
			 NULL), ao2_cleanup);

	if (!globals) {
		return NULL;
	}

	return ao2_find(globals, NULL, 0);
}

char *ast_sip_global_default_outbound_endpoint(void)
{
	RAII_VAR(struct global_config *, cfg, get_global_cfg(), ao2_cleanup);

	if (!cfg) {
		return NULL;
	}

	return ast_strdup(cfg->default_outbound_endpoint);
}

char *ast_sip_get_debug(void)
{
	char *res;
	struct global_config *cfg = get_global_cfg();

	if (!cfg) {
		return ast_strdup("no");
	}

	res = ast_strdup(cfg->debug);
	ao2_ref(cfg, -1);

	return res;
}

int ast_sip_initialize_sorcery_global(void)
{
	struct ast_sorcery *sorcery = ast_sip_get_sorcery();

	snprintf(default_useragent, sizeof(default_useragent), "%s %s", DEFAULT_USERAGENT_PREFIX, ast_get_version());

	ast_sorcery_apply_default(sorcery, "global", "config", "pjsip.conf,criteria=type=global");

	if (ast_sorcery_object_register(sorcery, "global", global_alloc, NULL, global_apply)) {
		return -1;
	}

	ast_sorcery_object_field_register(sorcery, "global", "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register(sorcery, "global", "max_forwards", __stringify(DEFAULT_MAX_FORWARDS),
			OPT_UINT_T, 0, FLDSET(struct global_config, max_forwards));
	ast_sorcery_object_field_register(sorcery, "global", "user_agent", default_useragent,
			OPT_STRINGFIELD_T, 0, STRFLDSET(struct global_config, useragent));
	ast_sorcery_object_field_register(sorcery, "global", "default_outbound_endpoint", DEFAULT_OUTBOUND_ENDPOINT,
			OPT_STRINGFIELD_T, 0, STRFLDSET(struct global_config, default_outbound_endpoint));
	ast_sorcery_object_field_register(sorcery, "global", "debug", "no",
			OPT_STRINGFIELD_T, 0, STRFLDSET(struct global_config, debug));
	ast_sorcery_object_field_register(sorcery, "global", "nameservers", DEFAULT_NAMESERVERS,
			OPT_STRINGFIELD_T, 0, STRFLDSET(struct global_config, nameservers));

	return 0;
}


/*! \brief Helper function which parses resolv.conf and automatically adds nameservers if found */
static int system_add_resolv_conf_nameservers(pj_pool_t *pool, pj_str_t *nameservers, unsigned int *count)
{
	struct ao2_container *discovered_nameservers;
	struct ao2_iterator it_nameservers;
	char *nameserver;

	discovered_nameservers = ast_dns_get_nameservers();
	if (!discovered_nameservers) {
		ast_log(LOG_ERROR, "Could not retrieve local system nameservers\n");
		return -1;
	}

	if (!ao2_container_count(discovered_nameservers)) {
		ast_log(LOG_ERROR, "There are no local system nameservers configured\n");
		ao2_ref(discovered_nameservers, -1);
		return -1;
	}

	it_nameservers = ao2_iterator_init(discovered_nameservers, 0);
	while ((nameserver = ao2_iterator_next(&it_nameservers))) {
		pj_strdup2(pool, &nameservers[(*count)++], nameserver);
		ao2_ref(nameserver, -1);

		if (*count == (PJ_DNS_RESOLVER_MAX_NS - 1)) {
			break;
		}
	}
	ao2_iterator_destroy(&it_nameservers);

	ao2_ref(discovered_nameservers, -1);

	return 0;
}

static int system_create_resolver_and_set_nameservers(void *data)
{
	struct global_config *cfg = get_global_cfg();
	pj_status_t status;
	pj_pool_t *pool = NULL;
	pj_dns_resolver *resolver;
	pj_str_t nameservers[PJ_DNS_RESOLVER_MAX_NS];
	unsigned int count = 0;
	char *nameserver, *remaining;

	if (cfg) {
		remaining = ast_strdupa(cfg->nameservers);
	} else {
		remaining = ast_strdupa(DEFAULT_NAMESERVERS);
	}

	ao2_cleanup(cfg);

	/* If DNS support has been disabled don't even bother doing anything, just resort to the
	 * system way of doing lookups
	 */
	if (!strcmp(remaining, "disabled")) {
		return 0;
	}

	if (!pjsip_endpt_get_resolver(ast_sip_get_pjsip_endpoint())) {
		status = pjsip_endpt_create_resolver(ast_sip_get_pjsip_endpoint(), &resolver);
		if (status != PJ_SUCCESS) {
			ast_log(LOG_ERROR, "Could not create DNS resolver(%d)\n", status);
			return -1;
		}
	}

	while ((nameserver = strsep(&remaining, ","))) {
		nameserver = ast_strip(nameserver);

		if (!strcmp(nameserver, "auto")) {
			if (!pool) {
				pool = pjsip_endpt_create_pool(ast_sip_get_pjsip_endpoint(), "Automatic Nameserver Discovery", 256, 256);
			}
			if (!pool) {
				ast_log(LOG_ERROR, "Could not create memory pool for automatic nameserver discovery\n");
				return -1;
			} else if (system_add_resolv_conf_nameservers(pool, nameservers, &count)) {
				/* A log message will have already been output by system_add_resolv_conf_nameservers */
				pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);
				return -1;
			}
		} else {
			pj_strset2(&nameservers[count++], nameserver);
		}

		/* If we have reached the max number of nameservers we can specify bail early */
		if (count == (PJ_DNS_RESOLVER_MAX_NS - 1)) {
			break;
		}
	}

	if (!count) {
		ast_log(LOG_ERROR, "No nameservers specified for DNS resolver, resorting to system resolution\n");
		if (pool) {
			pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);
		}
		return 0;
	}

	status = pj_dns_resolver_set_ns(resolver, count, nameservers, NULL);

	/* Since we no longer need the nameservers we can drop the memory pool they may be allocated from */
	if (pool) {
		pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);
	}

	if (status != PJ_SUCCESS) {
		ast_log(LOG_ERROR, "Could not set nameservers on DNS resolver in PJSIP(%d)\n", status);
		return -1;
	}

	if (!pjsip_endpt_get_resolver(ast_sip_get_pjsip_endpoint())) {
		status = pjsip_endpt_set_resolver(ast_sip_get_pjsip_endpoint(), resolver);
		if (status != PJ_SUCCESS) {
			ast_log(LOG_ERROR, "Could not set DNS resolver in PJSIP(%d)\n", status);
			return -1;
		}
	}

	return 0;
}

int ast_sip_initialize_dns(void)
{
	return ast_sip_push_task_synchronous(NULL, system_create_resolver_and_set_nameservers, NULL);
}