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
#include "asterisk/sorcery.h"
#include "include/res_pjsip_private.h"
#include "asterisk/threadpool.h"
#include "asterisk/dns.h"

#define TIMER_T1_MIN 100
#define DEFAULT_TIMER_T1 500
#define DEFAULT_TIMER_B 32000

#define NAMESERVERS_SIZE 512

struct system_config {
	SORCERY_OBJECT(details);
	/*! Transaction Timer T1 value */
	unsigned int timert1;
	/*! Transaction Timer B value */
	unsigned int timerb;
	/*! Should we use short forms for headers? */
	unsigned int compactheaders;
	struct {
		/*! Initial number of threads in the threadpool */
		int initial_size;
		/*! The amount by which the number of threads is incremented when necessary */
		int auto_increment;
		/*! Thread idle timeout in seconds */
		int idle_timeout;
		/*! Maxumum number of threads in the threadpool */
		int max_size;
	} threadpool;
	/*! Configured nameservers */
	char nameservers[NAMESERVERS_SIZE];
};

static struct ast_threadpool_options sip_threadpool_options = {
	.version = AST_THREADPOOL_OPTIONS_VERSION,
};

static char sip_nameservers[NAMESERVERS_SIZE];

void sip_get_threadpool_options(struct ast_threadpool_options *threadpool_options)
{
	*threadpool_options = sip_threadpool_options;
}

static struct ast_sorcery *system_sorcery;

static void *system_alloc(const char *name)
{
	struct system_config *system = ast_sorcery_generic_alloc(sizeof(*system), NULL);

	if (!system) {
		return NULL;
	}

	return system;
}

static int system_apply(const struct ast_sorcery *system_sorcery, void *obj)
{
	struct system_config *system = obj;
	int min_timerb;

	if (system->timert1 < TIMER_T1_MIN) {
		ast_log(LOG_WARNING, "Timer T1 setting is too low. Setting to %d\n", TIMER_T1_MIN);
		system->timert1 = TIMER_T1_MIN;
	}

	min_timerb = 64 * system->timert1;

	if (system->timerb < min_timerb) {
		ast_log(LOG_WARNING, "Timer B setting is too low. Setting to %d\n", min_timerb);
		system->timerb = min_timerb;
	}

	pjsip_cfg()->tsx.t1 = system->timert1;
	pjsip_cfg()->tsx.td = system->timerb;

	if (system->compactheaders) {
		extern pj_bool_t pjsip_use_compact_form;
		pjsip_use_compact_form = PJ_TRUE;
	}

	sip_threadpool_options.initial_size = system->threadpool.initial_size;
	sip_threadpool_options.auto_increment = system->threadpool.auto_increment;
	sip_threadpool_options.idle_timeout = system->threadpool.idle_timeout;
	sip_threadpool_options.max_size = system->threadpool.max_size;

	ast_copy_string(sip_nameservers, system->nameservers, sizeof(sip_nameservers));

	return 0;
}

int ast_sip_initialize_system(void)
{
	RAII_VAR(struct ao2_container *, system_configs, NULL, ao2_cleanup);
	RAII_VAR(struct system_config *, system, NULL, ao2_cleanup);

	system_sorcery = ast_sorcery_open();
	if (!system_sorcery) {
		ast_log(LOG_ERROR, "Failed to open SIP system sorcery\n");
		return -1;
	}

	ast_sorcery_apply_config(system_sorcery, "res_pjsip");

	ast_sorcery_apply_default(system_sorcery, "system", "config", "pjsip.conf,criteria=type=system");

	if (ast_sorcery_object_register_no_reload(system_sorcery, "system", system_alloc, NULL, system_apply)) {
		ast_log(LOG_ERROR, "Failed to register with sorcery (is res_sorcery_config loaded?)\n");
		ast_sorcery_unref(system_sorcery);
		system_sorcery = NULL;
		return -1;
	}

	ast_sorcery_object_field_register(system_sorcery, "system", "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register(system_sorcery, "system", "timer_t1", __stringify(DEFAULT_TIMER_T1),
			OPT_UINT_T, 0, FLDSET(struct system_config, timert1));
	ast_sorcery_object_field_register(system_sorcery, "system", "timer_b", __stringify(DEFAULT_TIMER_B),
			OPT_UINT_T, 0, FLDSET(struct system_config, timerb));
	ast_sorcery_object_field_register(system_sorcery, "system", "compact_headers", "no",
			OPT_BOOL_T, 1, FLDSET(struct system_config, compactheaders));
	ast_sorcery_object_field_register(system_sorcery, "system", "threadpool_initial_size", "0",
			OPT_UINT_T, 0, FLDSET(struct system_config, threadpool.initial_size));
	ast_sorcery_object_field_register(system_sorcery, "system", "threadpool_auto_increment", "5",
			OPT_UINT_T, 0, FLDSET(struct system_config, threadpool.auto_increment));
	ast_sorcery_object_field_register(system_sorcery, "system", "threadpool_idle_timeout", "60",
			OPT_UINT_T, 0, FLDSET(struct system_config, threadpool.idle_timeout));
	ast_sorcery_object_field_register(system_sorcery, "system", "threadpool_max_size", "0",
			OPT_UINT_T, 0, FLDSET(struct system_config, threadpool.max_size));
	ast_sorcery_object_field_register(system_sorcery, "system", "nameservers", "auto",
			OPT_CHAR_ARRAY_T, 0, CHARFLDSET(struct system_config, nameservers));

	ast_sorcery_load(system_sorcery);

	system_configs = ast_sorcery_retrieve_by_fields(system_sorcery, "system",
		AST_RETRIEVE_FLAG_MULTIPLE | AST_RETRIEVE_FLAG_ALL, NULL);

	if (ao2_container_count(system_configs)) {
		return 0;
	}

	/* No config present, allocate one and apply defaults */
	system = ast_sorcery_alloc(system_sorcery, "system", NULL);
	if (!system) {
		ast_log(LOG_ERROR, "Unable to allocate default system config.\n");
		ast_sorcery_unref(system_sorcery);
		return -1;
	}

	if (system_apply(system_sorcery, system)) {
		ast_log(LOG_ERROR, "Failed to apply default system config.\n");
		ast_sorcery_unref(system_sorcery);
		return -1;
	}

	return 0;
}

void ast_sip_destroy_system(void)
{
	ast_sorcery_unref(system_sorcery);
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
	pj_status_t status;
	pj_pool_t *pool = NULL;
	pj_dns_resolver *resolver;
	pj_str_t nameservers[PJ_DNS_RESOLVER_MAX_NS];
	unsigned int count = 0;
	char *nameserver, *remaining = sip_nameservers;

	status = pjsip_endpt_create_resolver(ast_sip_get_pjsip_endpoint(), &resolver);
	if (status != PJ_SUCCESS) {
		ast_log(LOG_ERROR, "Could not create DNS resolver(%d)\n", status);
		return -1;
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

	status = pjsip_endpt_set_resolver(ast_sip_get_pjsip_endpoint(), resolver);
	if (status != PJ_SUCCESS) {
		ast_log(LOG_ERROR, "Could not set DNS resolver in PJSIP(%d)\n", status);
		return -1;
	}

	return 0;
}

int ast_sip_initialize_dns(void)
{
	/* If DNS support has been disabled don't even bother doing anything, just resort to the
	 * system way of doing lookups
	 */
	if (!strcmp(sip_nameservers, "disabled")) {
		return 0;
	}

	return ast_sip_push_task_synchronous(NULL, system_create_resolver_and_set_nameservers, NULL);
}