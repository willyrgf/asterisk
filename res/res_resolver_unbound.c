/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2015, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
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

/*** MODULEINFO
	<depend>unbound</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <unbound.h>

#include "asterisk/module.h"
#include "asterisk/linkedlists.h"
#include "asterisk/dns_core.h"
#include "asterisk/dns_resolver.h"
#include "asterisk/config.h"
#include "asterisk/config_options.h"

/*** DOCUMENTATION
	<configInfo name="res_resolver_unbound" language="en_US">
		<configFile name="resolver_unbound.conf">
			<configObject name="globals">
				<synopsis>Options that apply globally to res_resolver_unbound</synopsis>
				<configOption name="hosts">
					<synopsis>Full path to an optional hosts file</synopsis>
					<description><para>Hosts specified in a hosts file will be resolved within the resolver itself. If a value
					of system is provided the system-specific file will be used.</para></description>
				</configOption>
				<configOption name="resolv">
					<synopsis>Full path to an optional resolv.conf file</synopsis>
					<description><para>The resolv.conf file specifies the nameservers to contact when resolving queries. If a
					value of system is provided the system-specific file will be used.</para></description>
				</configOption>
				<configOption name="nameserver">
					<synopsis>Nameserver to use for queries</synopsis>
					<description><para>An explicit nameserver can be specified which is used for resolving queries. If multiple
					nameserver lines are specified the first will be the primary with failover occurring, in order, to the other
					nameservers as backups.</para></description>
				</configOption>
				<configOption name="debug">
					<synopsis>Unbound debug level</synopsis>
					<description><para>The debugging level for the unbound resolver. While there is no explicit range generally
					the higher the number the more debug is output.</para></description>
				</configOption>
				<configOption name="ta_file">
					<synopsis>Trust anchor file</synopsis>
					<description><para>Full path to a file with DS and DNSKEY records in zone file format. This file is provided
					to unbound and is used as a source for trust anchors.</para></description>
				</configOption>
			</configObject>
		</configFile>
	</configInfo>
 ***/

/*! \brief Structure for an unbound resolver */
struct unbound_resolver {
	/*! \brief Resolver context itself */
	struct ub_ctx *context;
	/*! \brief Thread handling the resolver */
	pthread_t thread;
};

/*! \brief Structure for query resolver data */
struct unbound_resolver_data {
	/*! \brief ID for the specific query */
	int id;
	/*! \brief The resolver in use for the query */
	struct unbound_resolver *resolver;
};

/*! \brief Unbound configuration state information */
struct unbound_config_state {
	/*! \brief The configured resolver */
	struct unbound_resolver *resolver;
};

/*! \brief A structure to hold global configuration-related options */
struct unbound_global_config {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(hosts);   /*!< Optional hosts file */
		AST_STRING_FIELD(resolv);  /*!< Optional resolv.conf file */
		AST_STRING_FIELD(ta_file); /*!< Optional trust anchor file */
	);
	/*! \brief List of nameservers (in order) to use for queries */
	struct ao2_container *nameservers;
	/*! \brief Debug level for the resolver */
	unsigned int debug;
	/*! \brief State information */
	struct unbound_config_state *state;
};

/*! \brief A container for config related information */
struct unbound_config {
	struct unbound_global_config *global;
};

/*!
 * \brief Allocate a unbound_config to hold a snapshot of the complete results of parsing a config
 * \internal
 * \returns A void pointer to a newly allocated unbound_config
 */
static void *unbound_config_alloc(void);

/*! \brief An aco_type structure to link the "general" category to the unbound_global_config type */
static struct aco_type global_option = {
	.type = ACO_GLOBAL,
	.name = "globals",
	.item_offset = offsetof(struct unbound_config, global),
	.category_match = ACO_WHITELIST,
	.category = "^general$",
};

static struct aco_type *global_options[] = ACO_TYPES(&global_option);

static struct aco_file resolver_unbound_conf = {
	.filename = "resolver_unbound.conf",
	.types = ACO_TYPES(&global_option),
};

/*! \brief A global object container that will contain the global_config that gets swapped out on reloads */
static AO2_GLOBAL_OBJ_STATIC(globals);

/*!
 * \brief Finish initializing new configuration
 * \internal
 */
static int unbound_config_preapply_callback(void);

/*! \brief Register information about the configs being processed by this module */
CONFIG_INFO_STANDARD(cfg_info, globals, unbound_config_alloc,
	.files = ACO_FILES(&resolver_unbound_conf),
	.pre_apply_config = unbound_config_preapply_callback,
);

/*! \brief Destructor for unbound resolver */
static void unbound_resolver_destroy(void *obj)
{
	struct unbound_resolver *resolver = obj;

	if (resolver->context) {
		ub_ctx_delete(resolver->context);
	}
}

/*! \brief Allocator for unbound resolver */
static struct unbound_resolver *unbound_resolver_alloc(void)
{
	struct unbound_resolver *resolver;

	resolver = ao2_alloc_options(sizeof(*resolver), unbound_resolver_destroy, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!resolver) {
		return NULL;
	}

	resolver->thread = AST_PTHREADT_NULL;

	resolver->context = ub_ctx_create();
	if (!resolver->context) {
		ao2_ref(resolver, -1);
		return NULL;
	}

	/* Each async result should be invoked in a separate thread so others are not blocked */
	ub_ctx_async(resolver->context, 1);

	return resolver;
}

/*! \brief Resolver thread which waits and handles results */
static void *unbound_resolver_thread(void *data)
{
	struct unbound_resolver *resolver = data;

	ast_debug(1, "Starting processing for unbound resolver\n");

	while (resolver->thread != AST_PTHREADT_STOP) {
		/* Wait for any results to come in */
		ast_wait_for_input(ub_fd(resolver->context), -1);

		/* Finally process any results */
		ub_process(resolver->context);
	}

	ast_debug(1, "Terminating processing for unbound resolver\n");

	ao2_ref(resolver, -1);

	return NULL;
}

/*! \brief Start function for the unbound resolver */
static int unbound_resolver_start(struct unbound_resolver *resolver)
{
	int res;

	if (resolver->thread != AST_PTHREADT_NULL) {
		return 0;
	}

	ast_debug(1, "Starting thread for unbound resolver\n");

	res = ast_pthread_create(&resolver->thread, NULL, unbound_resolver_thread, ao2_bump(resolver));
	if (res) {
		ast_debug(1, "Could not start thread for unbound resolver\n");
		ao2_ref(resolver, -1);
	}

	return res;
}

/*! \brief Stop function for the unbound resolver */
static void unbound_resolver_stop(struct unbound_resolver *resolver)
{
	pthread_t thread;

	if (resolver->thread == AST_PTHREADT_NULL) {
		return;
	}

	ast_debug(1, "Stopping processing thread for unbound resolver\n");

	thread = resolver->thread;
	resolver->thread = AST_PTHREADT_STOP;
	pthread_kill(thread, SIGURG);
	pthread_join(thread, NULL);

	ast_debug(1, "Stopped processing thread for unbound resolver\n");
}

/*! \brief Callback invoked when resolution completes on a query */
static void unbound_resolver_callback(void *data, int err, struct ub_result *ub_result)
{
	RAII_VAR(struct ast_dns_query *, query, data, ao2_cleanup);

	if (!ast_dns_resolver_set_result(query, ub_result->secure, ub_result->bogus, ub_result->rcode,
		S_OR(ub_result->canonname, ast_dns_query_get_name(query)))) {
		int i;
		char *data;

		for (i = 0; (data = ub_result->data[i]); i++) {
			if (ast_dns_resolver_add_record(query, ub_result->qtype, ub_result->qclass, ub_result->ttl,
				data, ub_result->len[i])) {
				break;
			}
		}
	}

	ast_dns_resolver_completed(query);
	ub_resolve_free(ub_result);
}

static int unbound_resolver_resolve(struct ast_dns_query *query)
{
	struct unbound_config *cfg = ao2_global_obj_ref(globals);
	struct unbound_resolver_data *data;
	int res;

	data = ao2_alloc_options(sizeof(*data), NULL, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!data) {
		ast_log(LOG_ERROR, "Failed to allocate resolver data for resolution of '%s'\n",
			ast_dns_query_get_name(query));
		return -1;
	}
	data->resolver = ao2_bump(cfg->global->state->resolver);
	ast_dns_resolver_set_data(query, data);

	res = ub_resolve_async(data->resolver->context, ast_dns_query_get_name(query),
		ast_dns_query_get_rr_type(query), ast_dns_query_get_rr_class(query),
		ao2_bump(query), unbound_resolver_callback, &data->id);

	if (res) {
		ast_log(LOG_ERROR, "Failed to perform async DNS resolution of '%s'\n",
			ast_dns_query_get_name(query));
		ao2_ref(query, -1);
	}

	ao2_ref(data, -1);
	ao2_ref(cfg, -1);

	return res;
}

static int unbound_resolver_cancel(struct ast_dns_query *query)
{
	struct unbound_resolver_data *data = ast_dns_resolver_get_data(query);
	int res;

	res = ub_cancel(data->resolver->context, data->id);
	if (!res) {
		/* When this query was started we bumped the ref, now that it has been cancelled we have ownership and
		 * need to drop it
		 */
		ao2_ref(query, -1);
	}

	return res;
}

struct ast_dns_resolver unbound_resolver = {
	.name = "unbound",
	.priority = 100,
	.resolve = unbound_resolver_resolve,
	.cancel = unbound_resolver_cancel,
};

static void unbound_config_destructor(void *obj)
{
	struct unbound_config *cfg = obj;

	ao2_cleanup(cfg->global);
}

static void unbound_global_config_destructor(void *obj)
{
	struct unbound_global_config *global = obj;

	ast_string_field_free_memory(global);
	ao2_cleanup(global->nameservers);
	ao2_cleanup(global->state);
}

static void unbound_config_state_destructor(void *obj)
{
	struct unbound_config_state *state = obj;

	if (state->resolver) {
		unbound_resolver_stop(state->resolver);
		ao2_ref(state->resolver, -1);
	}
}

static void *unbound_config_alloc(void)
{
	struct unbound_config *cfg;

	cfg = ao2_alloc_options(sizeof(*cfg), unbound_config_destructor, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!cfg) {
		return NULL;
	}

	/* Allocate/initialize memory */
	cfg->global = ao2_alloc_options(sizeof(*cfg->global), unbound_global_config_destructor,
		AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!cfg->global) {
		goto error;
	}

	if (ast_string_field_init(cfg->global, 128)) {
		goto error;
	}

	cfg->global->nameservers = ast_str_container_alloc_options(AO2_ALLOC_OPT_LOCK_NOLOCK, 1);
	if (!cfg->global->nameservers) {
		goto error;
	}

	return cfg;
error:
	ao2_ref(cfg, -1);
	return NULL;
}

static int unbound_config_preapply(struct unbound_config *cfg)
{
	int res = 0;
	struct ao2_iterator it_nameservers;
	const char *nameserver;

	cfg->global->state = ao2_alloc_options(sizeof(*cfg->global->state), unbound_config_state_destructor,
		AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!cfg->global->state) {
		ast_log(LOG_ERROR, "Could not allocate unbound resolver state structure\n");
		return -1;
	}

	cfg->global->state->resolver = unbound_resolver_alloc();
	if (!cfg->global->state->resolver) {
		ast_log(LOG_ERROR, "Could not create an unbound resolver\n");
		return -1;
	}

	if (!strcmp(cfg->global->hosts, "system")) {
		res = ub_ctx_hosts(cfg->global->state->resolver->context, NULL);
	} else if (!ast_strlen_zero(cfg->global->hosts)) {
		res = ub_ctx_hosts(cfg->global->state->resolver->context, cfg->global->hosts);
	}

	if (res) {
		ast_log(LOG_ERROR, "Failed to set hosts file to '%s' in unbound resolver: %s\n",
			cfg->global->hosts, ub_strerror(res));
		return -1;
	}

	if (!strcmp(cfg->global->resolv, "system")) {
		res = ub_ctx_resolvconf(cfg->global->state->resolver->context, NULL);
	} else if (!ast_strlen_zero(cfg->global->resolv)) {
		res = ub_ctx_resolvconf(cfg->global->state->resolver->context, cfg->global->resolv);
	}

	if (res) {
		ast_log(LOG_ERROR, "Failed to set resolv.conf file to '%s' in unbound resolver: %s\n",
			cfg->global->resolv, ub_strerror(res));
		return -1;
	}

	it_nameservers = ao2_iterator_init(cfg->global->nameservers, 0);
	while ((nameserver = ao2_iterator_next(&it_nameservers))) {
		res = ub_ctx_set_fwd(cfg->global->state->resolver->context, nameserver);

		if (res) {
			ast_log(LOG_ERROR, "Failed to add nameserver '%s' to unbound resolver: %s\n",
				nameserver, ub_strerror(res));
			ao2_iterator_destroy(&it_nameservers);
			return -1;
		}
	}
	ao2_iterator_destroy(&it_nameservers);

	ub_ctx_debuglevel(cfg->global->state->resolver->context, cfg->global->debug);

	if (!ast_strlen_zero(cfg->global->ta_file)) {
		res = ub_ctx_add_ta_file(cfg->global->state->resolver->context, cfg->global->ta_file);

		if (res) {
			ast_log(LOG_ERROR, "Failed to set trusted anchor file to '%s' in unbound resolver: %s\n",
				cfg->global->ta_file, ub_strerror(res));
			return -1;
		}
	}

	if (unbound_resolver_start(cfg->global->state->resolver)) {
		ast_log(LOG_ERROR, "Could not start unbound resolver thread\n");
		return -1;
	}

	return 0;
}

static int unbound_config_apply_default(void)
{
	struct unbound_config *cfg;

	cfg = unbound_config_alloc();
	if (!cfg) {
		ast_log(LOG_ERROR, "Could not create default configuration for unbound resolver\n");
		return -1;
	}

	aco_set_defaults(&global_option, "general", cfg->global);

	if (unbound_config_preapply(cfg)) {
		return -1;
	}

	ast_verb(1, "Starting unbound resolver using default configuration\n");

	ao2_global_obj_replace_unref(globals, cfg);
	ao2_ref(cfg, -1);

	return 0;
}

static int unbound_config_preapply_callback(void)
{
	return unbound_config_preapply(aco_pending_config(&cfg_info));
}

static int reload_module(void)
{
	if (aco_process_config(&cfg_info, 1) == ACO_PROCESS_ERROR) {
		return AST_MODULE_RELOAD_ERROR;
	}

	return 0;
}

static int unload_module(void)
{
	aco_info_destroy(&cfg_info);
	ao2_global_obj_release(globals);
	return 0;
}

static int custom_nameserver_handler(const struct aco_option *opt, struct ast_variable *var, void *obj)
{
	struct unbound_global_config *global = obj;

	return ast_str_container_add(global->nameservers, var->value);
}

static int load_module(void)
{
	struct ast_config *cfg;
	struct ast_flags cfg_flags = { 0, };

	if (aco_info_init(&cfg_info)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	aco_option_register(&cfg_info, "hosts", ACO_EXACT, global_options, "", OPT_STRINGFIELD_T, 0, STRFLDSET(struct unbound_global_config, hosts));
	aco_option_register(&cfg_info, "resolv", ACO_EXACT, global_options, "", OPT_STRINGFIELD_T, 0, STRFLDSET(struct unbound_global_config, resolv));
	aco_option_register_custom(&cfg_info, "nameserver", ACO_EXACT, global_options, "", custom_nameserver_handler, 0);
	aco_option_register(&cfg_info, "debug", ACO_EXACT, global_options, "0", OPT_UINT_T, 0, FLDSET(struct unbound_global_config, debug));
	aco_option_register(&cfg_info, "ta_file", ACO_EXACT, global_options, "", OPT_STRINGFIELD_T, 0, STRFLDSET(struct unbound_global_config, ta_file));

	/* This purposely checks for a configuration file so we don't output an error message in ACO if one is not present */
	cfg = ast_config_load(resolver_unbound_conf.filename, cfg_flags);
	if (!cfg) {
		if (unbound_config_apply_default()) {
			unload_module();
			return AST_MODULE_LOAD_DECLINE;
		}
	} else {
		ast_config_destroy(cfg);
		if (aco_process_config(&cfg_info, 0) == ACO_PROCESS_ERROR) {
			unload_module();
			return AST_MODULE_LOAD_DECLINE;
		}
	}

	ast_dns_resolver_register(&unbound_resolver);

	ast_module_shutdown_ref(ast_module_info->self);

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Unbound DNS Resolver Support",
		.support_level = AST_MODULE_SUPPORT_CORE,
		.load = load_module,
		.unload = unload_module,
		.reload = reload_module,
		.load_pri = AST_MODPRI_CHANNEL_DEPEND - 4,
	       );
