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

#include <unbound.h>

#include "asterisk/module.h"
#include "asterisk/linkedlists.h"
#include "asterisk/dns_core.h"
#include "asterisk/dns_resolver.h"

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
};

/*! \brief Unbound resolver */
static struct unbound_resolver *resolver;

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

	ub_ctx_resolvconf(resolver->context, NULL);
	ub_ctx_hosts(resolver->context, NULL);

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
		ub_result->canonname)) {
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
	struct unbound_resolver_data *data;
	int res;

	data = ao2_alloc_options(sizeof(*data), NULL, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!data) {
		ast_log(LOG_ERROR, "Failed to allocate resolver data for resolution of '%s'\n",
			ast_dns_query_get_name(query));
		return -1;
	}
	ast_dns_resolver_set_data(query, data);

	res = ub_resolve_async(resolver->context, ast_dns_query_get_name(query),
		ast_dns_query_get_rr_type(query), ast_dns_query_get_rr_class(query),
		ao2_bump(query), unbound_resolver_callback, &data->id);

	if (res) {
		ast_log(LOG_ERROR, "Failed to perform async DNS resolution of '%s'\n",
			ast_dns_query_get_name(query));
		ao2_ref(query, -1);
	}

	ao2_ref(data, -1);

	return res;
}

static int unbound_resolver_cancel(struct ast_dns_query *query)
{
	struct unbound_resolver_data *data = ast_dns_resolver_get_data(query);
	int res;

	res = ub_cancel(resolver->context, data->id);
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

static int unload_module(void)
{
	unbound_resolver_stop(resolver);
	ao2_replace(resolver, NULL);
	return 0;
}

static int load_module(void)
{
	resolver = unbound_resolver_alloc();
	if (!resolver) {
		return AST_MODULE_LOAD_DECLINE;
	}

	if (unbound_resolver_start(resolver) ||
		ast_dns_resolver_register(&unbound_resolver)) {
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_module_shutdown_ref(ast_module_info->self);

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Unbound DNS Resolver Support",
		.support_level = AST_MODULE_SUPPORT_CORE,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_CHANNEL_DEPEND - 4,
	       );
