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

/*! \file
 *
 * \brief Core DNS Functionality
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/linkedlists.h"
#include "asterisk/vector.h"
#include "asterisk/astobj2.h"
#include "asterisk/strings.h"
#include "asterisk/sched.h"
#include "asterisk/dns_core.h"
#include "asterisk/dns_naptr.h"
#include "asterisk/dns_srv.h"
#include "asterisk/dns_tlsa.h"
#include "asterisk/dns_recurring.h"
#include "asterisk/dns_resolver.h"
#include "asterisk/dns_internal.h"

#include <arpa/nameser.h>

AST_RWLIST_HEAD_STATIC(resolvers, ast_dns_resolver);

static struct ast_sched_context *sched;

const char *ast_dns_query_get_name(const struct ast_dns_query *query)
{
	return query->name;
}

int ast_dns_query_get_rr_type(const struct ast_dns_query *query)
{
	return query->rr_type;
}

int ast_dns_query_get_rr_class(const struct ast_dns_query *query)
{
	return query->rr_class;
}

void *ast_dns_query_get_data(const struct ast_dns_query *query)
{
	return query->user_data;
}

struct ast_dns_result *ast_dns_query_get_result(const struct ast_dns_query *query)
{
	return query->result;
}

unsigned int ast_dns_result_get_secure(const struct ast_dns_result *result)
{
	return result->secure;
}

unsigned int ast_dns_result_get_bogus(const struct ast_dns_result *result)
{
	return result->bogus;
}

unsigned int ast_dns_result_get_rcode(const struct ast_dns_result *result)
{
	return result->rcode;
}

const char *ast_dns_result_get_canonical(const struct ast_dns_result *result)
{
	return result->canonical;
}

const struct ast_dns_record *ast_dns_result_get_records(const struct ast_dns_result *result)
{
	return AST_LIST_FIRST(&result->records);
}

void ast_dns_result_free(struct ast_dns_result *result)
{
	ao2_cleanup(result);
}

int ast_dns_record_get_rr_type(const struct ast_dns_record *record)
{
	return record->rr_type;
}

int ast_dns_record_get_rr_class(const struct ast_dns_record *record)
{
	return record->rr_class;
}

int ast_dns_record_get_ttl(const struct ast_dns_record *record)
{
	return record->ttl;
}

const char *ast_dns_record_get_data(const struct ast_dns_record *record)
{
	return record->data;
}

const struct ast_dns_record *ast_dns_record_get_next(const struct ast_dns_record *record)
{
	return AST_LIST_NEXT(record, list);
}

/*! \brief \brief Destructor for a DNS query */
static void dns_query_destroy(void *data)
{
	struct ast_dns_query *query = data;

	ao2_cleanup(query->user_data);
	ao2_cleanup(query->resolver_data);
	ast_dns_result_free(query->result);
}

struct ast_dns_query *ast_dns_resolve_async(const char *name, int rr_type, int rr_class, ast_dns_resolve_callback callback, void *data)
{
	struct ast_dns_query *query;

	if (ast_strlen_zero(name)) {
		ast_log(LOG_ERROR, "Could not perform asynchronous resolution, no name provided\n");
		return NULL;
	} else if (rr_type > ns_t_max) {
		ast_log(LOG_ERROR, "Could not perform asynchronous resolution of '%s', resource record type '%d' exceeds maximum\n",
			name, rr_type);
		return NULL;
	} else if (rr_type < 0) {
		ast_log(LOG_ERROR, "Could not perform asynchronous resolution of '%s', invalid resource record type '%d'\n",
			name, rr_type);
		return NULL;
	} else if (rr_class > ns_c_max) {
		ast_log(LOG_ERROR, "Could not perform asynchronous resolution of '%s', resource record class '%d' exceeds maximum\n",
			name, rr_class);
		return NULL;
	} else if (rr_class < 0) {
		ast_log(LOG_ERROR, "Could not perform asynchronous resolution of '%s', invalid resource class '%d'\n",
			name, rr_class);
		return NULL;
	} else if (!callback) {
		ast_log(LOG_ERROR, "Could not perform asynchronous resolution of '%s', no callback provided\n",
			name);
		return NULL;
	}

	query = ao2_alloc_options(sizeof(*query) + strlen(name) + 1, dns_query_destroy, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!query) {
		return NULL;
	}

	query->callback = callback;
	query->user_data = ao2_bump(data);
	query->rr_type = rr_type;
	query->rr_class = rr_class;
	strcpy(query->name, name); /* SAFE */

	AST_RWLIST_RDLOCK(&resolvers);
	query->resolver = AST_RWLIST_FIRST(&resolvers);
	AST_RWLIST_UNLOCK(&resolvers);

	if (!query->resolver) {
		ast_log(LOG_ERROR, "Attempted to do a DNS query for '%s' of class '%d' and type '%d' but no resolver is available\n",
			name, rr_class, rr_type);
		ao2_ref(query, -1);
		return NULL;
	}

	if (query->resolver->resolve(query)) {
		ast_log(LOG_ERROR, "Resolver '%s' returned an error when resolving '%s' of class '%d' and type '%d'\n",
			query->resolver->name, name, rr_class, rr_type);
		ao2_ref(query, -1);
		return NULL;
	}

	return query;
}

int ast_dns_resolve_cancel(struct ast_dns_query *query)
{
	return query->resolver->cancel(query);
}

/*! \brief Structure used for signaling back for synchronous resolution completion */
struct dns_synchronous_resolve {
	/*! \brief Lock used for signaling */
	ast_mutex_t lock;
	/*! \brief Condition used for signaling */
	ast_cond_t cond;
	/*! \brief Whether the query has completed */
	unsigned int completed;
	/*! \brief The result from the query */
	struct ast_dns_result *result;
};

/*! \brief Destructor for synchronous resolution structure */
static void dns_synchronous_resolve_destroy(void *data)
{
	struct dns_synchronous_resolve *synchronous = data;

	ast_mutex_destroy(&synchronous->lock);
	ast_cond_destroy(&synchronous->cond);

	/* This purposely does not unref result as it has been passed to the caller */
}

/*! \brief Callback used to implement synchronous resolution */
static void dns_synchronous_resolve_callback(const struct ast_dns_query *query)
{
	struct dns_synchronous_resolve *synchronous = ast_dns_query_get_data(query);

	synchronous->result = ao2_bump(ast_dns_query_get_result(query));

	ast_mutex_lock(&synchronous->lock);
	synchronous->completed = 1;
	ast_cond_signal(&synchronous->cond);
	ast_mutex_unlock(&synchronous->lock);
}

int ast_dns_resolve(const char *name, int rr_type, int rr_class, struct ast_dns_result **result)
{
	struct dns_synchronous_resolve *synchronous;
	struct ast_dns_query *query;

	if (ast_strlen_zero(name)) {
		ast_log(LOG_ERROR, "Could not perform synchronous resolution, no name provided\n");
		return -1;
	} else if (rr_type > ns_t_max) {
		ast_log(LOG_ERROR, "Could not perform synchronous resolution of '%s', resource record type '%d' exceeds maximum\n",
			name, rr_type);
		return -1;
	} else if (rr_type < 0) {
		ast_log(LOG_ERROR, "Could not perform synchronous resolution of '%s', invalid resource record type '%d'\n",
			name, rr_type);
		return -1;
	} else if (rr_class > ns_c_max) {
		ast_log(LOG_ERROR, "Could not perform synchronous resolution of '%s', resource record class '%d' exceeds maximum\n",
			name, rr_class);
		return -1;
	} else if (rr_class < 0) {
		ast_log(LOG_ERROR, "Could not perform synchronous resolution of '%s', invalid resource class '%d'\n",
			name, rr_class);
		return -1;
	} else if (!result) {
		ast_log(LOG_ERROR, "Could not perform synchronous resolution of '%s', no result pointer provided for storing results\n",
			name);
		return -1;
	}

	synchronous = ao2_alloc_options(sizeof(*synchronous), dns_synchronous_resolve_destroy, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!synchronous) {
		return -1;
	}

	ast_mutex_init(&synchronous->lock);
	ast_cond_init(&synchronous->cond, NULL);

	query = ast_dns_resolve_async(name, rr_type, rr_class, dns_synchronous_resolve_callback, synchronous);
	if (query) {
		/* Wait for resolution to complete */
		ast_mutex_lock(&synchronous->lock);
		while (!synchronous->completed) {
			ast_cond_wait(&synchronous->cond, &synchronous->lock);
		}
		ast_mutex_unlock(&synchronous->lock);
		ao2_ref(query, -1);
	}

	*result = synchronous->result;
	ao2_ref(synchronous, -1);

	return *result ? 0 : -1;
}

const char *ast_dns_naptr_get_flags(const struct ast_dns_record *record)
{
	return NULL;
}

const char *ast_dns_naptr_get_service(const struct ast_dns_record *record)
{
	return NULL;
}

const char *ast_dns_naptr_get_regexp(const struct ast_dns_record *record)
{
	return NULL;
}

const char *ast_dns_naptr_get_replacement(const struct ast_dns_record *record)
{
	return NULL;
}

unsigned short ast_dns_naptr_get_order(const struct ast_dns_record *record)
{
	return 0;
}

unsigned short ast_dns_naptr_get_preference(const struct ast_dns_record *record)
{
	return 0;
}

const char *ast_dns_srv_get_host(const struct ast_dns_record *record)
{
	return NULL;
}

unsigned short ast_dns_srv_get_priority(const struct ast_dns_record *record)
{
	return 0;
}

unsigned short ast_dns_srv_get_weight(const struct ast_dns_record *record)
{
	return 0;
}

unsigned short ast_dns_srv_get_port(const struct ast_dns_record *record)
{
	return 0;
}

unsigned int ast_dns_tlsa_get_usage(const struct ast_dns_record *record)
{
	return 0;
}

unsigned int ast_dns_tlsa_get_selector(const struct ast_dns_record *record)
{
	return 0;
}

unsigned int ast_dns_tlsa_get_matching_type(const struct ast_dns_record *record)
{
	return 0;
}

const char *ast_dns_tlsa_get_association_data(const struct ast_dns_record *record)
{
	return NULL;
}

int ast_dns_resolver_set_data(struct ast_dns_query *query, void *data)
{
	if (query->resolver_data) {
		return -1;
	}

	query->resolver_data = ao2_bump(data);

	return 0;
}

void *ast_dns_resolver_get_data(const struct ast_dns_query *query)
{
	return query->resolver_data;
}

/*! \brief Destructor for DNS result */
static void dns_result_destroy(void *obj)
{
	struct ast_dns_result *result = obj;
	struct ast_dns_record *record;

	while ((record = AST_LIST_REMOVE_HEAD(&result->records, list))) {
		ast_free(record);
	}
}

int ast_dns_resolver_set_result(struct ast_dns_query *query, unsigned int secure, unsigned int bogus,
	unsigned int rcode, const char *canonical)
{
	if (secure && bogus) {
		ast_debug(2, "Query '%p': Could not set result information, it can not be both secure and bogus\n",
			query);
		return -1;
	}

	if (ast_strlen_zero(canonical)) {
		ast_debug(2, "Query '%p': Could not set result information since no canonical name was provided\n",
			query);
		return -1;
	}

	if (query->result) {
		ast_dns_result_free(query->result);
	}

	query->result = ao2_alloc_options(sizeof(*query->result) + strlen(canonical) + 1, dns_result_destroy, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!query->result) {
		return -1;
	}

	query->result->secure = secure;
	query->result->bogus = bogus;
	query->result->rcode = rcode;
	strcpy(query->result->canonical, canonical); /* SAFE */

	return 0;
}

int ast_dns_resolver_add_record(struct ast_dns_query *query, int rr_type, int rr_class, int ttl, const char *data, const size_t size)
{
	struct ast_dns_record *record;

	if (rr_type < 0) {
		ast_debug(2, "Query '%p': Could not add record, invalid resource record type '%d'\n",
			query, rr_type);
		return -1;
	} else if (rr_type > ns_t_max) {
		ast_debug(2, "Query '%p': Could not add record, resource record type '%d' exceeds maximum\n",
			query, rr_type);
		return -1;
	} else if (rr_class < 0) {
		ast_debug(2, "Query '%p': Could not add record, invalid resource record class '%d'\n",
			query, rr_class);
		return -1;
	} else if (rr_class > ns_c_max) {
		ast_debug(2, "Query '%p': Could not add record, resource record class '%d' exceeds maximum\n",
			query, rr_class);
		return -1;
	} else if (ttl < 0) {
		ast_debug(2, "Query '%p': Could not add record, invalid TTL '%d'\n",
			query, ttl);
		return -1;
	} else if (!data || !size) {
		ast_debug(2, "Query '%p': Could not add record, no data specified\n",
			query);
		return -1;
	} else if (!query->result) {
		ast_debug(2, "Query '%p': No result was set on the query, thus records can not be added\n",
			query);
		return -1;
	}

	record = ast_calloc(1, sizeof(*record) + size);
	if (!record) {
		return -1;
	}

	record->rr_type = rr_type;
	record->rr_class = rr_class;
	record->ttl = ttl;
	memcpy(record->data, data, size);
	record->data_len = size;

	AST_LIST_INSERT_TAIL(&query->result->records, record, list);

	return 0;
}

void ast_dns_resolver_completed(struct ast_dns_query *query)
{
	query->callback(query);
}

/*! \brief Destructor for a DNS query */
static void dns_query_recurring_destroy(void *data)
{
	struct ast_dns_query_recurring *recurring = data;

	ao2_cleanup(recurring->user_data);
}

/*! \brief Determine the TTL to use when scheduling recurring resolution */
static int dns_query_recurring_get_ttl(const struct ast_dns_query *query)
{
	int ttl = 0;
	const struct ast_dns_result *result = ast_dns_query_get_result(query);
	const struct ast_dns_record *record;

	if (ast_dns_result_get_rcode(result) == ns_r_nxdomain) {
		return 0;
	}

	for (record = ast_dns_result_get_records(result); record; record = ast_dns_record_get_next(record)) {
		if (!ttl || (ast_dns_record_get_ttl(record) < ttl)) {
			ttl = ast_dns_record_get_ttl(record);
		}
	}

	return ttl;
}

static void dns_query_recurring_resolution_callback(const struct ast_dns_query *query);

/*! \brief Scheduled recurring query callback */
static int dns_query_recurring_scheduled_callback(const void *data)
{
	struct ast_dns_query_recurring *recurring = (struct ast_dns_query_recurring *)data;

	ao2_lock(recurring);
	recurring->timer = -1;
	if (!recurring->cancelled) {
		recurring->query = ast_dns_resolve_async(recurring->name, recurring->rr_type, recurring->rr_class, dns_query_recurring_resolution_callback,
			recurring);
	}
	ao2_unlock(recurring);

	ao2_ref(recurring, -1);

	return 0;
}

/*! \brief Query resolution callback */
static void dns_query_recurring_resolution_callback(const struct ast_dns_query *query)
{
	struct ast_dns_query_recurring *recurring = ast_dns_query_get_data(query);

	/* Replace the user data so the actual callback sees what it provided */
	((struct ast_dns_query*)query)->user_data = ao2_bump(recurring->user_data);
	recurring->callback(query);

	ao2_lock(recurring);
	/* So.. if something has not externally cancelled this we can reschedule based on the TTL */
	if (!recurring->cancelled) {
		int ttl = dns_query_recurring_get_ttl(query);

		if (ttl) {
			recurring->timer = ast_sched_add(sched, ttl * 1000, dns_query_recurring_scheduled_callback, ao2_bump(recurring));
			if (recurring->timer < 0) {
				ao2_ref(recurring, -1);
			}
		}
	}

	ao2_replace(recurring->query, NULL);
	ao2_unlock(recurring);

	/* Since we stole the reference from the query we need to drop it ourselves */
	ao2_ref(recurring, -1);
}

struct ast_dns_query_recurring *ast_dns_resolve_recurring(const char *name, int rr_type, int rr_class, ast_dns_resolve_callback callback, void *data)
{
	struct ast_dns_query_recurring *recurring;

	if (ast_strlen_zero(name) || !callback) {
		return NULL;
	}

	recurring = ao2_alloc(sizeof(*recurring) + strlen(name) + 1, dns_query_recurring_destroy);
	if (!recurring) {
		return NULL;
	}

	recurring->callback = callback;
	recurring->user_data = ao2_bump(data);
	recurring->timer = -1;
	recurring->rr_type = rr_type;
	recurring->rr_class = rr_class;
	strcpy(recurring->name, name); /* SAFE */

	/* The scheduler callback expects a reference, so bump it up */
	recurring->query = ast_dns_resolve_async(name, rr_type, rr_class, dns_query_recurring_resolution_callback, recurring);
	if (!recurring->query) {
		ao2_ref(recurring, -1);
		return NULL;
	}

	return recurring;
}

int ast_dns_resolve_recurring_cancel(struct ast_dns_query_recurring *recurring)
{
	ao2_lock(recurring);

	recurring->cancelled = 1;
	AST_SCHED_DEL_UNREF(sched, recurring->timer, ao2_ref(recurring, -1));

	if (recurring->query) {
		ast_dns_resolve_cancel(recurring->query);
		ao2_replace(recurring->query, NULL);
	}

	ao2_unlock(recurring);

	return 0;
}

static void dns_shutdown(void)
{
	if (sched) {
		ast_sched_context_destroy(sched);
		sched = NULL;
	}
}

int ast_dns_resolver_register(struct ast_dns_resolver *resolver)
{
	struct ast_dns_resolver *iter;
	int inserted = 0;

	if (!resolver) {
		return -1;
	} else if (ast_strlen_zero(resolver->name)) {
		ast_log(LOG_ERROR, "Registration of DNS resolver failed as it does not have a name\n");
		return -1;
	} else if (!resolver->resolve) {
		ast_log(LOG_ERROR, "DNS resolver '%s' does not implement the resolve callback which is required\n",
			resolver->name);
		return -1;
	} else if (!resolver->cancel) {
		ast_log(LOG_ERROR, "DNS resolver '%s' does not implement the cancel callback which is required\n",
			resolver->name);
		return -1;
	}

	AST_RWLIST_WRLOCK(&resolvers);

	/* On the first registration of a resolver start a scheduler for recurring queries */
	if (AST_LIST_EMPTY(&resolvers) && !sched) {
		sched = ast_sched_context_create();
		if (!sched) {
			ast_log(LOG_ERROR, "DNS resolver '%s' could not be registered: Failed to create scheduler for recurring DNS queries\n",
				resolver->name);
			AST_RWLIST_UNLOCK(&resolvers);
			return -1;
		}

		if (ast_sched_start_thread(sched)) {
			ast_log(LOG_ERROR, "DNS resolver '%s' could not be registered: Failed to start thread for recurring DNS queries\n",
				resolver->name);
			dns_shutdown();
			AST_RWLIST_UNLOCK(&resolvers);
			return -1;
		}

		ast_register_cleanup(dns_shutdown);
	}

	AST_LIST_TRAVERSE(&resolvers, iter, next) {
		if (!strcmp(iter->name, resolver->name)) {
			ast_log(LOG_ERROR, "A DNS resolver with the name '%s' is already registered\n", resolver->name);
			AST_RWLIST_UNLOCK(&resolvers);
			return -1;
		}
	}

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&resolvers, iter, next) {
		if (iter->priority > resolver->priority) {
			AST_RWLIST_INSERT_BEFORE_CURRENT(resolver, next);
			inserted = 1;
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	if (!inserted) {
		AST_RWLIST_INSERT_TAIL(&resolvers, resolver, next);
	}

	AST_RWLIST_UNLOCK(&resolvers);

	ast_verb(2, "Registered DNS resolver '%s' with priority '%d'\n", resolver->name, resolver->priority);

	return 0;
}

void ast_dns_resolver_unregister(struct ast_dns_resolver *resolver)
{
	struct ast_dns_resolver *iter;

	if (!resolver) {
		return;
	}

	AST_RWLIST_WRLOCK(&resolvers);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&resolvers, iter, next) {
		if (resolver == iter) {
			AST_RWLIST_REMOVE_CURRENT(next);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	AST_RWLIST_UNLOCK(&resolvers);

	ast_verb(2, "Unregistered DNS resolver '%s'\n", resolver->name);
}
