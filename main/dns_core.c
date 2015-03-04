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
#include "asterisk/dns_core.h"
#include "asterisk/dns_naptr.h"
#include "asterisk/dns_srv.h"
#include "asterisk/dns_tlsa.h"
#include "asterisk/dns_resolver.h"

AST_RWLIST_HEAD_STATIC(resolvers, ast_dns_resolver);

const char *ast_dns_query_get_name(const struct ast_dns_query *query)
{
	return NULL;
}

int ast_dns_query_get_rr_type(const struct ast_dns_query *query)
{
		return 0;
}

int ast_dns_query_get_rr_class(const struct ast_dns_query *query)
{
	return 0;
}

int ast_dns_query_get_rcode(const struct ast_dns_query *query)
{
	return 0;
}

void *ast_dns_query_get_data(const struct ast_dns_query *query)
{
	return NULL;
}

struct ast_dns_result *ast_dns_query_get_result(const struct ast_dns_query *query)
{
	return NULL;
}

unsigned int ast_dns_result_get_nxdomain(const struct ast_dns_result *result)
{
	return 0;
}

unsigned int ast_dns_result_get_secure(const struct ast_dns_result *result)
{
	return 0;
}

unsigned int ast_dns_result_get_bogus(const struct ast_dns_result *result)
{
	return 0;
}

const char *ast_dns_result_get_canonical(const struct ast_dns_result *result)
{
	return NULL;
}

const struct ast_dns_record *ast_dns_result_get_records(const struct ast_dns_result *result)
{
	return NULL;
}

void ast_dns_result_free(struct ast_dns_result *result)
{
}

int ast_dns_record_get_rr_type(const struct ast_dns_record *record)
{
	return 0;
}

int ast_dns_record_get_rr_class(const struct ast_dns_record *record)
{
	return 0;
}

int ast_dns_record_get_ttl(const struct ast_dns_record *record)
{
	return 0;
}

const char *ast_dns_record_get_data(const struct ast_dns_record *record)
{
	return NULL;
}

struct ast_dns_record *ast_dns_record_get_next(const struct ast_dns_record *record)
{
	return NULL;
}

struct ast_dns_query *ast_dns_resolve_async(const char *name, int rr_type, int rr_class, ast_dns_resolve_callback callback, void *data)
{
	return NULL;
}

struct ast_dns_query *ast_dns_resolve_async_recurring(const char *name, int rr_type, int rr_class, ast_dns_resolve_callback callback, void *data)
{
	return NULL;
}

int ast_dns_resolve_cancel(struct ast_dns_query *query)
{
	return 0;
}

int ast_dns_resolve(const char *name, int rr_type, int rr_class, struct ast_dns_result **result)
{
	return 0;
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

void ast_dns_resolver_set_data(struct ast_dns_query *query, void *data)
{
}

void *ast_dns_resolver_get_data(const struct ast_dns_query *query)
{
	return NULL;
}

void ast_dns_resolver_set_result(struct ast_dns_query *query, unsigned int nxdomain, unsigned int secure, unsigned int bogus,
	const char *canonical)
{
}

int ast_dns_resolver_add_record(struct ast_dns_query *query, int rr_type, int rr_class, int ttl, char *data, size_t size)
{
	return -1;
}

void ast_dns_resolver_completed(const struct ast_dns_query *query)
{
}

int ast_dns_resolver_register(struct ast_dns_resolver *resolver)
{
	struct ast_dns_resolver *iter;
	int inserted = 0;

	AST_RWLIST_WRLOCK(&resolvers);

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