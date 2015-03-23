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
 * \brief DNS SRV Record Support
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "asterisk/dns_core.h"
#include "asterisk/dns_srv.h"
#include "asterisk/linkedlists.h"
#include "asterisk/dns_internal.h"
#include "asterisk/utils.h"

struct ast_dns_record *ast_dns_srv_alloc(struct ast_dns_query *query, const char *data, const size_t size)
{
	const char *ptr = data;
	size_t remaining = size;
	struct ast_dns_srv_record *srv;
	unsigned short priority;
	unsigned short weight;
	unsigned short port;
	int host_size;
	char host[256] = "";

	if (remaining < 2) {
		return NULL;
	}
	priority = (ptr[1] << 0) | (ptr[0] << 8);
	ptr += 2;
	remaining -= 2;

	if (remaining < 2) {
		return NULL;
	}
	weight = (ptr[1] << 0) | (ptr[0] << 8);
	ptr += 2;
	remaining -= 2;

	if (remaining < 2) {
		return NULL;
	}
	port = (ptr[1] << 0) | (ptr[0] << 8);
	ptr += 2;

	/* This currently assumes that the DNS core will provide a record within the full answer, which I'm going to talk to
	 * Mark about in a few hours
	 */
	host_size = dn_expand((unsigned char *)query->result->answer, (unsigned char *) data, (unsigned char *) ptr, host, sizeof(host) - 1);
	if (host_size < 0) {
		ast_log(LOG_ERROR, "Failed to expand domain name: %s\n", strerror(errno));
		return NULL;
	}

	if (!strcmp(host, ".")) {
		return NULL;
	}

	srv = ast_calloc(1, sizeof(*srv) + host_size + 1);
	if (!srv) {
		return NULL;
	}

	srv->priority = ntohs(priority);
	srv->weight = ntohs(weight);
	srv->port = ntohs(port);
	strcpy(srv->host, host); /* SAFE */

	return (struct ast_dns_record *)srv;
}

/* This implementation was taken from the existing srv.c which, after reading the RFC, implements it
 * as it should.
 */
void ast_dns_srv_sort(struct ast_dns_result *result)
{
	struct ast_dns_record *current;
	struct dns_records newlist = AST_LIST_HEAD_NOLOCK_INIT_VALUE;

	while (AST_LIST_FIRST(&result->records)) {
		unsigned int random_weight;
		unsigned int weight_sum;
		unsigned short cur_priority = ((struct ast_dns_srv_record *)AST_LIST_FIRST(&result->records))->priority;
		struct dns_records temp_list = AST_LIST_HEAD_NOLOCK_INIT_VALUE;
		weight_sum = 0;

		AST_LIST_TRAVERSE_SAFE_BEGIN(&result->records, current, list) {
			if (((struct ast_dns_srv_record *)current)->priority != cur_priority)
				break;

			AST_LIST_MOVE_CURRENT(&temp_list, list);
		}
		AST_LIST_TRAVERSE_SAFE_END;

		while (AST_LIST_FIRST(&temp_list)) {
			weight_sum = 0;

			AST_LIST_TRAVERSE(&temp_list, current, list) {
				weight_sum += ((struct ast_dns_srv_record *)current)->weight;
			}

			/* if all the remaining entries have weight == 0,
			   then just append them to the result list and quit */
			if (weight_sum == 0) {
				AST_LIST_APPEND_LIST(&newlist, &temp_list, list);
				break;
			}

			random_weight = 1 + (unsigned int) ((float) weight_sum * (ast_random() / ((float) RAND_MAX + 1.0)));

			AST_LIST_TRAVERSE_SAFE_BEGIN(&temp_list, current, list) {
				if (((struct ast_dns_srv_record *)current)->weight < random_weight)
					continue;

				AST_LIST_MOVE_CURRENT(&newlist, list);
				break;
			}
			AST_LIST_TRAVERSE_SAFE_END;
		}

	}

	/* now that the new list has been ordered,
	   put it in place */

	AST_LIST_APPEND_LIST(&result->records, &newlist, list);
}

const char *ast_dns_srv_get_host(const struct ast_dns_record *record)
{
	struct ast_dns_srv_record *srv = (struct ast_dns_srv_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_srv);
	return srv->host;
}

unsigned short ast_dns_srv_get_priority(const struct ast_dns_record *record)
{
	struct ast_dns_srv_record *srv = (struct ast_dns_srv_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_srv);
	return srv->priority;
}

unsigned short ast_dns_srv_get_weight(const struct ast_dns_record *record)
{
	struct ast_dns_srv_record *srv = (struct ast_dns_srv_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_srv);
	return srv->weight;
}

unsigned short ast_dns_srv_get_port(const struct ast_dns_record *record)
{
	struct ast_dns_srv_record *srv = (struct ast_dns_srv_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_srv);
	return srv->port;
}
