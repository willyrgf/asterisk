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
 * \brief DNS NAPTR Record Support
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <arpa/nameser.h>

#include "asterisk/dns_core.h"
#include "asterisk/dns_naptr.h"
#include "asterisk/linkedlists.h"
#include "asterisk/dns_internal.h"
#include "asterisk/utils.h"

static int compare_order(const void *record1, const void *record2)
{
	const struct ast_dns_naptr_record **left = (const struct ast_dns_naptr_record **)record1;
	const struct ast_dns_naptr_record **right = (const struct ast_dns_naptr_record **)record2;

	if ((*left)->order < (*right)->order) {
		return -1;
	} else if ((*left)->order > (*right)->order) {
		return 1;
	} else {
		return 0;
	}
}

static int compare_preference(const void *record1, const void *record2)
{
	const struct ast_dns_naptr_record **left = (const struct ast_dns_naptr_record **)record1;
	const struct ast_dns_naptr_record **right = (const struct ast_dns_naptr_record **)record2;

	if ((*left)->preference < (*right)->preference) {
		return -1;
	} else if ((*left)->preference > (*right)->preference) {
		return 1;
	} else {
		return 0;
	}
}

void ast_dns_naptr_sort(struct ast_dns_result *result)
{
	struct ast_dns_record *current;
	size_t num_records = 0;
	struct ast_dns_naptr_record **records;
	int i = 0;
	int j = 0;
	int cur_order;

	/* Determine the number of records */
	AST_LIST_TRAVERSE(&result->records, current, list) {
		++num_records;
	}

	/* Allocate an array with that number of records */
	records = ast_alloca(num_records * sizeof(*records));

	/* Move records from the list to the array */
	AST_LIST_TRAVERSE_SAFE_BEGIN(&result->records, current, list) {
		records[i++] = (struct ast_dns_naptr_record *) current;
		AST_LIST_REMOVE_CURRENT(list);
	}
	AST_LIST_TRAVERSE_SAFE_END;

	/* Sort the array by order */
	qsort(records, num_records, sizeof(*records), compare_order);

	/* Sort subarrays by preference */
	for (i = 0; i < num_records; i = j) {
		cur_order = records[i]->order;
		for (j = i + 1; j < num_records; ++j) {
			if (records[j]->order != cur_order) {
				break;
			}
		}
		qsort(&records[i], j - i, sizeof(*records), compare_preference);
	}

	/* Place sorted records back into the original list */
	for (i = 0; i < num_records; ++i) {
		AST_LIST_INSERT_TAIL(&result->records, (struct ast_dns_record *)(records[i]), list);
	}
}

const char *ast_dns_naptr_get_flags(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->flags;
}

const char *ast_dns_naptr_get_service(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->service;
}

const char *ast_dns_naptr_get_regexp(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->regexp;
}

const char *ast_dns_naptr_get_replacement(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->replacement;
}

unsigned short ast_dns_naptr_get_order(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->order;
}

unsigned short ast_dns_naptr_get_preference(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->preference;
}
