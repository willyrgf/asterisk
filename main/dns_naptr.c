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
#include <resolv.h>

#include "asterisk/dns_core.h"
#include "asterisk/dns_naptr.h"
#include "asterisk/linkedlists.h"
#include "asterisk/dns_internal.h"
#include "asterisk/utils.h"

struct ast_dns_record *ast_dns_naptr_alloc(struct ast_dns_query *query, const char *data, const size_t size)
{
	struct ast_dns_naptr_record *naptr;
	char *ptr = NULL;
	uint16_t order;
	uint16_t preference;
	uint8_t flags_size;
	char *flags;
	uint8_t services_size;
	char *services;
	uint8_t regexp_size;
	char *regexp;
	char replacement[256] = "";
	int replacement_size;
	char *naptr_offset;
	char *naptr_search_base = (char *)query->result->answer;
	size_t remaining_size = query->result->answer_size;
	char *end_of_record;

	/* 
	 * This is bordering on the hackiest thing I've ever written.
	 * Part of parsing a NAPTR record is to parse a potential replacement
	 * domain name. Decoding this domain name requires the use of the
	 * dn_expand() function. This function requires that the domain you
	 * pass in be a pointer to within the full DNS answer. Unfortunately,
	 * libunbound gives its RRs back as copies of data from the DNS answer
	 * instead of pointers to within the DNS answer. This means that in order
	 * to be able to parse the domain name correctly, I need to find the
	 * current NAPTR record inside the DNS answer and operate on it. This
	 * loop is designed to find the current NAPTR record within the full
	 * DNS answer and set the "ptr" variable to the beginning of the
	 * NAPTR RDATA
	 */
	while (1) {
		naptr_offset = memchr(naptr_search_base, data[0], remaining_size);

		/* Since the NAPTR record we have been given came from the DNS answer,
		 * we should never run into a situation where we can't find ourself
		 * in the answer
		 */
		ast_assert(naptr_offset != NULL);
		ast_assert(naptr_search_base + remaining_size - naptr_offset >= size);
		
		if (!memcmp(naptr_offset, data, size)) {
			/* BAM! FOUND IT! */
			ptr = naptr_offset;
			break;
		}
		/* Data didn't match us, so keep looking */
		remaining_size -= naptr_offset - naptr_search_base;
		naptr_search_base = naptr_offset + 1;
	}

	ast_assert(ptr != NULL);

	end_of_record = ptr + size;

	/* ORDER */
	order = ((unsigned char)(ptr[1]) << 0) | ((unsigned char)(ptr[0]) << 8);
	ptr += 2;

	if (ptr >= end_of_record) {
		return NULL;
	}

	/* PREFERENCE */
	preference = ((unsigned char) (ptr[1]) << 0) | ((unsigned char)(ptr[0]) << 8);
	ptr += 2;

	if (ptr >= end_of_record) {
		return NULL;
	}

	/* FLAGS */
	flags_size = *ptr;
	++ptr;
	if (ptr >= end_of_record) {
		return NULL;
	}
	flags = ptr;
	ptr += flags_size;
	if (ptr >= end_of_record) {
		return NULL;
	}

	/* SERVICES */
	services_size = *ptr;
	++ptr;
	if (ptr >= end_of_record) {
		return NULL;
	}
	services = ptr;
	ptr += services_size;
	if (ptr >= end_of_record) {
		return NULL;
	}

	/* REGEXP */
	regexp_size = *ptr;
	++ptr;
	if (ptr >= end_of_record) {
		return NULL;
	}
	regexp = ptr;
	ptr += regexp_size;
	if (ptr >= end_of_record) {
		return NULL;
	}

	replacement_size = dn_expand((unsigned char *)query->result->answer, (unsigned char *) end_of_record, (unsigned char *) ptr, replacement, sizeof(replacement) - 1);
	if (replacement_size < 0) {
		ast_log(LOG_ERROR, "Failed to expand domain name: %s\n", strerror(errno));
		return NULL;
	}

	naptr = ast_calloc(1, sizeof(*naptr) + size + flags_size + 1 + services_size + 1 + regexp_size + 1 + replacement_size + 1);
	if (!naptr) {
		return NULL;
	}

	naptr->order = order;
	naptr->preference = preference;

	ptr = naptr->data;
	ptr += size;

	strncpy(ptr, flags, flags_size);
	ptr[flags_size] = '\0';
	naptr->flags = ptr;
	ptr += flags_size + 1;

	strncpy(ptr, services, services_size);
	ptr[services_size] = '\0';
	naptr->service = ptr;
	ptr += services_size + 1;

	strncpy(ptr, regexp, regexp_size);
	ptr[regexp_size] = '\0';
	naptr->regexp = ptr;
	ptr += regexp_size + 1;

	strcpy(ptr, replacement);
	naptr->replacement = ptr;

	naptr->generic.data_ptr = naptr->data;

	return (struct ast_dns_record *)naptr;
}


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
