/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2015, Mark Michelson
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

/*** MODULEINFO
	<depend>TEST_FRAMEWORK</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include <arpa/nameser.h>

#include "asterisk/test.h"
#include "asterisk/module.h"
#include "asterisk/dns_core.h"
#include "asterisk/dns_resolver.h"
#include "asterisk/dns_naptr.h"

#define DNS_HEADER_SIZE 96

const char DNS_HEADER[] = {
	/* ID  == 0 */
	0x00, 0x00,
	/* QR == 1, Opcode == 0, AA == 1, TC == 0, RD == 1 */
	0x85,
	/* RA == 1, Z == 0, RCODE == 0 */
	0x80,
	/* QDCOUNT == 1 */
	0x00, 0x01,
	/* ANCOUNT == 1 */
	0x00, 0x00,
	/* NSCOUNT == 0 */
	0x00, 0x00,
	/* ARCOUNT == 0 */
	0x00, 0x00,
};

static int generate_dns_header(unsigned short num_records, char *buf)
{
	unsigned short net_num_records = htons(num_records);

	memcpy(buf, DNS_HEADER, ARRAY_LEN(DNS_HEADER));
	/* Overwrite the ANCOUNT with the actual number of answers */
	memcpy(&buf[6], &net_num_records, sizeof(num_records));

	return ARRAY_LEN(DNS_HEADER);
}

const char DNS_QUESTION [] = {
	/* goose */
	0x05, 0x67, 0x6f, 0x6f, 0x73, 0x65,
	/* feathers */
	0x08, 0x66, 0x65, 0x61, 0x74, 0x68, 0x65, 0x72, 0x73,
	/* end label */
	0x00,
	/* NAPTR type */
	0x00, 0x23,
	/* IN class */
	0x00, 0x01,
};

static int generate_dns_question(char *buf)
{
	memcpy(buf, DNS_QUESTION, ARRAY_LEN(DNS_QUESTION));
	return ARRAY_LEN(DNS_QUESTION);
}

const char NAPTR_ANSWER [] = {
	/* Domain points to name from question */
	0xc0, 0x0c,
	/* NAPTR type */
	0x00, 0x23,
	/* IN Class */
	0x00, 0x01,
	/* TTL (12345 by default) */
	0x00, 0x00, 0x30, 0x39,
};

static int generate_dns_answer(int ttl, char *buf)
{
	int net_ttl = htonl(ttl);

	memcpy(buf, NAPTR_ANSWER, ARRAY_LEN(NAPTR_ANSWER));
	/* Overwrite TTL if one is provided */
	if (ttl) {
		memcpy(&buf[6], &net_ttl, sizeof(int));
	}

	return ARRAY_LEN(NAPTR_ANSWER);
}

struct dns_string {
	uint8_t len;
	const char *val;
};

static int write_dns_string(const struct dns_string *string, char *buf)
{
	uint8_t len = string->len;
	buf[0] = len;
	/*
	 * We use the actual length of the string instead of
	 * the stated value since sometimes we're going to lie about
	 * the length of the string
	 */
	if (strlen(string->val)) {
		memcpy(&buf[1], string->val, strlen(string->val));
	}

	return strlen(string->val) + 1;
}

static int write_dns_domain(const char *string, char *buf)
{
	char *copy = ast_strdupa(string);
	char *part;
	char *ptr = buf;
	static const struct dns_string null_label = {
		.len = 0,
		.val = "",
	};

	while (1) {
		struct dns_string dns_str;
		part = strsep(&copy, ".");
		if (ast_strlen_zero(part)) {
			break;
		}
		dns_str.len = strlen(part);
		dns_str.val = part;

		ptr += write_dns_string(&dns_str, ptr);
	}
	ptr += write_dns_string(&null_label, ptr);

	return ptr - buf;
}

struct naptr_record {
	uint16_t order;
	uint16_t preference;
	struct dns_string flags;
	struct dns_string services;
	struct dns_string regexp;
	const char * replacement;
};

static int generate_naptr_record(struct naptr_record *record, char *buf)
{
	uint16_t net_order = htons(record->order);
	uint16_t net_preference = htons(record->preference);
	char *ptr = buf;

	memcpy(ptr, &net_order, sizeof(net_order));
	ptr += sizeof(net_order);

	memcpy(ptr, &net_preference, sizeof(net_preference));
	ptr += sizeof(net_preference);

	ptr += write_dns_string(&record->flags, ptr);
	ptr += write_dns_string(&record->services, ptr);
	ptr += write_dns_string(&record->regexp, ptr);
	ptr += write_dns_domain(record->replacement, ptr);

	return ptr - buf;
}

static struct naptr_record *test_records;
static int num_test_records;
static char ans_buffer[1024];

static void *naptr_thread(void *dns_query)
{
	struct ast_dns_query *query = dns_query;
	int i;
	char *ptr = ans_buffer;
	
	ptr += generate_dns_header(num_test_records, ptr);
	ptr += generate_dns_question(ptr);

	for (i = 0; i < num_test_records; ++i) {
		unsigned short rdlength;
		unsigned short net_rdlength;

		ptr += generate_dns_answer(0, ptr);
		rdlength = generate_naptr_record(&test_records[i], ptr + 2);
		net_rdlength = htons(rdlength);
		memcpy(ptr, &net_rdlength, 2);
		ptr += 2;
		ptr += rdlength;
	}

	ast_dns_resolver_set_result(query, 0, 0, ns_r_noerror, "goose.feathers", ans_buffer, ptr - ans_buffer);

	for (i = 0; i < num_test_records; ++i) {
		char record[128];
		ptr = record;

		ptr += generate_naptr_record(&test_records[i], ptr);
		ast_dns_resolver_add_record(query, ns_t_naptr, ns_c_in, 12345, record, ptr - record);
	}

	ast_dns_resolver_completed(query);

	ao2_ref(query, -1);
	return NULL;
}

static int naptr_resolve(struct ast_dns_query *query)
{
	pthread_t thread;

	return ast_pthread_create_detached(&thread, NULL, naptr_thread, ao2_bump(query));
}

static int naptr_cancel(struct ast_dns_query *query)
{
	return 0;
}

static struct ast_dns_resolver naptr_resolver = {
	.name = "naptr_test",
	.priority = 0,
	.resolve = naptr_resolve,
	.cancel = naptr_cancel,
};

AST_TEST_DEFINE(naptr_resolve_nominal)
{
	RAII_VAR(struct ast_dns_result *, result, NULL, ast_dns_result_free);
	const struct ast_dns_record *record;
	struct naptr_record records[] = {
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {0, ""}, "goose.down" },
		{ 200, 200, {1, "A"}, {4, "BLAH"}, {0, ""}, "duck.down" },
		{ 100, 200, {1, "A"}, {4, "BLAH"}, {18, "![^\\.]+\\.(.*)$!\\1!"}, "" },
		{ 200, 100, {1, "A"}, {4, "BLAH"}, {29, "!([^\\.]+\\.)(.*)$!\\1.happy.\\2!"}, "" },
	};

	int naptr_record_order[] = { 0, 2, 3, 1 };
	enum ast_test_result_state res = AST_TEST_PASS;
	int i;

	switch (cmd) {
	case TEST_INIT:
		info->name = "naptr_resolve";
		info->category = "/main/dns/naptr/";
		info->summary = "Test nominal resolution of NAPTR records";
		info->description = "This test defines four valid NAPTR records and\n"
			"performs a resolution of the domain to which they belong. The test\n"
			"ensures that all fields of the NAPTR records are parsed correctly\n"
			"and that the records are returned in sorted order\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	test_records = records;
	num_test_records = ARRAY_LEN(records);
	memset(ans_buffer, 0, sizeof(ans_buffer));

	ast_dns_resolver_register(&naptr_resolver);

	if (ast_dns_resolve("goose.feathers", ns_t_naptr, ns_c_in, &result)) {
		ast_test_status_update(test, "DNS resolution failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!result) {
		ast_test_status_update(test, "DNS resolution returned no result\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	i = 0;
	for (record = ast_dns_result_get_records(result); record; record = ast_dns_record_get_next(record)) {
		if (ast_dns_naptr_get_order(record) != records[naptr_record_order[i]].order) {
			ast_test_status_update(test, "Unexpected order in returned NAPTR record\n");
			res = AST_TEST_FAIL;
		}
		if (ast_dns_naptr_get_preference(record) != records[naptr_record_order[i]].preference) {
			ast_test_status_update(test, "Unexpected preference in returned NAPTR record\n");
			res = AST_TEST_FAIL;
		}
		if (strcmp(ast_dns_naptr_get_flags(record), records[naptr_record_order[i]].flags.val)) {
			ast_test_status_update(test, "Unexpected flags in returned NAPTR record\n");
			res = AST_TEST_FAIL;
		}
		if (strcmp(ast_dns_naptr_get_service(record), records[naptr_record_order[i]].services.val)) {
			ast_test_status_update(test, "Unexpected services in returned NAPTR record\n");
			res = AST_TEST_FAIL;
		}
		if (strcmp(ast_dns_naptr_get_regexp(record), records[naptr_record_order[i]].regexp.val)) {
			ast_test_status_update(test, "Unexpected regexp in returned NAPTR record\n");
			res = AST_TEST_FAIL;
		}
		if (strcmp(ast_dns_naptr_get_replacement(record), records[naptr_record_order[i]].replacement)) {
			ast_test_status_update(test, "Unexpected replacement in returned NAPTR record\n");
			res = AST_TEST_FAIL;
		}
		++i;
	}

	if (i != ARRAY_LEN(records)) {
		ast_test_status_update(test, "Unexpected number of records returned in NAPTR lookup\n");
		res = AST_TEST_FAIL;
	}

cleanup:

	ast_dns_resolver_unregister(&naptr_resolver);

	test_records = NULL;
	num_test_records = 0;
	memset(ans_buffer, 0, sizeof(ans_buffer));

	return res;
}

static enum ast_test_result_state off_nominal_test(struct ast_test *test, struct naptr_record *records, int num_records)
{
	RAII_VAR(struct ast_dns_result *, result, NULL, ast_dns_result_free);
	enum ast_test_result_state res = AST_TEST_PASS;
	const struct ast_dns_record *record;

	test_records = records;
	num_test_records = num_records;
	memset(ans_buffer, 0, sizeof(ans_buffer));

	ast_dns_resolver_register(&naptr_resolver);

	if (ast_dns_resolve("goose.feathers", ns_t_naptr, ns_c_in, &result)) {
		ast_test_status_update(test, "Failed to perform DNS resolution, despite using valid inputs\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!result) {
		ast_test_status_update(test, "Synchronous DNS resolution failed to set a result\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	record = ast_dns_result_get_records(result);
	if (record) {
		ast_test_status_update(test, "DNS resolution returned records when it was not expected to\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

cleanup:
	ast_dns_resolver_unregister(&naptr_resolver);

	test_records = NULL;
	num_test_records = 0;
	memset(ans_buffer, 0, sizeof(ans_buffer));

	return res;
}

AST_TEST_DEFINE(naptr_resolve_off_nominal_length)
{
	struct naptr_record records[] = {
		{ 100, 100, {255, "A"}, {4, "BLAH"},   {15, "!.*!horse.mane!"}, "" },
		{ 100, 100, {0, "A"},   {4, "BLAH"},   {15, "!.*!horse.mane!"}, "" },
		{ 100, 100, {1, "A"},   {255, "BLAH"}, {15, "!.*!horse.mane!"}, "" },
		{ 100, 100, {1, "A"},   {2, "BLAH"},   {15, "!.*!horse.mane!"}, "" },
		{ 100, 100, {1, "A"},   {4, "BLAH"},   {255, "!.*!horse.mane!"}, "" },
		{ 100, 100, {1, "A"},   {4, "BLAH"},   {3, "!.*!horse.mane!"}, "" },
		{ 100, 100, {255, "A"}, {255, "BLAH"}, {255, "!.*!horse.mane!"}, "" },
		{ 100, 100, {0, "A"},   {2, "BLAH"},   {3, "!.*!horse.mane!"}, "" },
	};

	switch (cmd) {
	case TEST_INIT:
		info->name = "naptr_resolve_off_nominal_length";
		info->category = "/main/dns/naptr/";
		info->summary = "Test resolution of NAPTR records with off-nominal lengths";
		info->description = "This test defines a set of records where the strings provided\n"
			"within the record are valid, but the lengths of the strings in the record are\n"
			"invalid, either too large or too small. The goal of this test is to ensure that\n"
			"these invalid lengths result in resolution failures\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	return off_nominal_test(test, records, ARRAY_LEN(records));
}

AST_TEST_DEFINE(naptr_resolve_off_nominal_flags)
{
	struct naptr_record records[] = {
		/* Non-alphanumeric flag */
		{ 100, 100, {1, "!"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		/* Mix of valid and non-alphanumeric */
		{ 100, 100, {2, "A!"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "!A"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		/* Invalid combinations of flags */
		{ 100, 100, {2, "sa"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "su"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "sp"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "as"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "au"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "ap"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "ua"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "us"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "up"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "pa"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "ps"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {2, "pu"}, {4, "BLAH"}, {15, "!.*!horse.mane!"}, ""},
	};

	switch (cmd) {
	case TEST_INIT:
		info->name = "naptr_resolve_off_nominal_flags";
		info->category = "/main/dns/naptr/";
		info->summary = "Ensure that NAPTR records with invalid flags are not presented in results";
		info->description = "This test defines a set of records where the flags provided are\n"
			"invalid in some way. This may be due to providing non-alphanumeric characters or\n"
			"by providing clashing flags. The result should be that none of the defined records\n"
			"are returned by the resolver\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	return off_nominal_test(test, records, ARRAY_LEN(records));
}

AST_TEST_DEFINE(naptr_resolve_off_nominal_services)
{
	struct naptr_record records[] = {
		{ 100, 100, {1, "A"}, {5, "BLAH!"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {5, "BL!AH"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {8, "1SIP+D2U"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {8, "SIP+1D2U"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {4, "+D2U"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {4, "SIP+"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {8, "SIP++D2U"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {37, "SIPSIPSIPSIPSIPSIPSIPSIPSIPSIPSIP+D2U"}, {15, "!.*!horse.mane!"}, ""},
		{ 100, 100, {1, "A"}, {37, "SIP+D2UD2UD2UD2UD2UD2UD2UD2UD2UD2UD2U"}, {15, "!.*!horse.mane!"}, ""},
	};

	switch (cmd) {
	case TEST_INIT:
		info->name = "naptr_resolve_off_nominal_services";
		info->category = "/main/dns/naptr/";
		info->summary = "Ensure that NAPTR records with invalid services are not presented in results";
		info->description = "This test defines a set of records where the services provided are\n"
			"invalid in some way. This may be due to providing non-alphanumeric characters, providing\n"
			"protocols or resolution services that start with a non-alphabetic character, or\n"
			"providing fields that are too long.\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	return off_nominal_test(test, records, ARRAY_LEN(records));
}

AST_TEST_DEFINE(naptr_resolve_off_nominal_regexp)
{
	struct naptr_record records[] = {
		/* Invalid delim-char */
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {15, "1.*1horse.mane1"}, ""},
		/* Not enough delim-chars */
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {14, "!.*!horse.mane"}, ""},
		/* Not enough delim-chars, part 2 */
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {16, "!.*!horse.mane\\!"}, ""},
		/* Too many delim-chars */
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {15, "!.*!horse!mane!"}, ""},
		/* Invalid regex flag */
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {16, "!.*!horse.mane!o"}, ""},
		/* Invalid backreference */
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {14, "!.*!horse.\\0!"}, ""},
		/* Invalid regex */
		{ 100, 100, {1, "A"}, {4, "BLAH"}, {16, "!(.*!horse.mane!"}, ""},
	};

	switch (cmd) {
	case TEST_INIT:
		info->name = "naptr_resolve_off_nominal_regexp";
		info->category = "/main/dns/naptr/";
		info->summary = "Ensure that NAPTR records with invalid services are not presented in results";
		info->description = "This test defines a set of records where the services provided are\n"
			"invalid in some way. This may be due to providing non-alphanumeric characters, providing\n"
			"protocols or resolution services that start with a non-alphabetic character, or\n"
			"providing fields that are too long.\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	return off_nominal_test(test, records, ARRAY_LEN(records));
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(naptr_resolve_nominal);
	AST_TEST_UNREGISTER(naptr_resolve_off_nominal_length);
	AST_TEST_UNREGISTER(naptr_resolve_off_nominal_flags);
	AST_TEST_UNREGISTER(naptr_resolve_off_nominal_services);
	AST_TEST_UNREGISTER(naptr_resolve_off_nominal_regexp);

	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(naptr_resolve_nominal);
	AST_TEST_REGISTER(naptr_resolve_off_nominal_length);
	AST_TEST_REGISTER(naptr_resolve_off_nominal_flags);
	AST_TEST_REGISTER(naptr_resolve_off_nominal_services);
	AST_TEST_REGISTER(naptr_resolve_off_nominal_regexp);

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "DNS API Tests");
