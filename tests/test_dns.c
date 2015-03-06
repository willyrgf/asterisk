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
#include <arpa/inet.h>

#include "asterisk/test.h"
#include "asterisk/module.h"
#include "asterisk/dns_core.h"
#include "asterisk/dns_resolver.h"
#include "asterisk/dns_internal.h"

/* Used when a stub is needed for certain tests */
static int stub_resolve(struct ast_dns_query *query)
{
	return 0;
}

/* Used when a stub is needed for certain tests */
static int stub_cancel(struct ast_dns_query *query)
{
	return 0;
}

AST_TEST_DEFINE(resolver_register_unregister)
{
	struct ast_dns_resolver cool_guy_resolver = {
		.name = "A snake that swallowed a deer",
		.priority = 19890504,
		.resolve = stub_resolve,
		.cancel = stub_cancel,
	};

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_register_unregister";
		info->category = "/main/dns/";
		info->summary = "Test nominal resolver registration and unregistration";
		info->description =
			"The test performs the following steps:\n"
			"\t* Register a valid resolver.\n"
			"\t* Unregister the resolver.\n"
			"If either step fails, the test fails\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	if (ast_dns_resolver_register(&cool_guy_resolver)) {
		ast_test_status_update(test, "Unable to register a perfectly good resolver\n");
		return AST_TEST_FAIL;
	}

	ast_dns_resolver_unregister(&cool_guy_resolver);

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(resolver_register_off_nominal)
{
	struct ast_dns_resolver valid = {
		.name = "valid",
		.resolve = stub_resolve,
		.cancel = stub_cancel,
	};

	struct ast_dns_resolver incomplete1 = {
		.name = NULL,
		.resolve = stub_resolve,
		.cancel = stub_cancel,
	};

	struct ast_dns_resolver incomplete2 = {
		.name = "incomplete2",
		.resolve = NULL,
		.cancel = stub_cancel,
	};

	struct ast_dns_resolver incomplete3 = {
		.name = "incomplete3",
		.resolve = stub_resolve,
		.cancel = NULL,
	};

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_register_off_nominal";
		info->category = "/main/dns/";
		info->summary = "Test off-nominal resolver registration";
		info->description =
			"Test off-nominal resolver registration:\n"
			"\t* Register a duplicate resolver\n"
			"\t* Register a resolver without a name\n"
			"\t* Register a resolver without a resolve() method\n"
			"\t* Register a resolver without a cancel() method\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	if (ast_dns_resolver_register(&valid)) {
		ast_test_status_update(test, "Failed to register valid resolver\n");
		return AST_TEST_FAIL;
	}

	if (!ast_dns_resolver_register(&valid)) {
		ast_test_status_update(test, "Successfully registered the same resolver multiple times\n");
		return AST_TEST_FAIL;
	}

	ast_dns_resolver_unregister(&valid);

	if (!ast_dns_resolver_register(NULL)) {
		ast_test_status_update(test, "Successfully registered a NULL resolver\n");
		return AST_TEST_FAIL;
	}

	if (!ast_dns_resolver_register(&incomplete1)) {
		ast_test_status_update(test, "Successfully registered a DNS resolver with no name\n");
		return AST_TEST_FAIL;
	}

	if (!ast_dns_resolver_register(&incomplete2)) {
		ast_test_status_update(test, "Successfully registered a DNS resolver with no resolve() method\n");
		return AST_TEST_FAIL;
	}

	if (!ast_dns_resolver_register(&incomplete3)) {
		ast_test_status_update(test, "Successfully registered a DNS resolver with no cancel() method\n");
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(resolver_unregister_off_nominal)
{
	struct ast_dns_resolver non_existent = {
		.name = "I do not exist",
		.priority = 20141004,
		.resolve = stub_resolve,
		.cancel = stub_cancel,
	};

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_unregister_off_nominal";
		info->category = "/main/dns/";
		info->summary = "Test off-nominal DNS resolver unregister";
		info->description =
			"The test attempts the following:\n"
			"\t* Unregister a resolver that is not registered.\n"
			"\t* Unregister a NULL pointer.\n"
			"Because unregistering a resolver does not return an indicator of success, the best\n"
			"this test can do is verify that nothing blows up when this is attempted.\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_dns_resolver_unregister(&non_existent);
	ast_dns_resolver_unregister(NULL);

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(resolver_data)
{
	struct ast_dns_query some_query;

	struct digits {
		int fingers;
		int toes;
	};
	
	struct digits average = {
		.fingers = 10,
		.toes = 10,
	};

	struct digits polydactyl = {
		.fingers = 12,
		.toes = 10,
	};

	struct digits *data_ptr;

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_data";
		info->category = "/main/dns/";
		info->summary = "Test getting and setting data on a DNS resolver";
		info->description = "This test does the following:\n"
			"\t* Ensure that requesting resolver data results in a NULL return if no data has been set.\n"
			"\t* Ensure that setting resolver data does not result in an error.\n"
			"\t* Ensure that retrieving the set resolver data returns the data we expect\n"
			"\t* Ensure that setting new resolver data on the query does not result in an error\n"
			"\t* Ensure that retrieving the resolver data returns the new data that we set\n"
			"\t* Ensure that ast_dns_resolver_completed() removes resolver data from the query\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	memset(&some_query, 0, sizeof(some_query));

	/* Ensure that NULL is retrieved if we haven't set anything on the query */
	data_ptr = ast_dns_resolver_get_data(&some_query);
	if (data_ptr) {
		ast_test_status_update(test, "Retrieved non-NULL resolver data from query unexpectedly\n");
		return AST_TEST_FAIL;
	}

	ast_dns_resolver_set_data(&some_query, &average);

	/* Ensure that data can be set and retrieved */
	data_ptr = ast_dns_resolver_get_data(&some_query);
	if (!data_ptr) {
		ast_test_status_update(test, "Unable to retrieve resolver data from DNS query\n");
		return AST_TEST_FAIL;
	}

	if (data_ptr->fingers != average.fingers || data_ptr->toes != average.toes) {
		ast_test_status_update(test, "Unexpected resolver data retrieved from DNS query\n");
		return AST_TEST_FAIL;
	}

	/* Ensure that we can set new resolver data even if there already is resolver data on the query */
	ast_dns_resolver_set_data(&some_query, &polydactyl);

	data_ptr = ast_dns_resolver_get_data(&some_query);
	if (!data_ptr) {
		ast_test_status_update(test, "Unable to retrieve resolver data from DNS query\n");
		return AST_TEST_FAIL;
	}

	if (data_ptr->fingers != polydactyl.fingers || data_ptr->toes != polydactyl.toes) {
		ast_test_status_update(test, "Unexpected resolver data retrieved from DNS query\n");
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

static int test_results(struct ast_test *test, const struct ast_dns_query *query,
		unsigned int expected_secure, unsigned int expected_bogus,
		unsigned int expected_rcode, const char *expected_canonical)
{
	struct ast_dns_result *result;

	result = ast_dns_query_get_result(query);
	if (!result) {
		ast_test_status_update(test, "Unable to retrieve result from query\n");
		return -1;
	}

	if (ast_dns_result_get_secure(result) != expected_secure ||
			ast_dns_result_get_bogus(result) != expected_bogus ||
			ast_dns_result_get_rcode(result) != expected_rcode ||
			strcmp(ast_dns_result_get_canonical(result), expected_canonical)) {
		ast_test_status_update(test, "Unexpected values in result from query\n");
		return -1;
	}

	return 0;
}

AST_TEST_DEFINE(resolver_set_result)
{
	struct ast_dns_query some_query;
	struct ast_dns_result *result;
	
	struct dns_result {
		unsigned int secure;
		unsigned int bogus;
		unsigned int rcode;
	} results[] = {
		{ 0, 0, ns_r_noerror },
		{ 0, 1, ns_r_noerror },
		{ 1, 0, ns_r_noerror },
		{ 0, 0, ns_r_nxdomain },
	};
	int i;
	enum ast_test_result_state res = AST_TEST_PASS;

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_set_result";
		info->category = "/main/dns/";
		info->summary = "Test setting and getting results on DNS queries";
		info->description =
			"This test performs the following:\n"
			"\t* Sets a result that is not secure, bogus, and has rcode 0\n"
			"\t* Sets a result that is not secure, has rcode 0, but is secure\n"
			"\t* Sets a result that is not bogus, has rcode 0, but is secure\n"
			"\t* Sets a result that is not secure or bogus, but has rcode NXDOMAIN\n"
			"After each result is set, we ensure that parameters retrieved from\n"
			"the result have the expected values.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	memset(&some_query, 0, sizeof(some_query));

	for (i = 0; i < ARRAY_LEN(results); ++i) {
		if (ast_dns_resolver_set_result(&some_query, results[i].secure, results[i].bogus,
				results[i].rcode, "asterisk.org")) {
			ast_test_status_update(test, "Unable to add DNS result to query\n");
			res = AST_TEST_FAIL;
		}

		if (test_results(test, &some_query, results[i].secure, results[i].bogus,
				results[i].rcode, "asterisk.org")) {
			res = AST_TEST_FAIL;
		}
	}

	/* The final result we set needs to be freed */
	result = ast_dns_query_get_result(&some_query);
	ast_dns_result_free(result);

	return res;
}

AST_TEST_DEFINE(resolver_set_result_off_nominal)
{
	struct ast_dns_query some_query;
	struct ast_dns_result *result;

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_set_result_off_nominal";
		info->category = "/main/dns/";
		info->summary = "Test setting off-nominal DNS results\n";
		info->description =
			"This test performs the following:\n"
			"\t* Attempt to add a DNS result that is both bogus and secure\n"
			"\t* Attempt to add a DNS result that has no canonical name\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	memset(&some_query, 0, sizeof(some_query));

	if (!ast_dns_resolver_set_result(&some_query, 1, 1, ns_r_noerror, "asterisk.org")) {
		ast_test_status_update(test, "Successfully added a result that was both secure and bogus\n");
		result = ast_dns_query_get_result(&some_query);
		ao2_cleanup(result);
		return AST_TEST_FAIL;
	}

	if (!ast_dns_resolver_set_result(&some_query, 0, 0, ns_r_noerror, NULL)) {
		ast_test_status_update(test, "Successfully added result with no canonical name\n");
		result = ast_dns_query_get_result(&some_query);
		ao2_cleanup(result);
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

static int test_record(struct ast_test *test, const struct ast_dns_record *record,
		int rr_type, int rr_class, int ttl, const char *data, const size_t size)
{
	if (ast_dns_record_get_rr_type(record) != rr_type) {
		ast_test_status_update(test, "Unexpected rr_type from DNS record\n");
		return -1;
	}

	if (ast_dns_record_get_rr_class(record) != rr_class) {
		ast_test_status_update(test, "Unexpected rr_class from DNS record\n");
		return -1;
	}

	if (ast_dns_record_get_ttl(record) != ttl) {
		ast_test_status_update(test, "Unexpected ttl from DNS record\n");
		return -1;
	}

	if (memcmp(ast_dns_record_get_data(record), data, size)) {
		ast_test_status_update(test, "Unexpected data in DNS record\n");
		return -1;
	}

	return 0;
}

AST_TEST_DEFINE(resolver_add_record)
{
	RAII_VAR(struct ast_dns_result *, result, NULL, ast_dns_result_free);
	struct ast_dns_query some_query;
	const struct ast_dns_record *record;

	static const char *V4 = "127.0.0.1";
	static const size_t V4_BUFSIZE = sizeof(struct in_addr);
	char v4_buf[V4_BUFSIZE];

	static const char *V6 = "::1";
	static const size_t V6_BUFSIZE = sizeof(struct in6_addr);
	char v6_buf[V6_BUFSIZE];

	struct dns_record_details {
		int type;
		int class;
		int ttl;
		const char *data;
		const size_t size;
		int visited;
	} records[] = {
		{ ns_t_a, ns_c_in, 12345, v4_buf, V4_BUFSIZE, 0, },
		{ ns_t_aaaa, ns_c_in, 12345, v6_buf, V6_BUFSIZE, 0, },
	};

	int num_records_visited = 0;

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_add_record";
		info->category = "/main/dns/";
		info->summary = "Test adding DNS records to a query";
		info->description =
			"This test performs the following:\n"
			"\t* Ensure a nominal A record can be added to a query result\n"
			"\t* Ensures that the record can be retrieved\n"
			"\t* Ensure that a second record can be added to the query result\n"
			"\t* Ensures that both records can be retrieved\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	memset(&some_query, 0, sizeof(some_query));

	if (ast_dns_resolver_set_result(&some_query, 0, 0, ns_r_noerror, "asterisk.org")) {
		ast_test_status_update(test, "Unable to set result for DNS query\n");
		return AST_TEST_FAIL;
	}

	result = ast_dns_query_get_result(&some_query);
	if (!result) {
		ast_test_status_update(test, "Unable to retrieve result from query\n");
		return AST_TEST_FAIL;
	}

	inet_pton(AF_INET, V4, v4_buf);

	/* Nominal Record */
	if (ast_dns_resolver_add_record(&some_query, records[0].type, records[0].class,
				records[0].ttl, records[0].data, records[0].size)) {
		ast_test_status_update(test, "Unable to add nominal record to query result\n");
		return AST_TEST_FAIL;
	}

	/* I should only be able to retrieve one record */
	record = ast_dns_result_get_records(result);
	if (!record) {
		ast_test_status_update(test, "Unable to retrieve record from result\n");
		return AST_TEST_FAIL;
	}

	if (test_record(test, record, records[0].type, records[0].class, records[0].ttl,
				records[0].data, records[0].size)) {
		return AST_TEST_FAIL;
	}

	if (ast_dns_record_get_next(record)) {
		ast_test_status_update(test, "Multiple records returned when only one was expected\n");
		return AST_TEST_FAIL;
	}

	inet_pton(AF_INET6, V6, v6_buf);

	if (ast_dns_resolver_add_record(&some_query, records[1].type, records[1].class,
				records[1].ttl, records[1].data, records[1].size)) {
		ast_test_status_update(test, "Unable to add second record to query result\n");
		return AST_TEST_FAIL;
	}

	for (record = ast_dns_result_get_records(result); record; record = ast_dns_record_get_next(record)) {
		/* The order of returned records is not specified. We use the record type as the discriminator
		 * to determine which record data to expect.
		 */
		int res;

		if (ast_dns_record_get_rr_type(record) == records[0].type) {
			res = test_record(test, record, records[0].type, records[0].class, records[0].ttl, records[0].data, records[0].size);
			records[0].visited = 1;
		} else if (ast_dns_record_get_rr_type(record) == records[1].type) {
			res = test_record(test, record, records[1].type, records[1].class, records[1].ttl, records[1].data, records[1].size);
			records[1].visited = 1;
		} else {
			ast_test_status_update(test, "Unknown record type found in DNS results\n");
			return AST_TEST_FAIL;
		}

		if (res) {
			return AST_TEST_FAIL;
		}
		
		++num_records_visited;
	}

	if (!records[0].visited || !records[1].visited) {
		ast_test_status_update(test, "Did not visit all added DNS records\n");
		return AST_TEST_FAIL;
	}

	if (num_records_visited != ARRAY_LEN(records)) {
		ast_test_status_update(test, "Did not visit the expected number of DNS records\n");
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(resolver_add_record_off_nominal)
{
	struct ast_dns_query some_query;
	static const char *V4 = "127.0.0.1";
	static const size_t V4_BUFSIZE = sizeof(struct in_addr);
	char v4_buf[V4_BUFSIZE];

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_add_record_off_nominal";
		info->category = "/main/dns/";
		info->summary = "Test adding off-nominal DNS records to a query";
		info->description =
			"This test performs the following:\n"
			"\t* Ensure a nominal A record cannot be added if no result has been set.\n"
			"\t* Ensure that an A record with invalid RR types cannot be added to a query\n"
			"\t* Ensure that an A record with invalid RR classes cannot be added to a query\n"
			"\t* Ensure that an A record with invalid TTL cannot be added to a query\n"
			"\t* Ensure that an A record with NULL data cannot be added to a query\n"
			"\t* Ensure that an A record with invalid length cannot be added to a query\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	memset(&some_query, 0, sizeof(some_query));

	inet_ntop(AF_INET, V4, v4_buf, V4_BUFSIZE);

	/* Add record before setting result */
	if (!ast_dns_resolver_add_record(&some_query, ns_t_a, ns_c_in, 12345, v4_buf, V4_BUFSIZE)) {
		ast_test_status_update(test, "Successfully added DNS record to query before setting a result\n");
		return AST_TEST_FAIL;
	}

	if (ast_dns_resolver_set_result(&some_query, 0, 0, ns_r_noerror, "asterisk.org")) {
		ast_test_status_update(test, "Unable to set result for DNS query\n");
		return AST_TEST_FAIL;
	}

	/* Invalid RR types */
	if (!ast_dns_resolver_add_record(&some_query, -1, ns_c_in, 12345, v4_buf, V4_BUFSIZE)) {
		ast_test_status_update(test, "Successfully added DNS record with negative RR type\n");
		return AST_TEST_FAIL;
	}
	
	if (!ast_dns_resolver_add_record(&some_query, ns_t_max + 1, ns_c_in, 12345, v4_buf, V4_BUFSIZE)) {
		ast_test_status_update(test, "Successfully added DNS record with too large RR type\n");
		return AST_TEST_FAIL;
	}

	/* Invalid RR classes */
	if (!ast_dns_resolver_add_record(&some_query, ns_t_a, -1, 12345, v4_buf, V4_BUFSIZE)) {
		ast_test_status_update(test, "Successfully added DNS record with negative RR class\n");
		return AST_TEST_FAIL;
	}

	if (!ast_dns_resolver_add_record(&some_query, ns_t_a, ns_c_max + 1, 12345, v4_buf, V4_BUFSIZE)) {
		ast_test_status_update(test, "Successfully added DNS record with too large RR class\n");
		return AST_TEST_FAIL;
	}

	/* Invalid TTL */
	if (!ast_dns_resolver_add_record(&some_query, ns_t_a, ns_c_in, -1, v4_buf, V4_BUFSIZE)) {
		ast_test_status_update(test, "Successfully added DNS record with negative TTL\n");
		return AST_TEST_FAIL;
	}

	/* No data */
	if (!ast_dns_resolver_add_record(&some_query, ns_t_a, ns_c_in, 12345, NULL, 0)) {
		ast_test_status_update(test, "Successfully added a DNS record with no data\n");
		return AST_TEST_FAIL;
	}

	/* Lie about the length */
	if (!ast_dns_resolver_add_record(&some_query, ns_t_a, ns_c_in, 12345, v4_buf, 0)) {
		ast_test_status_update(test, "Successfully added a DNS record with length zero\n");
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

static struct resolver_data {
	int resolve_called;
	int canceled;
	int resolution_complete;
	ast_mutex_t lock;
	ast_cond_t cancel_cond;
} test_resolver_data;

static void *resolution_thread(void *dns_query)
{
	struct ast_dns_query *query = dns_query;
	struct timespec timeout;

	static const char *V4 = "127.0.0.1";
	static const size_t V4_BUFSIZE = sizeof(struct in_addr);
	char v4_buf[V4_BUFSIZE];

	clock_gettime(CLOCK_REALTIME, &timeout);
	timeout.tv_sec += 5;

	ast_mutex_lock(&test_resolver_data.lock);
	while (!test_resolver_data.canceled) {
		if (ast_cond_timedwait(&test_resolver_data.cancel_cond, &test_resolver_data.lock, &timeout) == ETIMEDOUT) {
			break;
		}
	}
	ast_mutex_unlock(&test_resolver_data.lock);
	
	if (test_resolver_data.canceled) {
		ast_dns_resolver_completed(query);
		ao2_ref(query, -1);
		return NULL;
	}

	ast_dns_resolver_set_result(query, 0, 0, ns_r_noerror, "asterisk.org");

	inet_pton(AF_INET, V4, v4_buf);
	ast_dns_resolver_add_record(query, ns_t_a, ns_c_in, 12345, v4_buf, V4_BUFSIZE);
	
	test_resolver_data.resolution_complete = 1;
	ast_dns_resolver_completed(query);

	ao2_ref(query, -1);
	return NULL;
}

static int test_resolve(struct ast_dns_query *query)
{
	pthread_t resolver_thread;

	test_resolver_data.resolve_called = 1;
	return ast_pthread_create_detached(&resolver_thread, NULL, resolution_thread, ao2_bump(query));
}

static int test_cancel(struct ast_dns_query *query)
{
	ast_mutex_lock(&test_resolver_data.lock);
	test_resolver_data.canceled = 1;
	ast_cond_signal(&test_resolver_data.cancel_cond);
	ast_mutex_unlock(&test_resolver_data.lock);

	return 0;
}

static void resolver_data_init(void)
{
	test_resolver_data.resolve_called = 0;
	test_resolver_data.canceled = 0;
	test_resolver_data.resolution_complete = 0;

	ast_mutex_init(&test_resolver_data.lock);
	ast_cond_init(&test_resolver_data.cancel_cond, NULL);
}

static void resolver_data_cleanup(void)
{
	ast_mutex_destroy(&test_resolver_data.lock);
	ast_cond_destroy(&test_resolver_data.cancel_cond);
}

static struct ast_dns_resolver test_resolver = {
	.name = "test",
	.priority = 0,
	.resolve = test_resolve,
	.cancel = test_cancel,
};

AST_TEST_DEFINE(resolver_resolve_sync)
{
	RAII_VAR(struct ast_dns_result *, result, NULL, ast_dns_result_free);
	enum ast_test_result_state res = AST_TEST_PASS;

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_resolve_sync";
		info->category = "/main/dns/";
		info->summary = "Test a nominal synchronous DNS resolution";
		info->description =
			"This test performs a synchronous DNS resolution of a domain. The goal of this\n"
			"test is not to check the records for accuracy. Rather, the goal is to ensure that\n"
			"the resolver is called into as expected, that the query completes entirely before\n"
			"returning from the synchronous resolution, that nothing tried to cancel the resolution\n,"
			"and that some records were returned.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	if (ast_dns_resolver_register(&test_resolver)) {
		ast_test_status_update(test, "Unable to register test resolver\n");
		return AST_TEST_FAIL;
	}

	resolver_data_init();

	if (ast_dns_resolve("asterisk.org", ns_t_a, ns_c_in, &result)) {
		ast_test_status_update(test, "Resolution of address failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!result) {
		ast_test_status_update(test, "DNS resolution returned a NULL result\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!test_resolver_data.resolve_called) {
		ast_test_status_update(test, "DNS resolution did not call resolver's resolve() method\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (test_resolver_data.canceled) {
		ast_test_status_update(test, "Resolver's cancel() method called for no reason\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!test_resolver_data.resolution_complete) {
		ast_test_status_update(test, "Synchronous resolution completed early?\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!ast_dns_result_get_records(result)) {
		ast_test_status_update(test, "Synchronous resolution yielded no records.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

cleanup:
	ast_dns_resolver_unregister(&test_resolver);
	resolver_data_cleanup();
	return res;
}

struct async_resolution_data {
	int complete;
	ast_mutex_t lock;
	ast_cond_t cond;
};

static void async_data_destructor(void *obj)
{
	struct async_resolution_data *async_data = obj;

	ast_mutex_destroy(&async_data->lock);
	ast_cond_destroy(&async_data->cond);
}

static struct async_resolution_data *async_data_alloc(void)
{
	struct async_resolution_data *async_data;

	async_data = ao2_alloc(sizeof(*async_data), async_data_destructor);
	if (!async_data) {
		return NULL;
	}

	async_data->complete = 0;
	ast_mutex_init(&async_data->lock);
	ast_cond_init(&async_data->cond, NULL);

	return async_data;
}

static void async_callback(const struct ast_dns_query *query)
{
	struct async_resolution_data *async_data = ast_dns_query_get_data(query);

	ast_mutex_lock(&async_data->lock);
	async_data->complete = 1;
	ast_cond_signal(&async_data->cond);
	ast_mutex_unlock(&async_data->lock);
}

AST_TEST_DEFINE(resolver_resolve_async)
{
	RAII_VAR(struct async_resolution_data *, async_data, NULL, ao2_cleanup); 
	RAII_VAR(struct ast_dns_query *, query, NULL, ao2_cleanup);
	struct ast_dns_result *result;
	enum ast_test_result_state res = AST_TEST_PASS;
	struct timespec timeout;

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_resolve_async";
		info->category = "/main/dns/";
		info->summary = "Test a nominal asynchronous DNS resolution";
		info->description =
			"This test performs an asynchronous DNS resolution of a domain. The goal of this\n"
			"test is not to check the records for accuracy. Rather, the goal is to ensure that\n"
			"the resolver is called into as expected, that we regain control before the query\n"
			"is completed, and to ensure that nothing tried to cancel the resolution.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	if (ast_dns_resolver_register(&test_resolver)) {
		ast_test_status_update(test, "Unable to register test resolver\n");
		return AST_TEST_FAIL;
	}

	resolver_data_init();

	async_data = async_data_alloc();
	if (!async_data) {
		ast_test_status_update(test, "Failed to allocate asynchronous data\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	query = ast_dns_resolve_async("asterisk.org", ns_t_a, ns_c_in, async_callback, async_data);
	if (!query) {
		ast_test_status_update(test, "Asynchronous resolution of address failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!test_resolver_data.resolve_called) {
		ast_test_status_update(test, "DNS resolution did not call resolver's resolve() method\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (test_resolver_data.canceled) {
		ast_test_status_update(test, "Resolver's cancel() method called for no reason\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	clock_gettime(CLOCK_REALTIME, &timeout);
	timeout.tv_sec += 10;
	ast_mutex_lock(&async_data->lock);
	while (!async_data->complete) {
		if (ast_cond_timedwait(&async_data->cond, &async_data->lock, &timeout) == ETIMEDOUT) {
			break;
		}
	}
	ast_mutex_unlock(&async_data->lock);

	if (!async_data->complete) {
		ast_test_status_update(test, "Asynchronous resolution timed out\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!test_resolver_data.resolution_complete) {
		ast_test_status_update(test, "Asynchronous resolution completed early?\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	
	result = ast_dns_query_get_result(query);
	if (!result) {
		ast_test_status_update(test, "Asynchronous resolution yielded no result\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!ast_dns_result_get_records(result)) {
		ast_test_status_update(test, "Asynchronous result had no records\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

cleanup:
	ast_dns_resolver_unregister(&test_resolver);
	resolver_data_cleanup();
	return res;
}

AST_TEST_DEFINE(resolver_resolve_async_cancel)
{
	RAII_VAR(struct async_resolution_data *, async_data, NULL, ao2_cleanup); 
	RAII_VAR(struct ast_dns_query *, query, NULL, ao2_cleanup);
	struct ast_dns_result *result;
	enum ast_test_result_state res = AST_TEST_PASS;
	struct timespec timeout;

	switch (cmd) {
	case TEST_INIT:
		info->name = "resolver_resolve_async_cancel";
		info->category = "/main/dns/";
		info->summary = "Test canceling an asynchronous DNS resolution";
		info->description =
			"This test performs an asynchronous DNS resolution of a domain and then cancels\n"
			"the resolution. The goal of this test is to ensure that the cancel() callback of\n"
			"the resolver is called and that it properly interrupts the resolution such that no\n"
			"records are returned.\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	if (ast_dns_resolver_register(&test_resolver)) {
		ast_test_status_update(test, "Unable to register test resolver\n");
		return AST_TEST_FAIL;
	}

	resolver_data_init();

	async_data = async_data_alloc();
	if (!async_data) {
		ast_test_status_update(test, "Failed to allocate asynchronous data\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	query = ast_dns_resolve_async("asterisk.org", ns_t_a, ns_c_in, async_callback, async_data);
	if (!query) {
		ast_test_status_update(test, "Asynchronous resolution of address failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (!test_resolver_data.resolve_called) {
		ast_test_status_update(test, "DNS resolution did not call resolver's resolve() method\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (test_resolver_data.canceled) {
		ast_test_status_update(test, "Resolver's cancel() method called for no reason\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	ast_dns_resolve_cancel(query);

	if (!test_resolver_data.canceled) {
		ast_test_status_update(test, "Resolver's cancel() method was not called\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	clock_gettime(CLOCK_REALTIME, &timeout);
	timeout.tv_sec += 10;
	ast_mutex_lock(&async_data->lock);
	while (!async_data->complete) {
		if (ast_cond_timedwait(&async_data->cond, &async_data->lock, &timeout) == ETIMEDOUT) {
			break;
		}
	}
	ast_mutex_unlock(&async_data->lock);

	if (!async_data->complete) {
		ast_test_status_update(test, "Asynchronous resolution timed out\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	if (test_resolver_data.resolution_complete) {
		ast_test_status_update(test, "Resolution completed without cancelation\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	result = ast_dns_query_get_result(query);
	if (result) {
		ast_test_status_update(test, "Canceled resolution had a result\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

cleanup:
	ast_dns_resolver_unregister(&test_resolver);
	resolver_data_cleanup();
	return res;
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(resolver_register_unregister);
	AST_TEST_UNREGISTER(resolver_register_off_nominal);
	AST_TEST_UNREGISTER(resolver_unregister_off_nominal);
	AST_TEST_UNREGISTER(resolver_data);
	AST_TEST_UNREGISTER(resolver_set_result);
	AST_TEST_UNREGISTER(resolver_set_result_off_nominal);
	AST_TEST_UNREGISTER(resolver_add_record);
	AST_TEST_UNREGISTER(resolver_add_record_off_nominal);
	AST_TEST_UNREGISTER(resolver_resolve_sync);
	AST_TEST_UNREGISTER(resolver_resolve_async);
	AST_TEST_UNREGISTER(resolver_resolve_async_cancel);

	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(resolver_register_unregister);
	AST_TEST_REGISTER(resolver_register_off_nominal);
	AST_TEST_REGISTER(resolver_unregister_off_nominal);
	AST_TEST_REGISTER(resolver_data);
	AST_TEST_REGISTER(resolver_set_result);
	AST_TEST_REGISTER(resolver_set_result_off_nominal);
	AST_TEST_REGISTER(resolver_add_record);
	AST_TEST_REGISTER(resolver_add_record_off_nominal);
	AST_TEST_REGISTER(resolver_resolve_sync);
	AST_TEST_REGISTER(resolver_resolve_async);
	AST_TEST_REGISTER(resolver_resolve_async_cancel);

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "DNS API Tests");
