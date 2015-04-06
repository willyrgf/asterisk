/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2011-2015, Digium, Inc.
 *
 * Terry Wilson <twilson@digium.com>
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

/*!
 * \file
 * \brief AstDB Unit Tests
 *
 * \author Terry Wilson <twilson@digium.com>
 *
 */

/*** MODULEINFO
	<depend>TEST_FRAMEWORK</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "")

#include "asterisk/test.h"
#include "asterisk/module.h"
#include "asterisk/astdb.h"
#include "asterisk/logger.h"
#include "asterisk/stasis.h"

#define CATEGORY "/main/astdb/"

#define TEST_EID "ff:ff:ff:ff:ff:ff"

#define GLOBAL_SHARED_FAMILY "astdbtest_global"

#define UNIQUE_SHARED_FAMILY "astdbtest_unique"

enum {
	FAMILY = 0,
	KEY    = 1,
	VALUE  = 2,
};

/* Longest value we can support is 256 for family/key/ so, with
 * family = astdbtest and two slashes we are left with 244 bytes */
static const char long_val[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

struct consumer {
	ast_cond_t out;
	struct stasis_message **messages_rxed;
	size_t messages_rxed_len;
	int ignore_subscriptions;
	int complete;
};

static void consumer_dtor(void *obj)
{
	struct consumer *consumer = obj;

	ast_cond_destroy(&consumer->out);

	while (consumer->messages_rxed_len > 0) {
		ao2_cleanup(consumer->messages_rxed[--consumer->messages_rxed_len]);
	}
	ast_free(consumer->messages_rxed);
	consumer->messages_rxed = NULL;
}

static struct consumer *consumer_create(int ignore_subscriptions)
{
	struct consumer *consumer;

	consumer = ao2_alloc(sizeof(*consumer), consumer_dtor);
	if (!consumer) {
		return NULL;
	}

	consumer->ignore_subscriptions = ignore_subscriptions;
	consumer->messages_rxed = ast_malloc(sizeof(*consumer->messages_rxed));
	if (!consumer->messages_rxed) {
		ao2_cleanup(consumer);
		return NULL;
	}

	ast_cond_init(&consumer->out, NULL);

	return consumer;
}

static void consumer_exec(void *data, struct stasis_subscription *sub, struct stasis_message *message)
{
	struct consumer *consumer = data;
	RAII_VAR(struct consumer *, consumer_needs_cleanup, NULL, ao2_cleanup);
	SCOPED_AO2LOCK(lock, consumer);

	if (!consumer->ignore_subscriptions || stasis_message_type(message) != stasis_subscription_change_type()) {
		++consumer->messages_rxed_len;
		consumer->messages_rxed = ast_realloc(consumer->messages_rxed, sizeof(*consumer->messages_rxed) * consumer->messages_rxed_len);
		ast_assert(consumer->messages_rxed != NULL);
		consumer->messages_rxed[consumer->messages_rxed_len - 1] = message;
		ao2_ref(message, +1);
	}

	if (stasis_subscription_final_message(sub, message)) {
		consumer->complete = 1;
		consumer_needs_cleanup = consumer;
	}

	ast_cond_signal(&consumer->out);
}

static int consumer_wait_for(struct consumer *consumer, size_t expected_len)
{
	struct timeval start = ast_tvnow();
	struct timespec end = {
		.tv_sec = start.tv_sec + 30,
		.tv_nsec = start.tv_usec * 1000
	};

	SCOPED_AO2LOCK(lock, consumer);

	while (consumer->messages_rxed_len < expected_len) {
		int r = ast_cond_timedwait(&consumer->out, ao2_object_get_lockaddr(consumer), &end);

		if (r == ETIMEDOUT) {
			break;
		}
		ast_assert(r == 0); /* Not expecting any other types of errors */
	}
	return consumer->messages_rxed_len;
}

AST_TEST_DEFINE(put_get_del)
{
	int res = AST_TEST_PASS;
	const char *inputs[][3] = {
		{"family", "key", "value"},
		{"astdbtest", "a", "b"},
		{"astdbtest", "a", "a"},
		{"astdbtest", "b", "a"},
		{"astdbtest", "b", "b"},
		{"astdbtest", "b", "!@#$%^&*()|+-<>?"},
		{"astdbtest", long_val, "b"},
		{"astdbtest", "b", long_val},
		{"astdbtest", "!@#$%^&*()|+-<>?", "b"},
	};
	size_t x;
	char buf[sizeof(long_val)] = { 0, };

	switch (cmd) {
	case TEST_INIT:
		info->name = "put_get_del";
		info->category = CATEGORY;
		info->summary = "ast_db_(put|get|del) unit test";
		info->description =
			"Ensures that the ast_db put, get, and del functions work";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	for (x = 0; x < ARRAY_LEN(inputs); x++) {
		if (ast_db_put(inputs[x][FAMILY], inputs[x][KEY], inputs[x][VALUE])) {
			ast_test_status_update(test, "Failed to put %s : %s : %s\n", inputs[x][FAMILY], inputs[x][KEY], inputs[x][VALUE]);
			res = AST_TEST_FAIL;
		}
		if (ast_db_get(inputs[x][FAMILY], inputs[x][KEY], buf, sizeof(buf))) {
			ast_test_status_update(test, "Failed to get %s : %s : %s\n", inputs[x][FAMILY], inputs[x][KEY], inputs[x][VALUE]);
			res = AST_TEST_FAIL;
		} else if (strcmp(buf, inputs[x][VALUE])) {
			ast_test_status_update(test, "Failed to match key '%s/%s' value '%s' to '%s'\n", inputs[x][FAMILY], inputs[x][KEY], inputs[x][VALUE], buf);
			res = AST_TEST_FAIL;
		}
		if (ast_db_del(inputs[x][FAMILY], inputs[x][KEY])) {
			ast_test_status_update(test, "Failed to del %s : %s\n", inputs[x][FAMILY], inputs[x][KEY]);
			res = AST_TEST_FAIL;
		}
	}

	return res;
}

AST_TEST_DEFINE(gettree_deltree)
{
	int res = AST_TEST_PASS;
	const char *inputs[][3] = {
#define BASE "astdbtest"
#define SUB1 "one"
#define SUB2 "two"
#define FAM1 BASE "/" SUB1
#define FAM2 BASE "/" SUB2
		{FAM1, "one", "blah"},
		{FAM1, "two", "bling"},
		{FAM1, "three", "blast"},
		{FAM2, "one", "blah"},
		{FAM2, "two", "bling"},
		{FAM2, "three", "blast"},
	};
	size_t x;
	struct ast_db_entry *dbes, *cur;
	int num_deleted;

	switch (cmd) {
	case TEST_INIT:
		info->name = "gettree_deltree";
		info->category = CATEGORY;
		info->summary = "ast_db_(gettree|deltree) unit test";
		info->description =
			"Ensures that the ast_db gettree and deltree functions work";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	for (x = 0; x < ARRAY_LEN(inputs); x++) {
		if (ast_db_put(inputs[x][FAMILY], inputs[x][KEY], inputs[x][VALUE])) {
			ast_test_status_update(test, "Failed to put %s : %s : %s\n", inputs[x][FAMILY], inputs[x][KEY], inputs[x][VALUE]);
			res = AST_TEST_FAIL;
		}
	}

	if (!(dbes = ast_db_gettree(BASE, NULL))) {
		ast_test_status_update(test, "Failed to ast_db_gettree family %s\n", BASE);
		res = AST_TEST_FAIL;
	}

	for (cur = dbes, x = 0; cur; cur = cur->next, x++) {
		int found = 0;
		size_t z;
		for (z = 0; z < ARRAY_LEN(inputs); z++) {
			char buf[256];
			snprintf(buf, sizeof(buf), "/%s/%s", inputs[z][FAMILY], inputs[z][KEY]);
			if (!strcmp(buf, cur->key) && !strcmp(inputs[z][VALUE], cur->data)) {
				found = 1;
			}
		}
		if (!found) {
			ast_test_status_update(test, "inputs array has no entry for %s == %s\n", cur->key, cur->data);
			res = AST_TEST_FAIL;
		}
	}

	if (x != ARRAY_LEN(inputs)) {
		ast_test_status_update(test, "ast_db_gettree returned %zu entries when we expected %zu\n", x, ARRAY_LEN(inputs));
		res = AST_TEST_FAIL;
	}

	ast_db_freetree(dbes);

	if (!(dbes = ast_db_gettree(BASE, SUB1))) {
		ast_test_status_update(test, "Failed to ast_db_gettree for %s/%s\n", BASE, SUB1);
		res = AST_TEST_FAIL;
	}

	for (cur = dbes, x = 0; cur; cur = cur->next, x++) {
		int found = 0;
		size_t z;
		for (z = 0; z < ARRAY_LEN(inputs); z++) {
			char buf[256];
			snprintf(buf, sizeof(buf), "/%s/%s", inputs[z][FAMILY], inputs[z][KEY]);
			if (!strcmp(buf, cur->key) && !strcmp(inputs[z][VALUE], cur->data)) {
				found = 1;
			}
		}
		if (!found) {
			ast_test_status_update(test, "inputs array has no entry for %s == %s\n", cur->key, cur->data);
			res = AST_TEST_FAIL;
		}
	}

	if (x != (ARRAY_LEN(inputs) / 2)) {
		ast_test_status_update(test, "ast_db_gettree returned %zu entries when we expected %zu\n", x, ARRAY_LEN(inputs) / 2);
		res = AST_TEST_FAIL;
	}

	ast_db_freetree(dbes);

	if ((num_deleted = ast_db_deltree(BASE, SUB2)) != ARRAY_LEN(inputs) / 2) {
		ast_test_status_update(test, "Failed to deltree %s/%s, expected %zu deletions and got %d\n", BASE, SUB2, ARRAY_LEN(inputs) / 2, num_deleted);
		res = AST_TEST_FAIL;
	}

	if ((num_deleted = ast_db_deltree(BASE, NULL)) != ARRAY_LEN(inputs) / 2) {
		ast_test_status_update(test, "Failed to deltree %s, expected %zu deletions and got %d\n", BASE, ARRAY_LEN(inputs) / 2, num_deleted);
		res = AST_TEST_FAIL;
	}

	return res;
}

AST_TEST_DEFINE(perftest)
{
	int res = AST_TEST_PASS;
	size_t x;
	char buf[10];

	switch (cmd) {
	case TEST_INIT:
		info->name = "perftest";
		info->category = CATEGORY;
		info->summary = "astdb performance unit test";
		info->description =
			"Measure astdb performance";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	for (x = 0; x < 100000; x++) {
		sprintf(buf, "%zu", x);
		ast_db_put("astdbtest", buf, buf);
	}
	ast_db_deltree("astdbtest", NULL);

	return res;
}

AST_TEST_DEFINE(put_get_long)
{
	int res = AST_TEST_PASS;
	struct ast_str *s;
	int i, j;

#define STR_FILL_32 "abcdefghijklmnopqrstuvwxyz123456"

	switch (cmd) {
	case TEST_INIT:
		info->name = "put_get_long";
		info->category = CATEGORY;
		info->summary = "ast_db_(put|get_allocated) unit test";
		info->description =
			"Ensures that the ast_db_put and ast_db_get_allocated functions work";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	if (!(s = ast_str_create(4096))) {
		return AST_TEST_FAIL;
	}

	for (i = 1024; i <= 1024 * 1024 * 8; i *= 2) {
		char *out = NULL;

		ast_str_reset(s);

		for (j = 0; j < i; j += sizeof(STR_FILL_32) - 1) {
			ast_str_append(&s, 0, "%s", STR_FILL_32);
		}

		if (ast_db_put("astdbtest", "long", ast_str_buffer(s))) {
			ast_test_status_update(test, "Failed to put value of %zu bytes\n", ast_str_strlen(s));
			res = AST_TEST_FAIL;
		} else if (ast_db_get_allocated("astdbtest", "long", &out)) {
			ast_test_status_update(test, "Failed to get value of %zu bytes\n", ast_str_strlen(s));
			res = AST_TEST_FAIL;
		} else if (strcmp(ast_str_buffer(s), out)) {
			ast_test_status_update(test, "Failed to match value of %zu bytes\n", ast_str_strlen(s));
			res = AST_TEST_FAIL;
		} else if (ast_db_del("astdbtest", "long")) {
			ast_test_status_update(test, "Failed to delete astdbtest/long\n");
			res = AST_TEST_FAIL;
		}

		if (out) {
			ast_free(out);
		}
	}

	ast_free(s);

	return res;
}

/*!
 * \brief Test the AstDB for the given family, key, value tuple
 *
 * As annoying as it is, it's actually really hard to synchronize on when the
 * AstDB updates itself from the received publication of a shared family value.
 * This is because while we can synchronize on the delivery to a topic, we can't
 * synchronize that the AstDB handlers for that topic have written the value out.
 * Hence, we use this loop - if we don't get a value written within 1000 usec,
 * something is definitely wrong and we should just fail the unit test.
 */
#define TEST_FOR_VALUE(family, key, value) do { \
	int i; \
	for (i = 0; i < 10; i++) { \
		res = ast_db_get_allocated((family), (key), &(value)); \
		if ((value)) { \
			break; \
		} \
		usleep(100); \
	} \
	ast_test_validate(test, (value) != NULL); \
	ast_test_status_update(test, "Retrieved '%s' for '%s'\n", (value), (key)); \
} while (0)


AST_TEST_DEFINE(test_ast_db_put_shared_create)
{
	RAII_VAR(const char *, global_family, GLOBAL_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, unique_family, UNIQUE_SHARED_FAMILY, ast_db_del_shared);
	int res;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = CATEGORY;
		info->summary = "Test basic creation of a shared family";
		info->description =
			"Verifies that a family can be shared, and shared only once";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	res = ast_db_put_shared(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, res == 0, "Creating global shared area");
	res = ast_db_is_shared(GLOBAL_SHARED_FAMILY);
	ast_test_validate(test, res == 1, "Test existance of global shared area");
	res = ast_db_put_shared(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, res != 0, "Creating duplicate global shared area");
	res = ast_db_put_shared(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, res != 0, "Creating duplicate unique of global shared area");

	res = ast_db_put_shared(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, res == 0, "Creating unique shared area");
	res = ast_db_is_shared(UNIQUE_SHARED_FAMILY);
	ast_test_validate(test, res == 1, "Test existance of unique shared area");
	res = ast_db_put_shared(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, res != 0, "Creating duplicate unique shared area");
	res = ast_db_put_shared(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, res != 0, "Creating duplicate global of unique shared area");

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(test_ast_db_put_shared_delete)
{
	RAII_VAR(const char *, global_family, GLOBAL_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, unique_family, UNIQUE_SHARED_FAMILY, ast_db_del_shared);
	int res;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = CATEGORY;
		info->summary = "Test removal of a shared family";
		info->description =
			"Verifies that a shared family can be deleted\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	res = ast_db_put_shared(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, res == 0, "Creating global shared area");
	res = ast_db_del_shared(GLOBAL_SHARED_FAMILY);
	ast_test_validate(test, res == 0, "Deletion of global shared area");
	res = ast_db_is_shared(GLOBAL_SHARED_FAMILY);
	ast_test_validate(test, res == 0, "Test absence of global shared area");
	res = ast_db_del_shared(GLOBAL_SHARED_FAMILY);
	ast_test_validate(test, res != 0, "Allowed duplicate deletion of global shared area");

	res = ast_db_put_shared(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, res == 0, "Creating unique shared area");
	res = ast_db_del_shared(UNIQUE_SHARED_FAMILY);
	ast_test_validate(test, res == 0, "Deletion of unique shared area");
	res = ast_db_is_shared(UNIQUE_SHARED_FAMILY);
	ast_test_validate(test, res == 0, "Test absence of unique shared area");
	res = ast_db_del_shared(UNIQUE_SHARED_FAMILY);
	ast_test_validate(test, res != 0, "Allowed duplicate deletion of unique shared area");

	return AST_TEST_PASS;
}

static void tree_cleanup(const char *name)
{
	ast_db_deltree(name, "");
}

AST_TEST_DEFINE(test_ast_db_put_shared_unique)
{
	RAII_VAR(const char *, unique_family, UNIQUE_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, tree_family, UNIQUE_SHARED_FAMILY, tree_cleanup);
	RAII_VAR(struct consumer *, consumer, NULL, ao2_cleanup);
	RAII_VAR(struct stasis_subscription *, uut, NULL, stasis_unsubscribe);
	int res;
	int actual_len;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = CATEGORY;
		info->summary = "Test publication of a unique shared area";
		info->description =
			"Verifies that a unique shared family is published and not\n"
			"updated locally\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	consumer = consumer_create(1);
	ast_test_validate(test, NULL != consumer);

	uut = stasis_subscribe(ast_db_cluster_topic(), consumer_exec, consumer);
	ast_test_validate(test, NULL != uut);
	ao2_ref(consumer, +1);

	/* Create a key that is not published due to not being shared yet */
	res = ast_db_put(UNIQUE_SHARED_FAMILY, "foo", "bar");
	ast_test_validate(test, res == 0, "Creation of non-published test key");
	res = ast_db_put_shared(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, res == 0, "Creation of unique shared area");

	/* Publish a new key */
	res = ast_db_put(UNIQUE_SHARED_FAMILY, "foobar", "awesome");
	ast_test_validate(test, res == 0, "Creation of shared key foobar");

	/* Update the old key */
	res = ast_db_put(UNIQUE_SHARED_FAMILY, "foo", "awesome-bar");
	ast_test_validate(test, res == 0, "Update of shared key foo");

	/* Verify that we got two messages */
	actual_len = consumer_wait_for(consumer, 2);
	ast_test_status_update(test, "Got %d messages\n", actual_len);
	ast_test_validate(test, actual_len == 2);

	ast_test_validate(test, stasis_message_type(consumer->messages_rxed[0]) == ast_db_put_shared_type());
	ast_test_validate(test, stasis_message_type(consumer->messages_rxed[1]) == ast_db_put_shared_type());

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(test_ast_db_put_shared_global)
{
	RAII_VAR(const char *, global_family, GLOBAL_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, tree_family, GLOBAL_SHARED_FAMILY, tree_cleanup);
	RAII_VAR(struct consumer *, consumer, NULL, ao2_cleanup);
	RAII_VAR(struct stasis_subscription *, uut, NULL, stasis_unsubscribe);
	int res;
	int actual_len;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = CATEGORY;
		info->summary = "Test publication of a global shared area";
		info->description =
			"Verifies that a global shared family is published and not\n"
			"updated locally\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	consumer = consumer_create(1);
	ast_test_validate(test, NULL != consumer);

	uut = stasis_subscribe(ast_db_cluster_topic(), consumer_exec, consumer);
	ast_test_validate(test, NULL != uut);
	ao2_ref(consumer, +1);

	/* Create a key that is not published due to not being shared yet */
	res = ast_db_put(GLOBAL_SHARED_FAMILY, "foo", "bar");
	ast_test_validate(test, res == 0, "Creation of non-published test key");
	res = ast_db_put_shared(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, res == 0, "Creation of global shared area");

	/* Publish a new key */
	res = ast_db_put(GLOBAL_SHARED_FAMILY, "foobar", "awesome");
	ast_test_validate(test, res == 0, "Creation of shared key foobar");

	/* Update the old key */
	res = ast_db_put(GLOBAL_SHARED_FAMILY, "foo", "awesome-bar");
	ast_test_validate(test, res == 0, "Update of shared key foo");

	/* Verify that we got two messages */
	actual_len = consumer_wait_for(consumer, 2);
	ast_test_status_update(test, "Got %d messages\n", actual_len);
	ast_test_validate(test, actual_len == 2);

	ast_test_validate(test, stasis_message_type(consumer->messages_rxed[0]) == ast_db_put_shared_type());
	ast_test_validate(test, stasis_message_type(consumer->messages_rxed[1]) == ast_db_put_shared_type());

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(test_ast_db_put_shared_unique_update)
{
	RAII_VAR(const char *, unique_family, UNIQUE_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, tree_family, "astdbtest_unique", tree_cleanup);
	RAII_VAR(const char *, eid_tree_family, TEST_EID, tree_cleanup);
	RAII_VAR(struct ast_db_shared_family *, shared_family, NULL, ao2_cleanup);
	RAII_VAR(char *, value, NULL, ast_free);
	char eid_family[256];
	struct ast_eid eid;
	int res;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = CATEGORY;
		info->summary = "Test updating of a unique shared area";
		info->description =
			"Verifies that a unique shared family is updated when an\n"
			"external system publishes an update\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_validate(test, ast_str_to_eid(&eid, TEST_EID) == 0);
	snprintf(eid_family, sizeof(eid_family), "%s/%s", TEST_EID, UNIQUE_SHARED_FAMILY);

	ast_test_status_update(test, "Verifying unique shared area can be updated\n");

	shared_family = ast_db_shared_family_alloc(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, shared_family != NULL);
	shared_family->entries = ast_db_entry_create("foo", "bar");
	ast_test_validate(test, shared_family->entries != NULL);

	res = ast_db_put_shared(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, res == 0, "Creation of unique shared area");

	ast_db_publish_shared_message(ast_db_put_shared_type(), shared_family, &eid);

	TEST_FOR_VALUE(eid_family, "foo", value);
	ast_test_validate(test, strcmp(value, "bar") == 0);
	ast_free(value);
	value = NULL;

	res = ast_db_del_shared(UNIQUE_SHARED_FAMILY);
	ast_test_validate(test, res == 0, "Removal of unique shared area");

	/* Destroy the current message */
	ao2_ref(shared_family, -1);

	ast_test_status_update(test, "Verifying unique non-shared area is not updated\n");
	shared_family = ast_db_shared_family_alloc(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, shared_family != NULL);
	shared_family->entries = ast_db_entry_create("foo", "yackity");
	ast_test_validate(test, shared_family->entries != NULL);

	ast_db_publish_shared_message(ast_db_put_shared_type(), shared_family, &eid);

	/* Make sure we didn't update the value */
	TEST_FOR_VALUE(eid_family, "foo", value);
	ast_test_validate(test, strcmp(value, "bar") == 0);

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(test_ast_db_put_shared_global_update)
{
	RAII_VAR(const char *, global_family, GLOBAL_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, tree_family, GLOBAL_SHARED_FAMILY, tree_cleanup);
	RAII_VAR(struct ast_db_shared_family *, shared_family, NULL, ao2_cleanup);
	RAII_VAR(char *, value, NULL, ast_free);
	struct ast_eid eid;
	int res;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = CATEGORY;
		info->summary = "Test updating of a global shared area";
		info->description =
			"Verifies that a global shared family is updated when an\n"
			"external system publishes an update\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_validate(test, ast_str_to_eid(&eid, TEST_EID) == 0);

	ast_test_status_update(test, "Verifying global shared area can be updated\n");

	shared_family = ast_db_shared_family_alloc(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, shared_family != NULL);
	shared_family->entries = ast_db_entry_create("foo", "bar");
	ast_test_validate(test, shared_family->entries != NULL);

	res = ast_db_put_shared(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, res == 0, "Creation of global shared area");

	ast_db_publish_shared_message(ast_db_put_shared_type(), shared_family, &eid);

	TEST_FOR_VALUE(GLOBAL_SHARED_FAMILY, "foo", value);
	ast_test_validate(test, strcmp(value, "bar") == 0);
	ast_free(value);
	value = NULL;

	res = ast_db_del_shared(GLOBAL_SHARED_FAMILY);
	ast_test_validate(test, res == 0, "Removal of global shared area");

	/* Destroy the current message */
	ao2_ref(shared_family, -1);

	ast_test_status_update(test, "Verifying global non-shared area is not updated\n");
	shared_family = ast_db_shared_family_alloc(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, shared_family != NULL);
	shared_family->entries = ast_db_entry_create("foo", "yackity");
	ast_test_validate(test, shared_family->entries != NULL);

	ast_db_publish_shared_message(ast_db_put_shared_type(), shared_family, &eid);

	/* Make sure we didn't update the value */
	TEST_FOR_VALUE(GLOBAL_SHARED_FAMILY, "foo", value);
	ast_test_validate(test, strcmp(value, "bar") == 0);

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(test_ast_db_refresh_shared)
{
	RAII_VAR(struct consumer *, consumer, NULL, ao2_cleanup);
	RAII_VAR(struct stasis_subscription *, uut, NULL, stasis_unsubscribe);
	RAII_VAR(const char *, global_family, GLOBAL_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, global_tree_family, GLOBAL_SHARED_FAMILY, tree_cleanup);
	RAII_VAR(const char *, unique_family, UNIQUE_SHARED_FAMILY, ast_db_del_shared);
	RAII_VAR(const char *, unique_tree_family, UNIQUE_SHARED_FAMILY, tree_cleanup);
	int res;
	int actual_len;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = CATEGORY;
		info->summary = "Test refresh of existing shared families";
		info->description =
			"Verifies that all existing shared families can be published\n"
			"over the Stasis message bus.\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	res = ast_db_put_shared(GLOBAL_SHARED_FAMILY, DB_SHARE_TYPE_GLOBAL);
	ast_test_validate(test, res == 0, "Creation of global shared area");

	res = ast_db_put_shared(UNIQUE_SHARED_FAMILY, DB_SHARE_TYPE_UNIQUE);
	ast_test_validate(test, res == 0, "Creation of unique shared area");

	ast_test_validate(test, ast_db_put(GLOBAL_SHARED_FAMILY, "foo", "foo_key") == 0);
	ast_test_validate(test, ast_db_put(GLOBAL_SHARED_FAMILY, "bar", "bar_key") == 0);
	ast_test_validate(test, ast_db_put(UNIQUE_SHARED_FAMILY, "foo", "unique") == 0);

	consumer = consumer_create(1);
	ast_test_validate(test, NULL != consumer);

	uut = stasis_subscribe(ast_db_cluster_topic(), consumer_exec, consumer);
	ast_test_validate(test, NULL != uut);
	ao2_ref(consumer, +1);

	ast_db_refresh_shared();

	/* Verify that we got two messages */
	actual_len = consumer_wait_for(consumer, 2);
	ast_test_status_update(test, "Got %d messages\n", actual_len);
	ast_test_validate(test, actual_len == 2);

	ast_test_validate(test, stasis_message_type(consumer->messages_rxed[0]) == ast_db_put_shared_type());
	ast_test_validate(test, stasis_message_type(consumer->messages_rxed[1]) == ast_db_put_shared_type());

	return AST_TEST_PASS;
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(put_get_del);
	AST_TEST_UNREGISTER(gettree_deltree);
	AST_TEST_UNREGISTER(perftest);
	AST_TEST_UNREGISTER(put_get_long);

	AST_TEST_UNREGISTER(test_ast_db_put_shared_create);
	AST_TEST_UNREGISTER(test_ast_db_put_shared_delete);
	AST_TEST_UNREGISTER(test_ast_db_put_shared_unique);
	AST_TEST_UNREGISTER(test_ast_db_put_shared_global);
	AST_TEST_UNREGISTER(test_ast_db_put_shared_unique_update);
	AST_TEST_UNREGISTER(test_ast_db_put_shared_global_update);
	AST_TEST_UNREGISTER(test_ast_db_refresh_shared);

	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(put_get_del);
	AST_TEST_REGISTER(gettree_deltree);
	AST_TEST_REGISTER(perftest);
	AST_TEST_REGISTER(put_get_long);

	AST_TEST_REGISTER(test_ast_db_put_shared_create);
	AST_TEST_REGISTER(test_ast_db_put_shared_delete);
	AST_TEST_REGISTER(test_ast_db_put_shared_unique);
	AST_TEST_REGISTER(test_ast_db_put_shared_global);
	AST_TEST_REGISTER(test_ast_db_put_shared_unique_update);
	AST_TEST_REGISTER(test_ast_db_put_shared_global_update);
	AST_TEST_REGISTER(test_ast_db_refresh_shared);

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "AstDB test module");
