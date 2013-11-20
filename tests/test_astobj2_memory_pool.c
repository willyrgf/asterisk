/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Matt Jordan
 *
 * Matt Jordan <mjordan@digium.com>
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
 * \brief Test of astobj2 memory pools
 *
 * \author \verbatim Matt Jordan <mjordan@digium.com> \endverbatim
 * 
 * This is a set of unit tests for AstObj2 memory pools. Memory pools contain
 * reference counted objects, but those objects are not destroyed when their
 * reference count reaches 0. Instead, the object is reclaimed by the pool.
 */

/*** MODULEINFO
	<depend>TEST_FRAMEWORK</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/utils.h"
#include "asterisk/module.h"
#include "asterisk/test.h"
#include "asterisk/time.h"
#include "asterisk/stringfields.h"

#define TEST_CATEGORY "/main/astobj2/memory_pool/"

struct test_memory_pool_item {
	unsigned int used;
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(name);
	);
	struct test_memory_pool_item *embedded_ref;
};

static unsigned int global_init;
static unsigned int global_cleanup;

static void test_memory_pool_item_cleanup(void *obj)
{
	struct test_memory_pool_item *item = obj;

	if (item->embedded_ref) {
		ao2_ref(item->embedded_ref, -1);
		item->embedded_ref = NULL;
	}

	global_cleanup++;
}

static void test_memory_pool_item_dtor(void *obj)
{
	struct test_memory_pool_item *item = obj;

	item->used = 0;
	ast_string_field_free_memory(item);
	test_memory_pool_item_cleanup(obj);
}

static int test_memory_pool_item_init(void *new_obj)
{
	struct test_memory_pool_item *item = new_obj;

	item->used = 1;

	global_init++;
	return ast_string_field_init(item, 128);
}

static int test_memory_pool_item_bad_init(void *new_obj)
{
	return 1;
}

AST_TEST_DEFINE(test_memory_pool_overflow)
{
	RAII_VAR(struct ao2_memory_pool *, pool, NULL, ao2_cleanup);
	struct test_memory_pool_item *items[8];
	int i;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = TEST_CATEGORY;
		info->summary = "Test overflowing a memory pool with requests";
		info->description =
			"Runs a test that asks for a lot of objects without releasing\n"
			"them. This should automagically increase the size of the pool.\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	pool = ao2_memory_pool_alloc(1, sizeof(struct test_memory_pool_item),
		test_memory_pool_item_init,
		test_memory_pool_item_cleanup,
		test_memory_pool_item_dtor);
	if (!pool) {
		ast_test_status_update(test, "Failed to create pool\n");
		return AST_TEST_FAIL;
	}

	for (i = 0; i < 8; i++) {
		items[i] = ao2_memory_pool_request(pool);
		if (!items[i]) {
			ast_test_status_update(test, "Failed to request item %d for pool\n", i);
			return AST_TEST_FAIL;
		}
	}

	for (i = 0; i < 8; i++) {
		ao2_ref(items[i], -1);
	}
	ast_test_validate(test, ao2_ref(pool, 0) == 1);
	ao2_ref(pool, -1);
	pool = NULL;

	return AST_TEST_PASS;
}

static void *pool_thread_fn(void *obj)
{
	int i;
	struct ao2_memory_pool *pool = obj;
	struct test_memory_pool_item *item;

	for (i = 0; i < 250000; i++) {
		ao2_lock(pool);
		item = ao2_memory_pool_request(pool);
		ao2_unlock(pool);
		if (!item) {
			return NULL;
		}
		ao2_ref(item, -1);
	}
	return NULL;
}

static void *ao2_alloc_thread_fn(void *obj)
{
	int i;
	struct test_memory_pool_item *item;

	for (i = 0; i < 250000; i++) {
		item = ao2_alloc(sizeof(*item), test_memory_pool_item_dtor);
		if (!item) {
			return NULL;
		}
		test_memory_pool_item_init(item);
		ao2_ref(item, -1);
	}
	return NULL;
}

AST_TEST_DEFINE(test_memory_pool_thrash)
{
	RAII_VAR(struct ao2_memory_pool *, pool, NULL, ao2_cleanup);
	int i;
	struct timeval tvstart;
	struct timeval tvend;
	pthread_t thread_ids[4];

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = TEST_CATEGORY;
		info->summary = "Test thrashing on a memory pool";
		info->description =
			"Runs a test that spawns four threads that request items from a\n"
			"memory pool. The speed of this is compared against four threads\n"
			"that simply ao2_alloc the objects.\n";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	pool = ao2_memory_pool_alloc(2, sizeof(struct test_memory_pool_item),
		test_memory_pool_item_init,
		test_memory_pool_item_cleanup,
		test_memory_pool_item_dtor);
	if (!pool) {
		ast_test_status_update(test, "Failed to create pool\n");
		return AST_TEST_FAIL;
	}

	gettimeofday(&tvstart, NULL);
	for (i = 0; i < 4; i++) {
		ast_pthread_create(&thread_ids[i], NULL, pool_thread_fn, pool);
	}
	for (i = 0; i < 4; i++) {
		pthread_join(thread_ids[i], NULL);
		thread_ids[i] = -1;
	}
	gettimeofday(&tvend, NULL);
	ast_test_status_update(test, "Execution time of pool: %ld\n", ast_tvdiff_us(tvend, tvstart));

	gettimeofday(&tvstart, NULL);
	for (i = 0; i < 4; i++) {
		ast_pthread_create(&thread_ids[i], NULL, ao2_alloc_thread_fn, NULL);
	}
	for (i = 0; i < 4; i++) {
		pthread_join(thread_ids[i], NULL);
		thread_ids[i] = -1;
	}
	gettimeofday(&tvend, NULL);
	ast_test_status_update(test, "Execution time of ao2 alloc: %ld\n", ast_tvdiff_us(tvend, tvstart));

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(test_memory_pool_speed)
{
	RAII_VAR(struct ao2_memory_pool *, pool, NULL, ao2_cleanup);
	RAII_VAR(struct test_memory_pool_item *, pool_item, NULL, ao2_cleanup);
	RAII_VAR(struct test_memory_pool_item *, ao2_item, NULL, ao2_cleanup);
	int i;
	struct timeval tvstart;
	struct timeval tvend;

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = TEST_CATEGORY;
		info->summary = "Test how fast an individual item can be obtained";
		info->description =
			"Runs a test that simply asks for 1 million items from the pool,\n"
			"and allocates 1 million astobj2 items.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	pool = ao2_memory_pool_alloc(2, sizeof(struct test_memory_pool_item),
		test_memory_pool_item_init,
		test_memory_pool_item_cleanup,
		test_memory_pool_item_dtor);
	if (!pool) {
		ast_test_status_update(test, "Failed to create pool\n");
		return AST_TEST_FAIL;
	}

	gettimeofday(&tvstart, NULL);
	for (i = 0; i < 1000000; i++) {
		pool_item = ao2_memory_pool_request(pool);
		ao2_ref(pool_item, -1);
	}
	gettimeofday(&tvend, NULL);
	ast_test_status_update(test, "Execution time of pool: %ld\n", ast_tvdiff_us(tvend, tvstart));

	gettimeofday(&tvstart, NULL);
	for (i = 0; i < 1000000; i++) {
		ao2_item = ao2_alloc(sizeof(*ao2_item), test_memory_pool_item_dtor);
		test_memory_pool_item_init(ao2_item);
		ao2_ref(ao2_item, -1);
	}
	gettimeofday(&tvend, NULL);
	ast_test_status_update(test, "Execution time of ao2 alloc: %ld\n", ast_tvdiff_us(tvend, tvstart));

	ao2_ref(pool, -1);
	pool = NULL;
	pool_item = NULL;
	ao2_item = NULL;

	return AST_TEST_PASS;

}

AST_TEST_DEFINE(test_memory_pool_request)
{
	RAII_VAR(struct ao2_memory_pool *, pool, NULL, ao2_cleanup);
	RAII_VAR(struct test_memory_pool_item *, item_one, NULL, ao2_cleanup);
	RAII_VAR(struct test_memory_pool_item *, item_two, NULL, ao2_cleanup);
	RAII_VAR(struct test_memory_pool_item *, item_three, NULL, ao2_cleanup);
	RAII_VAR(struct test_memory_pool_item *, item_four, NULL, ao2_cleanup);

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = TEST_CATEGORY;
		info->summary = "Test requesting elements from a pool";
		info->description =
			"Test requesting elements from a pool without exhausing it.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	pool = ao2_memory_pool_alloc(2, sizeof(struct test_memory_pool_item),
		test_memory_pool_item_init,
		test_memory_pool_item_cleanup,
		test_memory_pool_item_dtor);
	if (!pool) {
		ast_test_status_update(test, "Failed to create pool\n");
		return AST_TEST_FAIL;
	}

	item_one = ao2_memory_pool_request(pool);
	if (!item_one) {
		ast_test_status_update(test, "Failed to request item one from pool\n");
		return AST_TEST_FAIL;
	}

	item_two = ao2_memory_pool_request(pool);
	if (!item_two) {
		ast_test_status_update(test, "Failed to request item two from pool\n");
		return AST_TEST_FAIL;
	}

	ao2_ref(item_one, -1);
	item_three = ao2_memory_pool_request(pool);
	if (!item_three) {
		ast_test_status_update(test, "Failed to request item three from pool\n");
		return AST_TEST_FAIL;
	}
	ast_test_validate(test, item_one == item_three);

	ao2_ref(item_two, -1);
	item_four = ao2_memory_pool_request(pool);
	if (!item_four) {
		ast_test_status_update(test, "Failed to request item four from pool\n");
		return AST_TEST_FAIL;
	}
	ast_test_validate(test, item_two == item_four);
	ast_test_validate(test, ao2_ref(pool, -1) == 3);
	pool = NULL;
	ao2_ref(item_one, -1);
	ao2_ref(item_two, -1);
	item_one = NULL;
	item_two = NULL;
	item_three = NULL;
	item_four = NULL;

	return AST_TEST_PASS;

}

AST_TEST_DEFINE(test_memory_pool_init_dtor)
{
	RAII_VAR(struct ao2_memory_pool *, pool, NULL, ao2_cleanup);

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = TEST_CATEGORY;
		info->summary = "Test initialization and destruction of a memory pool";
		info->description =
			"Test creating a memory pool and disposing of it. This verifies "
			"that an empty memory pool is managed correctly.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	/* Make a pool with nothing in it */
	pool = ao2_memory_pool_alloc(4, sizeof(struct test_memory_pool_item), NULL, NULL, NULL);
	ast_test_validate(test, ao2_ref(pool, 0) == 1);
	ast_test_validate(test, ao2_ref(pool, -1) == 1);

	pool = ao2_memory_pool_alloc(4, sizeof(struct test_memory_pool_item),
		test_memory_pool_item_init,
		test_memory_pool_item_cleanup,
		test_memory_pool_item_dtor);
	ast_test_validate(test, ao2_ref(pool, 0) == 1);
	ast_test_validate(test, global_init == 4);
	ast_test_validate(test, ao2_ref(pool, -1) == 1);
	ast_test_validate(test, global_cleanup == 4);

	pool = ao2_memory_pool_alloc(4, sizeof(struct test_memory_pool_item),
		test_memory_pool_item_bad_init,
		test_memory_pool_item_cleanup,
		test_memory_pool_item_dtor);
	ast_test_validate(test, pool == NULL);

	return AST_TEST_PASS;
}

/*!
 * \internal
 * \brief Callback function called before each test executes
 */
static int test_init_cb(struct ast_test_info *info, struct ast_test *test)
{
	global_init = 0;
	global_cleanup = 0;
	return 0;
}

/*!
 * \internal
 * \brief Callback function called after each test executes
 */
static int test_cleanup_cb(struct ast_test_info *info, struct ast_test *test)
{
	global_init = 0;
	global_cleanup = 0;
	return 0;
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(test_memory_pool_init_dtor);
	AST_TEST_UNREGISTER(test_memory_pool_request);
	AST_TEST_UNREGISTER(test_memory_pool_overflow);
	AST_TEST_UNREGISTER(test_memory_pool_speed);
	AST_TEST_UNREGISTER(test_memory_pool_thrash);

	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(test_memory_pool_init_dtor);
	AST_TEST_REGISTER(test_memory_pool_request);
	AST_TEST_REGISTER(test_memory_pool_overflow);
	AST_TEST_REGISTER(test_memory_pool_speed);
	AST_TEST_REGISTER(test_memory_pool_thrash);

	ast_test_register_init(TEST_CATEGORY, test_init_cb);
	ast_test_register_cleanup(TEST_CATEGORY, test_cleanup_cb);

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "AstObj2 Memory Pool Unit Tests");
