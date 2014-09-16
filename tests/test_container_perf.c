/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, Matt Jordan
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
 * \brief Relative container performance comparison
 *
 * \author\verbatim Matt Jordan <mjordan@digium.com> \endverbatim
 * 
 * This does some relative performance comparisons of common
 * Asterisk container types.
 * \ingroup tests
 */

/*** MODULEINFO
	<depend>TEST_FRAMEWORK</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <math.h>
#include "asterisk/utils.h"
#include "asterisk/module.h"
#include "asterisk/test.h"
#include "asterisk/astobj2.h"
#include "asterisk/linkedlists.h"
#include "asterisk/dlinkedlists.h"
#include "asterisk/vector.h"
#include "asterisk/strings.h"

struct test_item {
	int unique_id;
	AST_LIST_ENTRY(test_item) list;
	AST_DLLIST_ENTRY(test_item) dlist;
};

struct vector_wrapper {
	AST_VECTOR(, struct test_item *) vector;
};

struct linked_list_wrapper {
	AST_LIST_HEAD_NOLOCK(, test_item) linked_list;
};

struct dlinked_list_wrapper {
	AST_DLLIST_HEAD_NOLOCK(, test_item) dlinked_list;
};

static int hash_sizes[5] = { 11, 101, 1009, 10007, 100003, };
static int vector_sizes[5] = { 10, 100, 1000, 10000, 100000, };

struct result {
	char name[32];
	struct timeval elapsed_time;
};

static int test_item_hash_fn(const void *obj, const int flags)
{
	const struct test_item *item;
	int key;

	switch (flags & (OBJ_POINTER | OBJ_KEY | OBJ_PARTIAL_KEY)) {
	case OBJ_KEY:
		key = *(int *)obj;
		break;
	case OBJ_POINTER:
		item = obj;
		key = item->unique_id;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	return key;
}

static int test_item_cmp_fn(void *obj, void *arg, int flags)
{
	struct test_item *left = obj;
	struct test_item *right = arg;
	int right_key = *(int *)arg;
	int cmp;

	switch (flags & (OBJ_POINTER | OBJ_KEY | OBJ_PARTIAL_KEY)) {
	case OBJ_POINTER:
		right_key = right->unique_id;
		/* Fall through */
	case OBJ_KEY:
	case OBJ_PARTIAL_KEY:
	default:
		cmp = (left->unique_id == right_key);
	break;
	}
	return cmp ? (CMP_MATCH | CMP_STOP) : 0;
}

static int test_item_sort_fn(const void *obj, const void *arg, int flags)
{
	const struct test_item *left = obj;
	const struct test_item *right = arg;
	int right_key = *(int *)arg;
	int cmp;

	switch (flags & (OBJ_POINTER | OBJ_KEY | OBJ_PARTIAL_KEY)) {
	case OBJ_POINTER:
		right_key = right->unique_id;
		/* Fall through */
	case OBJ_KEY:
	case OBJ_PARTIAL_KEY:
	default:
		if (left->unique_id < right_key) {
			cmp = -1;
		} else if (left->unique_id > right_key) {
			cmp = 1;
		} else {
			cmp = 0;
		}
	break;
	}
	return cmp;
}


static void destroy_item_array(struct test_item **item_array, size_t count)
{
	int i;

	for (i = 0; i < count; i++) {
		ao2_ref(item_array[i], -1);
	}
	ast_free(item_array);
}

static struct test_item **create_item_array(size_t count)
{
	struct test_item **alloc_array;
	int i;

	alloc_array = ast_calloc(count, sizeof(struct test_item *));
	if (!alloc_array) {
		return NULL;
	}

	for (i = 0; i < count; ++i) {
		struct test_item *item = ao2_alloc_options(sizeof(*item), NULL, AO2_ALLOC_OPT_LOCK_NOLOCK);
		if (!item) {
			destroy_item_array(alloc_array, i);
			return NULL;
		}
		item->unique_id = i;
		alloc_array[i] = item;
	}

	return alloc_array;
}

static void insert_vector_cb(void *container, struct test_item *item)
{
	struct vector_wrapper *wrapper = container;

	AST_VECTOR_APPEND(&wrapper->vector, item);
}

static void insert_list_cb(void *container, struct test_item *item)
{
	struct linked_list_wrapper *wrapper = container;

	AST_LIST_INSERT_TAIL(&wrapper->linked_list, item, list);
}

static void insert_dlist_cb(void *container, struct test_item *item)
{
	struct dlinked_list_wrapper *wrapper = container;

	AST_DLLIST_INSERT_TAIL(&wrapper->dlinked_list, item, dlist);
}


static void insert_ao2_cb(void *container, struct test_item *item)
{
	struct ao2_container *ao2_container = container;

	ao2_link_flags(ao2_container, item, OBJ_NOLOCK);
}

static struct timeval insert_items(void *container,
	void (* const insert_cb)(void *container, struct test_item *item),
	struct test_item **items,
	size_t count)
{
	struct timeval start;
	struct timeval stop;
	int i;

	start = ast_tvnow();
	for (i = 0; i < count; i++) {
		insert_cb(container, items[i]);
	}
	stop = ast_tvnow();

	return ast_tvsub(stop, start);
}

static void vector_insertion_test(void *obj, struct test_item **item_array, size_t elements, size_t container_size, struct result *result, int destroy)
{
	struct vector_wrapper *vec_wrapper = obj;

	snprintf(result->name, sizeof(result->name), "vector_%d", vector_sizes[container_size]);

	AST_VECTOR_INIT(&vec_wrapper->vector, vector_sizes[container_size]);
	result->elapsed_time = insert_items(vec_wrapper, insert_vector_cb, item_array, elements);
	if (destroy) {
		AST_VECTOR_FREE(&vec_wrapper->vector);
	}
}

static void ao2_hash_insertion_test(void *obj, struct test_item **item_array, size_t elements, size_t container_size, struct result *result, int destroy)
{
	struct ao2_container *container = obj;

	snprintf(result->name, sizeof(result->name), "ao2hash_%d", hash_sizes[container_size]);

	container = ao2_container_alloc_hash(OBJ_NOLOCK, 0, hash_sizes[container_size], test_item_hash_fn, test_item_sort_fn, test_item_cmp_fn);
	if (!container) {
		return;
	}
	result->elapsed_time = insert_items(container, insert_ao2_cb, item_array, elements);
	if (destroy) {
		ao2_ref(container, -1);
	}
}

static void ao2_list_insertion_test(void *obj, struct test_item **item_array, size_t elements, size_t container_size, struct result *result, int destroy)
{
	struct ao2_container *container = obj;

	snprintf(result->name, sizeof(result->name), "ao2list");

	container = ao2_container_alloc_list(OBJ_NOLOCK, 0, test_item_sort_fn, test_item_cmp_fn);
	if (!container) {
		return;
	}
	result->elapsed_time = insert_items(container, insert_ao2_cb, item_array, elements);
	if (destroy) {
		ao2_ref(container, -1);
	}
}

static void ao2_rb_insertion_test(void *obj, struct test_item **item_array, size_t elements, size_t container_size, struct result *result, int destroy)
{
	struct ao2_container *container = obj;

	snprintf(result->name, sizeof(result->name), "ao2rbtree");

	container = ao2_container_alloc_rbtree(OBJ_NOLOCK, 0, test_item_sort_fn, test_item_cmp_fn);
	if (!container) {
		return;
	}
	result->elapsed_time = insert_items(container, insert_ao2_cb, item_array, elements);
	if (destroy) {
		ao2_ref(container, -1);
	}
}

static void linked_list_insertion_test(void *obj, struct test_item **item_array, size_t elements, size_t container_size, struct result *result, int destroy)
{
	struct test_item *current;
	struct linked_list_wrapper *list_wrapper = obj;

	snprintf(result->name, sizeof(result->name), "llist");

	result->elapsed_time = insert_items(list_wrapper, insert_list_cb, item_array, elements);

	if (destroy) {
		while ((current = AST_LIST_REMOVE_HEAD(&list_wrapper->linked_list, list)));
	}
}

static void dlinked_list_insertion_test(void *obj, struct test_item **item_array, size_t elements, size_t container_size, struct result *result, int destroy)
{
	struct test_item *current;
	struct dlinked_list_wrapper *dlist_wrapper = obj;

	snprintf(result->name, sizeof(result->name), "dlist");

	result->elapsed_time = insert_items(dlist_wrapper, insert_dlist_cb, item_array, elements);

	if (destroy) {
		while ((current = AST_DLLIST_REMOVE_HEAD(&dlist_wrapper->dlinked_list, dlist)));
	}
}


AST_TEST_DEFINE(test_container_insertion)
{
	struct ao2_container *ao2_container = NULL;
	struct dlinked_list_wrapper dlist_wrapper = { .dlinked_list = AST_DLLIST_HEAD_NOLOCK_INIT_VALUE, };
	struct linked_list_wrapper list_wrapper = { .linked_list = AST_LIST_HEAD_NOLOCK_INIT_VALUE, };
	struct vector_wrapper vec_wrapper;
	size_t elements = 100000;
	struct test_item **item_array;
	int i, j, k;
	RAII_VAR(struct ast_str *, output, ast_str_create(1024), ast_free);
	struct {
		int subtest;
		void *container;
		void (* const test_fn)(void *obj, struct test_item **item_array, size_t elements, size_t container, struct result *result, int destroy);
	} tests[6] = {	{ .container = &vec_wrapper, .test_fn = vector_insertion_test, .subtest = 1, },
					{ .container = &list_wrapper, .test_fn = linked_list_insertion_test, },
					{ .container = &dlist_wrapper, .test_fn = dlinked_list_insertion_test, },
					{ .container = ao2_container, .test_fn = ao2_hash_insertion_test, .subtest = 1, },
					{ .container = ao2_container, .test_fn = ao2_list_insertion_test, },
					{ .container = ao2_container, .test_fn = ao2_rb_insertion_test, }, };

	struct result results[6][5][5];
	memset(results, 0, sizeof(results));

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = "/perf/container";
		info->summary = "Test insertion performance";
		info->description =
			"This tests insertion with a variable number of elements\n"
			"for a variety of containers/sizes";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	item_array = create_item_array(elements);
	if (!item_array) {
		return AST_TEST_FAIL;
	}

	ast_test_status_update(test, "Starting insertion test\n");
	for (i = 0; i < 6; i++) {
		for (j = 0; j < 5; j++) {
			size_t elements = (size_t)pow(10, (j + 1));
			for (k = 0; k < 5; k++) {
				if (!tests[i].subtest && k > 0) {
					break;
				}
				tests[i].test_fn(tests[i].container, item_array, elements, k, &results[i][j][k], 1);
				ast_test_status_update(test, "Tested %s with %zd elements\n", results[i][j][k].name, elements);
			}
		}
	}
	ast_test_status_update(test, "-- RESULTS --\n");
	ast_str_append(&output, 0, "\n%18.18s", " ");
	for (j = 0; j < 5; j++) {
		size_t elements = (size_t)pow(10, (j + 1));
		ast_str_append(&output, 0, "% 13zd", elements);
	}
	ast_str_append(&output, 0, "\n");
	ast_test_status_update(test, "\n");
	for (i = 0; i < 6; i++) {
		for (k = 0; k < 5; k++) {
			int skipped = 0;
			for (j = 0; j < 5; j++) {
				if (ast_tvzero(results[i][j][k].elapsed_time)) {
					skipped = 1;
					break;
				}
				if (j == 0 && (k == 0 || tests[i].subtest)) {
					ast_str_append(&output, 0, "%18.18s", results[i][j][k].name);
				}
				ast_str_append(&output, 0, "%6ld.%06ld", results[i][j][k].elapsed_time.tv_sec, results[i][j][k].elapsed_time.tv_usec);
			}
			if (!skipped) {
				ast_str_append(&output, 0, "\n");
			}
		}
	}
	ast_test_status_update(test, "%s\n", ast_str_buffer(output));
	destroy_item_array(item_array, elements);
	return AST_TEST_PASS;
}
/*
static void vector_dtor(void *obj)
{
	struct vector_wrapper *vec_wrapper = obj;

	AST_VECTOR_FREE(&vec_wrapper->vector);
}

static void linked_list_dtor(void *obj)
{
	struct test_item *current;
	struct linked_list_wrapper *list_wrapper = obj;

	while ((current = AST_LIST_REMOVE_HEAD(&list_wrapper->linked_list, list)));
}

static void dlinked_list_dtor(void *obj)
{
	struct test_item *current;
	struct dlinked_list_wrapper *dlist_wrapper = obj;

	while ((current = AST_DLLIST_REMOVE_HEAD(&dlist_wrapper->dlinked_list, dlist)));
}
*/
static void ao2_dtor(void *obj)
{
	struct ao2_container *container = obj;
	ao2_ref(container, -1);
}
/*
static void vector_lookup_test(void *obj, struct test_item **item_array, size_t elements, struct result *result)
{
	struct vector_wrapper *vec_wrapper = obj;
	struct test_item *item;
	int i, j;
	struct timeval start;
	struct timeval stop;
	int found = 0;

	start = ast_tvnow();
	for (i = 0; i < elements; i++) {
		for (j = 0; j < AST_VECTOR_SIZE(&vec_wrapper->vector); j++) {
			item = AST_VECTOR_GET(&vec_wrapper->vector, j);
			if (item_array[i]->unique_id == item->unique_id) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ast_assert(0);
		}
		found = 0;
	}
	stop = ast_tvnow();

	result->elapsed_time = ast_tvsub(start, stop);
}

static void linked_list_lookup_test(void *obj, struct test_item **item_array, size_t elements, struct result *result)
{
	struct linked_list_wrapper *list_wrapper = obj;
	struct test_item *item;
	int i;
	struct timeval start;
	struct timeval stop;
	int found = 0;

	start = ast_tvnow();
	for (i = 0; i < elements; i++) {
		AST_LIST_TRAVERSE(&list_wrapper->linked_list, item, list) {
			if (item_array[i]->unique_id == item->unique_id) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ast_assert(0);
		}
		found = 0;
	}
	stop = ast_tvnow();

	result->elapsed_time = ast_tvsub(start, stop);
}

static void dlinked_list_lookup_test(void *obj, struct test_item **item_array, size_t elements, struct result *result)
{
	struct dlinked_list_wrapper *dlist_wrapper = obj;
	struct test_item *item;
	int i;
	struct timeval start;
	struct timeval stop;
	int found = 0;

	start = ast_tvnow();
	for (i = 0; i < elements; i++) {
		AST_DLLIST_TRAVERSE(&dlist_wrapper->dlinked_list, item, dlist) {
			if (item_array[i]->unique_id == item->unique_id) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ast_assert(0);
		}
		found = 0;
	}
	stop = ast_tvnow();

	result->elapsed_time = ast_tvsub(start, stop);
}*/

static void ao2_lookup_test(void *obj, struct test_item **item_array, size_t elements, struct result *result)
{
	struct ao2_container *container = obj;
	struct test_item *item;
	struct timeval start;
	struct timeval stop;
	int i;

	start = ast_tvnow();
	for (i = 0; i < elements; i++) {
		item = ao2_find(container, &item_array[i]->unique_id, OBJ_KEY | OBJ_NOLOCK);
		if (!item) {
			ast_assert(0);
		}
		ao2_ref(item, -1);
	}
	stop = ast_tvnow();

	result->elapsed_time = ast_tvsub(start, stop);
}

AST_TEST_DEFINE(test_container_lookup)
{
	struct ao2_container *ao2_container = NULL;
	/*struct dlinked_list_wrapper dlist_wrapper = { .dlinked_list = AST_DLLIST_HEAD_NOLOCK_INIT_VALUE, };
	struct linked_list_wrapper list_wrapper = { .linked_list = AST_LIST_HEAD_NOLOCK_INIT_VALUE, };
	struct vector_wrapper vec_wrapper;*/
	size_t elements = 100000;
	struct test_item **item_array;
	int i, j, k;
	RAII_VAR(struct ast_str *, output, ast_str_create(1024), ast_free);
	struct {
		int subtest;
		void *container;
		void (* const build_fn)(void *obj, struct test_item **item_array, size_t elements, size_t container, struct result *result, int destroy);
		void (* const test_fn)(void *obj, struct test_item **item_array, size_t elements, struct result *result);
		void (* const dtor_fn)(void *obj);
	} tests[3] = {	/*{ .container = &vec_wrapper, .build_fn = vector_insertion_test, .test_fn = vector_lookup_test, .dtor_fn = vector_dtor, .subtest = 1, },
					{ .container = &list_wrapper, .build_fn = linked_list_insertion_test, .test_fn = linked_list_lookup_test, .dtor_fn = linked_list_dtor, },
					{ .container = &dlist_wrapper, .build_fn = dlinked_list_insertion_test, .test_fn = dlinked_list_lookup_test, .dtor_fn = dlinked_list_dtor, },*/
					{ .container = &ao2_container, .build_fn = ao2_hash_insertion_test, .test_fn = ao2_lookup_test, .dtor_fn = ao2_dtor, .subtest = 1, },
					{ .container = &ao2_container, .build_fn = ao2_list_insertion_test, .test_fn = ao2_lookup_test, .dtor_fn = ao2_dtor, },
					{ .container = &ao2_container, .build_fn = ao2_rb_insertion_test, .test_fn = ao2_lookup_test, .dtor_fn = ao2_dtor,  }, };

	struct result results[6][5][5];
	memset(results, 0, sizeof(results));

	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = "/perf/container";
		info->summary = "Test lookup performance";
		info->description =
			"This tests item selection with a variable number of elements\n"
			"for a variety of containers/sizes";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	item_array = create_item_array(elements);
	if (!item_array) {
		return AST_TEST_FAIL;
	}

	ast_test_status_update(test, "Starting lookup test\n");
	for (i = 0; i < 3; i++) {
		for (j = 0; j < 5; j++) {
			size_t elements = (size_t)pow(10, (j + 1));
			for (k = 0; k < 5; k++) {
				if (!tests[i].subtest && k > 0) {
					break;
				}
				tests[i].build_fn(tests[i].container, item_array, elements, k, &results[i][j][k], 0);
				results[i][j][k].elapsed_time.tv_sec = 0;
				results[i][j][k].elapsed_time.tv_usec = 0;
				ast_test_status_update(test, "Container: %p\n", tests[i].container);
				tests[i].test_fn(tests[i].container, item_array, elements, &results[i][j][k]);
				ast_test_status_update(test, "Container: %p\n", tests[i].container);
				tests[i].dtor_fn(tests[i].container);
				ast_test_status_update(test, "Tested %s with %zd elements\n", results[i][j][k].name, elements);
			}
		}
	}
	ast_test_status_update(test, "-- RESULTS --\n");
	ast_str_append(&output, 0, "\n%18.18s", " ");
	for (j = 0; j < 5; j++) {
		size_t elements = (size_t)pow(10, (j + 1));
		ast_str_append(&output, 0, "% 13zd", elements);
	}
	ast_str_append(&output, 0, "\n");
	ast_test_status_update(test, "\n");
	for (i = 0; i < 6; i++) {
		for (k = 0; k < 5; k++) {
			int skipped = 0;
			for (j = 0; j < 5; j++) {
				if (ast_tvzero(results[i][j][k].elapsed_time)) {
					skipped = 1;
					break;
				}
				if (j == 0 && (k == 0 || tests[i].subtest)) {
					ast_str_append(&output, 0, "%18.18s", results[i][j][k].name);
				}
				ast_str_append(&output, 0, "%6ld.%06ld", results[i][j][k].elapsed_time.tv_sec, results[i][j][k].elapsed_time.tv_usec);
			}
			if (!skipped) {
				ast_str_append(&output, 0, "\n");
			}
		}
	}
	ast_test_status_update(test, "%s\n", ast_str_buffer(output));
	destroy_item_array(item_array, elements);
	return AST_TEST_PASS;
}



static int unload_module(void)
{
	AST_TEST_UNREGISTER(test_container_insertion);
	AST_TEST_UNREGISTER(test_container_lookup);
	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(test_container_insertion);
	AST_TEST_REGISTER(test_container_lookup);
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Skeleton (sample) Test");
