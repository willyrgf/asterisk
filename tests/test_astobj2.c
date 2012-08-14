/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2010, Digium, Inc.
 *
 * David Vossel <dvossel@digium.com>
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
 * \brief astobj2 test module
 *
 * \author David Vossel <dvossel@digium.com>
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
#include "asterisk/astobj2.h"

struct test_obj {
	/*! What to increment when object is destroyed. */
	int *destructor_count;
	/*! Container object key */
	int i;
};

/*! Partial search key +/- matching range. */
int partial_key_match_range;
/*! Special iax2 OBJ_CONTINUE test.  Bucket selected. */
int special_bucket;
/*! Special iax2 OBJ_CONTINUE test.  Object number select. */
int special_match;

static void test_obj_destructor(void *v_obj)
{
	struct test_obj *obj = (struct test_obj *) v_obj;

	--*obj->destructor_count;
}

static int increment_cb(void *obj, void *arg, int flag)
{
	int *i = (int *) arg;

	*i = *i + 1;
	return 0;
}

static int all_but_one_cb(void *obj, void *arg, int flag)
{
	struct test_obj *cmp_obj = (struct test_obj *) obj;

	return (cmp_obj->i) ? CMP_MATCH : 0;
}

static int multiple_cb(void *obj, void *arg, int flag)
{
	int *i = (int *) arg;
	struct test_obj *cmp_obj = (struct test_obj *) obj;

	return (cmp_obj->i < *i) ? CMP_MATCH : 0;
}

static int test_cmp_cb(void *obj, void *arg, int flags)
{
	struct test_obj *cmp_obj = (struct test_obj *) obj;

	if (flags & OBJ_KEY) {
		int *i = (int *) arg;

		return (cmp_obj->i == *i) ? CMP_MATCH : 0;
	} else if (flags & OBJ_PARTIAL_KEY) {
		int *i = (int *) arg;

		return (*i - partial_key_match_range <= cmp_obj->i
			&& cmp_obj->i <= *i + partial_key_match_range) ? CMP_MATCH : 0;
	} else {
		struct test_obj *arg_obj = (struct test_obj *) arg;

		if (!arg_obj) {
			/* Never match on the special iax2 OBJ_CONTINUE test. */
			return 0;
		}

		return (cmp_obj->i == arg_obj->i) ? CMP_MATCH : 0;
	}
}

static int test_hash_cb(const void *obj, const int flags)
{
	if (flags & OBJ_KEY) {
		const int *i = obj;

		return *i;
	} else if (flags & OBJ_PARTIAL_KEY) {
		/* This is absolutely wrong to be called with this flag value. */
		abort();
		/* Just in case abort() doesn't work or something else super silly */
		*((int *) 0) = 0;
		return 0;
	} else {
		const struct test_obj *hash_obj = obj;

		if (!hash_obj) {
			/*
			 * Use the special_bucket as the bucket for the special iax2
			 * OBJ_CONTINUE test.
			 */
			return special_bucket;
		}

		return hash_obj->i;
	}
}

static int test_sort_cb(const void *obj_left, const void *obj_right, int flags)
{
	const struct test_obj *test_left = obj_left;

	if (flags & OBJ_KEY) {
		const int *i = obj_right;

		return test_left->i - *i;
	} else if (flags & OBJ_PARTIAL_KEY) {
		int *i = (int *) obj_right;

		if (*i - partial_key_match_range <= test_left->i
			&& test_left->i <= *i + partial_key_match_range) {
			return 0;
		}

		return test_left->i - *i;
	} else {
		const struct test_obj *test_right = obj_right;

		if (!test_right) {
			/*
			 * Compare with special_match in the special iax2 OBJ_CONTINUE
			 * test.
			 */
			return test_left->i - special_match;
		}

		return test_left->i - test_right->i;
	}
}

static int astobj2_test_1_helper(int tst_num, int use_hash, int use_sort, int use_cmp, unsigned int lim, struct ast_test *test)
{
	struct ao2_container *c1;
	struct ao2_container *c2;
	struct ao2_container *c3 = NULL;
	struct ao2_iterator it;
	struct ao2_iterator *mult_it;
	struct test_obj *obj;
	struct test_obj *obj2;
	struct test_obj tmp_obj;
	int n_buckets;
	int increment = 0;
	int destructor_count = 0;
	int count;
	int num;
	int res = AST_TEST_PASS;

	ast_test_status_update(test, "Test %d, %s hash_cb, sorted %s, and %s cmp_cb.\n",
		tst_num,
		use_hash ? "custom" : "default",
		use_sort ? "yes" : "no",
		use_cmp ? "custom" : "default");

	/* Need at least 12 objects for the special iax2 OBJ_CONTINUE test. */
	if (lim < 12) {
		lim = 12;
	}

	if (use_hash) {
		n_buckets = (ast_random() % ((lim / 4) + 1)) + 1;
		if (n_buckets < 6) {
			/* Need at least 6 buckets for the special iax2 OBJ_CONTINUE test. */
			n_buckets = 6;
		}
	} else {
		/* Without a hash function, the container is just a linked list. */
		n_buckets = 1;
	}
	c1 = ao2_t_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, n_buckets,
		use_hash ? test_hash_cb : NULL,
		use_sort ? test_sort_cb : NULL,
		use_cmp ? test_cmp_cb : NULL,
		"test");
	c2 = ao2_t_container_alloc(1, NULL, NULL, "test");

	if (!c1 || !c2) {
		ast_test_status_update(test, "ao2_container_alloc failed.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	/* Create objects and link into container */
	destructor_count = lim;
	for (num = 0; num < lim; ++num) {
		if (!(obj = ao2_t_alloc(sizeof(struct test_obj), test_obj_destructor, "making zombies"))) {
			ast_test_status_update(test, "ao2_alloc failed.\n");
			res = AST_TEST_FAIL;
			goto cleanup;
		}
		obj->destructor_count = &destructor_count;
		obj->i = num;
		ao2_link(c1, obj);
		ao2_t_ref(obj, -1, "test");
		if (ao2_container_count(c1) != num + 1) {
			ast_test_status_update(test, "container did not link correctly\n");
			res = AST_TEST_FAIL;
		}
	}
	if (ao2_container_check(c1, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	ast_test_status_update(test, "Container created: buckets %d: items: %d\n", n_buckets, lim);

	/* Testing ao2_container_clone */
	c3 = ao2_container_clone(c1, 0);
	if (!c3) {
		ast_test_status_update(test, "ao2_container_clone failed.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	if (ao2_container_check(c3, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	if (ao2_container_count(c1) != ao2_container_count(c3)) {
		ast_test_status_update(test, "Cloned container does not have the same number of objects.\n");
		res = AST_TEST_FAIL;
	} else {
		it = ao2_iterator_init(c1, 0);
		for (; (obj = ao2_t_iterator_next(&it, "test orig")); ao2_t_ref(obj, -1, "test orig")) {
			/*
			 * Unlink the matching object from the cloned container to make
			 * the next search faster.  This is a big speed optimization!
			 */
			obj2 = ao2_t_callback(c3, OBJ_POINTER | OBJ_UNLINK, ao2_match_by_addr, obj,
				"test clone");
			if (obj2) {
				ao2_t_ref(obj2, -1, "test clone");
				continue;
			}
			ast_test_status_update(test,
				"Orig container has an object %p not in the clone container.\n", obj);
			res = AST_TEST_FAIL;
		}
		ao2_iterator_destroy(&it);
		if (ao2_container_count(c3)) {
			ast_test_status_update(test, "Cloned container still has objects.\n");
			res = AST_TEST_FAIL;
		}
		if (ao2_container_check(c3, 0)) {
			ast_test_status_update(test, "container integrity check failed\n");
			res = AST_TEST_FAIL;
		}
	}
	ao2_t_ref(c3, -1, "bye c3");
	c3 = NULL;

	/* Testing ao2_find with no flags */
	for (num = 100; num--;) {
		int i = ast_random() % lim; /* find a random object */

		tmp_obj.i = i;
		if (!(obj = ao2_find(c1, &tmp_obj, 0))) {
			res = AST_TEST_FAIL;
			ast_test_status_update(test, "COULD NOT FIND:%d, ao2_find() with no flags failed.\n", i);
		} else {
			/* a correct match will only take place when the custom cmp function is used */
			if (use_cmp && obj->i != i) {
				ast_test_status_update(test, "object %d does not match object %d\n", obj->i, tmp_obj.i);
				res = AST_TEST_FAIL;
			}
			ao2_t_ref(obj, -1, "test");
		}
	}

	/* Testing ao2_find with OBJ_POINTER */
	for (num = 75; num--;) {
		int i = ast_random() % lim; /* find a random object */

		tmp_obj.i = i;
		if (!(obj = ao2_find(c1, &tmp_obj, OBJ_POINTER))) {
			res = AST_TEST_FAIL;
			ast_test_status_update(test, "COULD NOT FIND:%d, ao2_find() with OBJ_POINTER flag failed.\n", i);
		} else {
			/* a correct match will only take place when the custom cmp function is used */
			if (use_cmp && obj->i != i) {
				ast_test_status_update(test, "object %d does not match object %d\n", obj->i, tmp_obj.i);
				res = AST_TEST_FAIL;
			}
			ao2_t_ref(obj, -1, "test");
		}
	}

	/* Testing ao2_find with OBJ_KEY */
	for (num = 75; num--;) {
		int i = ast_random() % lim; /* find a random object */

		if (!(obj = ao2_find(c1, &i, OBJ_KEY))) {
			res = AST_TEST_FAIL;
			ast_test_status_update(test, "COULD NOT FIND:%d, ao2_find() with OBJ_KEY flag failed.\n", i);
		} else {
			/* a correct match will only take place when the custom cmp function is used */
			if (use_cmp && obj->i != i) {
				ast_test_status_update(test, "object %d does not match object %d\n", obj->i, tmp_obj.i);
				res = AST_TEST_FAIL;
			}
			ao2_t_ref(obj, -1, "test");
		}
	}

	/* Testing ao2_find with OBJ_PARTIAL_KEY */
	partial_key_match_range = 0;
	for (num = 100; num--;) {
		int i = ast_random() % lim; /* find a random object */

		if (!(obj = ao2_find(c1, &i, OBJ_PARTIAL_KEY))) {
			res = AST_TEST_FAIL;
			ast_test_status_update(test, "COULD NOT FIND:%d, ao2_find() with OBJ_PARTIAL_KEY flag failed.\n", i);
		} else {
			/* a correct match will only take place when the custom cmp function is used */
			if (use_cmp && obj->i != i) {
				ast_test_status_update(test, "object %d does not match object %d\n", obj->i, tmp_obj.i);
				res = AST_TEST_FAIL;
			}
			ao2_t_ref(obj, -1, "test");
		}
	}

	/*
	 * Testing ao2_find with OBJ_POINTER | OBJ_UNLINK | OBJ_CONTINUE.
	 * In this test items are unlinked from c1 and placed in c2.  Then
	 * unlinked from c2 and placed back into c1.
	 *
	 * For this module and set of custom hash/cmp functions, an object
	 * should only be found if the astobj2 default cmp function is used.
	 * This test is designed to mimic the chan_iax.c call number use case.
	 */
	num = lim;
	for (count = 0; num && count < 100; ++count) {
		--num;

		/* This special manipulation is needed for sorted buckets. */
		special_bucket = num;
		switch (count) {
		case 0:
			/* Beyond end of bucket list. */
			special_match = lim;
			break;
		case 1:
			/* At end of bucket list. */
			special_match = num;
			break;
		case 2:
			/* In between in middle of bucket list. */
			special_match = num - 1;
			break;
		case 3:
			/* Beginning of bucket list. */
			special_match = num % n_buckets;
			break;
		case 4:
			/* Before bucket list. */
			special_match = -1;
			break;
		default:
			/* Empty bucket list. (If possible to empty it.) */
			special_match = -1;
			special_bucket = lim - 1;
			break;
		}

		if (!(obj = ao2_find(c1, NULL, OBJ_POINTER | OBJ_UNLINK | OBJ_CONTINUE))) {
			if (!use_cmp) {
				ast_test_status_update(test,
					"ao2_find with OBJ_POINTER | OBJ_UNLINK | OBJ_CONTINUE failed with default cmp_cb.\n");
				res = AST_TEST_FAIL;
			}
		} else {
			if (use_cmp) {
				ast_test_status_update(test,
					"ao2_find with OBJ_POINTER | OBJ_UNLINK | OBJ_CONTINUE failed with custom cmp_cb.\n");
				res = AST_TEST_FAIL;
			}
			ao2_link(c2, obj);
			ao2_t_ref(obj, -1, "test");
		}
	}
	if (ao2_container_check(c1, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	if (ao2_container_check(c2, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	it = ao2_iterator_init(c2, 0);
	while ((obj = ao2_t_iterator_next(&it, "test"))) {
		ao2_t_unlink(c2, obj, "test");
		ao2_t_link(c1, obj, "test");
		ao2_t_ref(obj, -1, "test");
	}
	ao2_iterator_destroy(&it);
	if (ao2_container_check(c1, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	if (ao2_container_check(c2, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	/* Test Callback with no flags. */
	increment = 0;
	ao2_t_callback(c1, 0, increment_cb, &increment, "test callback");
	if (increment != lim) {
		ast_test_status_update(test, "callback with no flags failed. Increment is %d\n", increment);
		res = AST_TEST_FAIL;
	}

	/* Test Callback with OBJ_NODATA. This should do nothing different than with no flags here. */
	increment = 0;
	ao2_t_callback(c1, OBJ_NODATA, increment_cb, &increment, "test callback");
	if (increment != lim) {
		ast_test_status_update(test, "callback with OBJ_NODATA failed. Increment is %d\n", increment);
		res = AST_TEST_FAIL;
	}

	/* Test OBJ_MULTIPLE with OBJ_UNLINK, add items back afterwards */
	num = lim < 25 ? lim : 25;
	if (!(mult_it = ao2_t_callback(c1, OBJ_MULTIPLE | OBJ_UNLINK, multiple_cb, &num, "test multiple"))) {
		ast_test_status_update(test, "OBJ_MULTIPLE with OBJ_UNLINK test failed.\n");
		res = AST_TEST_FAIL;
	} else {
		/* make sure num items unlinked is as expected */
		if ((lim - ao2_container_count(c1)) != num) {
			ast_test_status_update(test, "OBJ_MULTIPLE | OBJ_UNLINK test failed, did not unlink correct number of objects.\n");
			res = AST_TEST_FAIL;
		}
		if (ao2_container_check(c1, 0)) {
			ast_test_status_update(test, "container integrity check failed\n");
			res = AST_TEST_FAIL;
			goto cleanup;
		}

		/* link what was unlinked back into c1 */
		while ((obj = ao2_t_iterator_next(mult_it, "test"))) {
			ao2_t_link(c1, obj, "test");
			ao2_t_ref(obj, -1, "test"); /* remove ref from iterator */
		}
		ao2_iterator_destroy(mult_it);
		if (ao2_container_check(c1, 0)) {
			ast_test_status_update(test, "container integrity check failed\n");
			res = AST_TEST_FAIL;
			goto cleanup;
		}
	}

	/* Test OBJ_MULTIPLE without unlink and iterate the returned container */
	num = 5;
	if (!(mult_it = ao2_t_callback(c1, OBJ_MULTIPLE, multiple_cb, &num, "test multiple"))) {
		ast_test_status_update(test, "OBJ_MULTIPLE without OBJ_UNLINK test failed.\n");
		res = AST_TEST_FAIL;
	} else {
		while ((obj = ao2_t_iterator_next(mult_it, "test"))) {
			ao2_t_ref(obj, -1, "test"); /* remove ref from iterator */
		}
		ao2_iterator_destroy(mult_it);
	}

	/* Test OBJ_MULTIPLE without unlink and no iterating */
	num = 5;
	if (!(mult_it = ao2_t_callback(c1, OBJ_MULTIPLE, multiple_cb, &num, "test multiple"))) {
		ast_test_status_update(test, "OBJ_MULTIPLE with no OBJ_UNLINK and no iterating failed.\n");
		res = AST_TEST_FAIL;
	} else {
		ao2_iterator_destroy(mult_it);
	}

	/* Is the container count what we expect after all the finds and unlinks? */
	if (ao2_container_count(c1) != lim) {
		ast_test_status_update(test, "container count does not match what is expected after ao2_find tests.\n");
		res = AST_TEST_FAIL;
	}

	/* Testing iterator.  Unlink a single object and break. do not add item back */
	it = ao2_iterator_init(c1, 0);
	num = ast_random() % lim; /* remove a random object */
	while ((obj = ao2_t_iterator_next(&it, "test"))) {
		if (obj->i == num) {
			ao2_t_unlink(c1, obj, "test");
			ao2_t_ref(obj, -1, "test");
			break;
		}
		ao2_t_ref(obj, -1, "test");
	}
	ao2_iterator_destroy(&it);

	/* Is the container count what we expect after removing a single item? */
	if (ao2_container_count(c1) != (lim - 1)) {
		ast_test_status_update(test, "unlink during iterator failed. Number %d was not removed.\n", num);
		res = AST_TEST_FAIL;
	}
	if (ao2_container_check(c1, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	/* Test unlink all with OBJ_MULTIPLE, leave a single object for the container to destroy */
	ao2_t_callback(c1, OBJ_MULTIPLE | OBJ_UNLINK | OBJ_NODATA, all_but_one_cb, NULL, "test multiple");
	/* check to make sure all test_obj destructors were called except for 1 */
	if (destructor_count != 1) {
		ast_test_status_update(test, "OBJ_MULTIPLE | OBJ_UNLINK | OBJ_NODATA failed. destructor count %d\n", destructor_count);
		res = AST_TEST_FAIL;
	}
	if (ao2_container_check(c1, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
	}

cleanup:
	/* destroy containers */
	if (c1) {
		ao2_t_ref(c1, -1, "bye c1");
	}
	if (c2) {
		ao2_t_ref(c2, -1, "bye c2");
	}
	if (c3) {
		ao2_t_ref(c3, -1, "bye c3");
	}

	if (destructor_count > 0) {
		ast_test_status_update(test, "all destructors were not called, destructor count is %d\n", destructor_count);
		res = AST_TEST_FAIL;
	} else if (destructor_count < 0) {
		ast_test_status_update(test, "Destructor was called too many times, destructor count is %d\n", destructor_count);
		res = AST_TEST_FAIL;
	}

	return res;
}

AST_TEST_DEFINE(astobj2_test_1)
{
	int res = AST_TEST_PASS;

	switch (cmd) {
	case TEST_INIT:
		info->name = "astobj2_test1";
		info->category = "/main/astobj2/";
		info->summary = "Test ao2 objects, containers, callbacks, and iterators";
		info->description =
			"Builds ao2_containers with various item numbers, bucket sizes, cmp and hash "
			"functions. Runs a series of tests to manipulate the container using callbacks "
			"and iterators.  Verifies expected behavior.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	/* Test number, use_hash, use_sort, use_cmp, number of objects. */
	if ((res = astobj2_test_1_helper(1, 0, 0, 0, 500, test)) == AST_TEST_FAIL) {
		return res;
	}

	if ((res = astobj2_test_1_helper(2, 0, 0, 1, 500, test)) == AST_TEST_FAIL) {
		return res;
	}

	if ((res = astobj2_test_1_helper(3, 0, 1, 0, 500, test)) == AST_TEST_FAIL) {
		return res;
	}

	if ((res = astobj2_test_1_helper(4, 0, 1, 1, 500, test)) == AST_TEST_FAIL) {
		return res;
	}

	if ((res = astobj2_test_1_helper(5, 1, 0, 0, 1000, test)) == AST_TEST_FAIL) {
		return res;
	}

	if ((res = astobj2_test_1_helper(6, 1, 0, 1, 1000, test)) == AST_TEST_FAIL) {
		return res;
	}

	if ((res = astobj2_test_1_helper(7, 1, 1, 0, 1000, test)) == AST_TEST_FAIL) {
		return res;
	}

	if ((res = astobj2_test_1_helper(8, 1, 1, 1, 1000, test)) == AST_TEST_FAIL) {
		return res;
	}

	return res;
}

AST_TEST_DEFINE(astobj2_test_2)
{
	int res = AST_TEST_PASS;
	struct ao2_container *c;
	struct ao2_iterator i;
	struct test_obj *obj;
	int num;
	static const int NUM_OBJS = 5;
	int destructor_count = NUM_OBJS;
	struct test_obj tmp_obj = { 0, };

	switch (cmd) {
	case TEST_INIT:
		info->name = "astobj2_test2";
		info->category = "/main/astobj2/";
		info->summary = "Test a certain scenario using ao2 iterators";
		info->description =
			"This test is aimed at testing for a specific regression that occurred. "
			"Add some objects into a container.  Mix finds and iteration and make "
			"sure that the iterator still sees all objects.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	c = ao2_container_alloc(1, NULL, test_cmp_cb);
	if (!c) {
		ast_test_status_update(test, "ao2_container_alloc failed.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	for (num = 1; num <= NUM_OBJS; num++) {
		if (!(obj = ao2_alloc(sizeof(struct test_obj), test_obj_destructor))) {
			ast_test_status_update(test, "ao2_alloc failed.\n");
			res = AST_TEST_FAIL;
			goto cleanup;
		}
		obj->destructor_count = &destructor_count;
		obj->i = num;
		ao2_link(c, obj);
		ao2_ref(obj, -1);
		if (ao2_container_count(c) != num) {
			ast_test_status_update(test, "container did not link correctly\n");
			res = AST_TEST_FAIL;
		}
	}
	if (ao2_container_check(c, 0)) {
		ast_test_status_update(test, "container integrity check failed\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}

	/*
	 * Iteration take 1.  Just make sure we see all NUM_OBJS objects.
	 */
	num = 0;
	i = ao2_iterator_init(c, 0);
	while ((obj = ao2_iterator_next(&i))) {
		num++;
		ao2_ref(obj, -1);
	}
	ao2_iterator_destroy(&i);

	if (num != NUM_OBJS) {
		ast_test_status_update(test, "iterate take 1, expected '%d', only saw '%d' objects\n",
				NUM_OBJS, num);
		res = AST_TEST_FAIL;
	}

	/*
	 * Iteration take 2.  Do a find for the last object, then iterate and make
	 * sure we find all NUM_OBJS objects.
	 */
	tmp_obj.i = NUM_OBJS;
	obj = ao2_find(c, &tmp_obj, OBJ_POINTER);
	if (!obj) {
		ast_test_status_update(test, "ao2_find() failed.\n");
		res = AST_TEST_FAIL;
	} else {
		ao2_ref(obj, -1);
	}

	num = 0;
	i = ao2_iterator_init(c, 0);
	while ((obj = ao2_iterator_next(&i))) {
		num++;
		ao2_ref(obj, -1);
	}
	ao2_iterator_destroy(&i);

	if (num != NUM_OBJS) {
		ast_test_status_update(test, "iterate take 2, expected '%d', only saw '%d' objects\n",
				NUM_OBJS, num);
		res = AST_TEST_FAIL;
	}

	/*
	 * Iteration take 3.  Do a find for an object while in the middle
	 * of iterating;
	 */
	num = 0;
	i = ao2_iterator_init(c, 0);
	while ((obj = ao2_iterator_next(&i))) {
		if (num == 1) {
			struct test_obj *obj2;
			tmp_obj.i = NUM_OBJS - 1;
			obj2 = ao2_find(c, &tmp_obj, OBJ_POINTER);
			if (!obj2) {
				ast_test_status_update(test, "ao2_find() failed.\n");
				res = AST_TEST_FAIL;
			} else {
				ao2_ref(obj2, -1);
			}
		}
		num++;
		ao2_ref(obj, -1);
	}
	ao2_iterator_destroy(&i);

	if (num != NUM_OBJS) {
		ast_test_status_update(test, "iterate take 3, expected '%d', only saw '%d' objects\n",
				NUM_OBJS, num);
		res = AST_TEST_FAIL;
	}


cleanup:
	if (c) {
		ao2_ref(c, -1);
	}

	return res;
}

static AO2_GLOBAL_OBJ_STATIC(astobj2_holder);

AST_TEST_DEFINE(astobj2_test_3)
{
	int res = AST_TEST_PASS;
	int destructor_count = 0;
	int num_objects = 0;
	struct test_obj *obj = NULL;
	struct test_obj *obj2 = NULL;
	struct test_obj *obj3 = NULL;

	switch (cmd) {
	case TEST_INIT:
		info->name = "astobj2_test3";
		info->category = "/main/astobj2/";
		info->summary = "Test global ao2 holder";
		info->description =
			"This test is to see if the global ao2 holder works as intended.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	/* Put an object in the holder */
	obj = ao2_alloc(sizeof(struct test_obj), test_obj_destructor);
	if (!obj) {
		ast_test_status_update(test, "ao2_alloc failed.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	obj->destructor_count = &destructor_count;
	obj->i = ++num_objects;
	obj2 = ao2_t_global_obj_replace(astobj2_holder, obj, "Save object in the holder");
	if (obj2) {
		ast_test_status_update(test, "Returned object not expected.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	/* Save object for next check. */
	obj3 = obj;

	/* Replace an object in the holder */
	obj = ao2_alloc(sizeof(struct test_obj), test_obj_destructor);
	if (!obj) {
		ast_test_status_update(test, "ao2_alloc failed.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	obj->destructor_count = &destructor_count;
	obj->i = ++num_objects;
	obj2 = ao2_t_global_obj_replace(astobj2_holder, obj, "Replace object in the holder");
	if (!obj2) {
		ast_test_status_update(test, "Expected an object.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	if (obj2 != obj3) {
		ast_test_status_update(test, "Replaced object not expected object.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	ao2_ref(obj3, -1);
	obj3 = NULL;
	ao2_ref(obj2, -1);
	obj2 = NULL;
	ao2_ref(obj, -1);

	/* Replace with unref of an object in the holder */
	obj = ao2_alloc(sizeof(struct test_obj), test_obj_destructor);
	if (!obj) {
		ast_test_status_update(test, "ao2_alloc failed.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	obj->destructor_count = &destructor_count;
	obj->i = ++num_objects;
	if (!ao2_t_global_obj_replace_unref(astobj2_holder, obj, "Replace w/ unref object in the holder")) {
		ast_test_status_update(test, "Expected an object to be replaced.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	/* Save object for next check. */
	obj3 = obj;

	/* Get reference to held object. */
	obj = ao2_t_global_obj_ref(astobj2_holder, "Get a held object reference");
	if (!obj) {
		ast_test_status_update(test, "Expected an object.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	if (obj != obj3) {
		ast_test_status_update(test, "Referenced object not expected object.\n");
		res = AST_TEST_FAIL;
		goto cleanup;
	}
	ao2_ref(obj3, -1);
	obj3 = NULL;
	ao2_ref(obj, -1);
	obj = NULL;

	/* Release the object in the global holder. */
	ao2_t_global_obj_release(astobj2_holder, "Check release all objects");
	destructor_count += num_objects;
	if (0 < destructor_count) {
		ast_test_status_update(test,
			"all destructors were not called, destructor count is %d\n",
			destructor_count);
		res = AST_TEST_FAIL;
	} else if (destructor_count < 0) {
		ast_test_status_update(test,
			"Destructor was called too many times, destructor count is %d\n",
			destructor_count);
		res = AST_TEST_FAIL;
	}

cleanup:
	if (obj) {
		ao2_t_ref(obj, -1, "Test cleanup external object 1");
	}
	if (obj2) {
		ao2_t_ref(obj2, -1, "Test cleanup external object 2");
	}
	if (obj3) {
		ao2_t_ref(obj3, -1, "Test cleanup external object 3");
	}
	ao2_t_global_obj_release(astobj2_holder, "Test cleanup holder");

	return res;
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(astobj2_test_1);
	AST_TEST_UNREGISTER(astobj2_test_2);
	AST_TEST_UNREGISTER(astobj2_test_3);
	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(astobj2_test_1);
	AST_TEST_REGISTER(astobj2_test_2);
	AST_TEST_REGISTER(astobj2_test_3);
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "ASTOBJ2 Unit Tests");
