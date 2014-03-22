/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, Digium, Inc.
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

/*!
 * \file
 * \brief Sorcery Composite Object Unit Tests
 *
 * \author Mark Michelson <jcolp@digium.com>
 *
 */

/*** MODULEINFO
	<depend>TEST_FRAMEWORK</depend>
	<depend>res_sorcery_config</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include "asterisk/test.h"
#include "asterisk/module.h"
#include "asterisk/astobj2.h"
#include "asterisk/sorcery.h"
#include "asterisk/logger.h"
#include "asterisk/stringfields.h"

#define DEFAULT_FOOD_MAIN "eggs"
#define DEFAULT_FOOD_SIDE "toast"
#define DEFAULT_FOOD_CONDIMENTS "jam,butter"

struct test_sorcery_food {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(main);
		AST_STRING_FIELD(side);
		AST_STRING_FIELD(condiments);
	);
};

static void test_sorcery_food_destroy(void *obj)
{
	struct test_sorcery_food *food = obj;

	ast_string_field_free_memory(food);
}

static void *test_sorcery_food_alloc(const char *id)
{
	struct test_sorcery_food *food;
	
	food = ast_sorcery_generic_alloc(sizeof(*food), test_sorcery_food_destroy);
	if (!food || ast_string_field_init(food, 32)) {
		return NULL;
	}
}

#define DEFAULT_DRINK_BEVERAGE "coffee"
#define DEFAULT_DRINK_CONDIMENTS "cream,sugar"

struct test_sorcery_drink {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(beverage);
		AST_STRING_FIELD(condiments);
	);
};

static void test_sorcery_drink_destroy(void *obj)
{
	struct test_sorcery_drink *drink = obj;

	ast_string_field_free_memory(drink);
}

static void *test_sorcery_drink_alloc(const char *id)
{
	struct test_sorcery_drink *drink;
	
	drink = ast_sorcery_generic_alloc(sizeof(*drink), test_sorcery_food_destroy);
	if (!drink || ast_string_field_init(drink, 32)) {
		return NULL;
	}
}

#define DEFAULT_BREAKFAST_MAIN "bacon"
#define DEFAULT_BREAKFAST_CONDIMENTS "ketchup"

struct test_sorcery_breakfast {
	struct test_sorcery_food *food;
	struct test_sorcery_drink *drink;
};

static void *test_sorcery_breakfast_alloc(const char *id)
{
	return ast_sorcery_generic_alloc(sizeof(struct test_sorcery_breakfast), NULL);
}

static struct ast_sorcery *alloc_and_initialize_sorcery(void)
{
	struct ast_sorcery *sorcery;

	if (!(sorcery = ast_sorcery_open())) {
		return NULL;
	}

	if (ast_sorcery_apply_default(sorcery, "food", "memory", NULL) ||
		ast_sorcery_internal_object_register(sorcery, "food", test_sorcery_food_alloc, NULL, NULL)) {
		ast_sorcery_unref(sorcery);
		return NULL;
	}

	if (ast_sorcery_apply_default(sorcery, "drink", "memory", NULL) ||
		ast_sorcery_internal_object_register(sorcery, "drink", test_sorcery_drink_alloc, NULL, NULL)) {
		ast_sorcery_unref(sorcery);
		return NULL;
	}

	if (ast_sorcery_apply_default(sorcery, "breakfast", "memory", NULL) ||
		ast_sorcery_internal_object_register(sorcery, "breakfast", test_sorcery_breakfast_alloc, NULL, NULL)) {
		ast_sorcery_unref(sorcery);
		return NULL;
	}

	if (ast_sorcery_object_composes("breakfast", "food", offsetof(struct test_sorcery_breakfast, food)) ||
			ast_sorcery_object_composes("breakfast", "drink", offsetof(struct test_sorcery_breakfast, drink))) {
		ast_sorcery_unref(sorcery);
		return NULL;
	}

	ast_sorcery_object_field_register_nodoc(sorcery, "food", "main", DEFAULT_FOOD_MAIN, OPT_STRINGFIELD_T, 0, STRFLDSET(struct test_sorcery_food, main));
	ast_sorcery_object_field_register_nodoc(sorcery, "food", "side", DEFAULT_FOOD_SIDE, OPT_STRINGFIELD_T, 0, STRFLDSET(struct test_sorcery_food, side));
	ast_sorcery_object_field_register_nodoc(sorcery, "food", "condiments", DEFAULT_FOOD_CONDIMENTS, OPT_STRINGFIELD_T, 0, STRFLDSET(struct test_sorcery_food, condiments));
	ast_sorcery_object_field_register_nodoc(sorcery, "drink", "beverage", DEFAULT_DRINK_BEVERAGE, OPT_STRINGFIELD_T, 0, STRFLDSET(struct test_sorcery_drink, beverage));
	ast_sorcery_object_field_register_nodoc(sorcery, "drink", "condiments", DEFAULT_DRINK_CONDIMENTS, OPT_STRINGFIELD_T, 0, STRFLDSET(struct test_sorcery_drink, condiments));

	return sorcery;
}

AST_TEST_DEFINE(composite_object_alloc)
{
	RAII_VAR(struct ast_sorcery *, sorcery, NULL, ast_sorcery_unref);
	RAII_VAR(struct test_sorcery_breakfast *, breakfast, NULL, ao2_cleanup);

	switch (cmd) {
	case TEST_INIT:
		info->name = "composite_object_alloc";
		info->category = "/main/sorcery_composite/";
		info->summary = "sorcery composite object type allocation unit test";
		info->description =
			"Test composite object type allocation in sorcery";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	sorcery = alloc_and_initialize_sorcery();
	if (!sorcery) {
		ast_test_status_update(test, "Failed to create sorcery with basic objects registered\n");
		return AST_TEST_FAIL;
	}

	breakfast = ast_sorcery_alloc(sorcery, "breakfast", "blah");
	if (!breakfast) {
		ast_test_status_update(test, "Failed to allocate breakfast\n");
		return AST_TEST_FAIL;
	}

	if (!breakfast->food) {
		ast_test_status_update(test, "Failed to allocate breakfast food\n");
		return AST_TEST_FAIL;
	}

	if (!breakfast->drink) {
		ast_test_status_update(test, "Failed to allocate breakfast drink\n");
		return AST_TEST_FAIL;
	}

	if (strcmp(breakfast->food->main, DEFAULT_FOOD_MAIN) ||
			strcmp(breakfast->food->side, DEFAULT_FOOD_SIDE) ||
			strcmp(breakfast->food->condiments, DEFAULT_FOOD_CONDIMENTS)) {
		ast_test_status_update(test, "Breakfast food values are incorrect\n");
		return AST_TEST_FAIL;
	}

	if (strcmp(breakfast->drink->beverage, DEFAULT_DRINK_BEVERAGE) ||
			strcmp(breakfast->drink->condiments, DEFAULT_DRINK_CONDIMENTS)) {
		ast_test_status_update(test, "Breakfast drink values are incorrect\n");
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

static int breakfast_main_handler(const struct aco_option *opt,
		struct ast_variable *var, void *obj)
{
	struct test_sorcery_breakfast *breakfast = obj;

	ast_string_field_set(breakfast->food, main, var->value);
	return 0;
}

static int breakfast_main_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct test_sorcery_breakfast *breakfast = obj;

	*buf = ast_strdup(breakfast->food->main);
	return 0;
}

static int breakfast_condiments_handler(const struct aco_option *opt,
		struct ast_variable *var, void *obj)
{
	struct test_sorcery_breakfast *breakfast = obj;

	ast_string_field_set(breakfast->food, condiments, var->value);
	return 0;
}

static int breakfast_condiments_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct test_sorcery_breakfast *breakfast = obj;

	*buf = ast_strdup(breakfast->food->condiments);
	return 0;
}

AST_TEST_DEFINE(composite_object_override)
{
	RAII_VAR(struct ast_sorcery *, sorcery, NULL, ast_sorcery_unref);
	RAII_VAR(struct test_sorcery_breakfast *, breakfast, NULL, ao2_cleanup);

	switch (cmd) {
	case TEST_INIT:
		info->name = "composite_object_override";
		info->category = "/main/sorcery_composite/";
		info->summary = "sorcery composite object field override test";
		info->description =
			"Test composite object type override in sorcery";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	sorcery = alloc_and_initialize_sorcery();
	if (!sorcery) {
		ast_test_status_update(test, "Failed to create sorcery with basic objects registered\n");
		return AST_TEST_FAIL;
	}

	/* These will override default food values */
	ast_sorcery_object_field_register_custom_nodoc(sorcery, "breakfast", "main", 
			DEFAULT_BREAKFAST_MAIN, breakfast_main_handler, breakfast_main_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(sorcery, "breakfast", "condiments",
			DEFAULT_BREAKFAST_CONDIMENTS, breakfast_condiments_handler, breakfast_condiments_str, NULL, 0, 0);

	breakfast = ast_sorcery_alloc(sorcery, "breakfast", "blah");
	if (!breakfast) {
		ast_test_status_update(test, "Failed to allocate breakfast\n");
		return AST_TEST_FAIL;
	}

	if (strcmp(breakfast->food->main, DEFAULT_BREAKFAST_MAIN)) {
		ast_test_status_update(test, "Breakfast food main has unexpected value\n");
		return AST_TEST_FAIL;
	}

	if (strcmp(breakfast->food->condiments, DEFAULT_BREAKFAST_CONDIMENTS)) {
		ast_test_status_update(test, "Breakfast food condiments have unexpected value\n");
		return AST_TEST_FAIL;
	}

	if (strcmp(breakfast->drink->condiments, DEFAULT_DRINK_CONDIMENTS)) {
		ast_test_status_update(test, "Breakfast drink condiments have unexpected value\n");
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(composite_object_copy)
{
	RAII_VAR(struct ast_sorcery *, sorcery, NULL, ast_sorcery_unref);
	RAII_VAR(struct test_sorcery_breakfast *, breakfast, NULL, ao2_cleanup);
	RAII_VAR(struct test_sorcery_breakfast *, copy, NULL, ao2_cleanup);

	switch (cmd) {
	case TEST_INIT:
		info->name = "composite_object_override";
		info->category = "/main/sorcery_composite/";
		info->summary = "sorcery composite object field override test";
		info->description =
			"Test composite object type override in sorcery";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	sorcery = alloc_and_initialize_sorcery();
	if (!sorcery) {
		ast_test_status_update(test, "Failed to create sorcery with basic objects registered\n");
		return AST_TEST_FAIL;
	}

	breakfast = ast_sorcery_alloc(sorcery, "breakfast", "blah");
	if (!breakfast) {
		ast_test_status_update(test, "Failed to allocate breakfast\n");
		return AST_TEST_FAIL;
	}

	copy = ast_sorcery_copy(sorcery, breakfast);
	if (!copy) {
		ast_test_status_update(test, "Failed to copy breakfast\n");
		return AST_TEST_FAIL;
	}

	if (copy == breakfast || copy->food == breakfast->food || copy->drink == breakfast->drink) {
		ast_test_status_update(test, "Copy is the same as the original breakfast\n");
		return AST_TEST_FAIL;
	}

	if (strcmp(copy->food->main, breakfast->food->main) ||
			strcmp(copy->food->side, breakfast->food->side) ||
			strcmp(copy->food->condiments, breakfast->food->condiments) ||
			strcmp(copy->drink->beverage, breakfast->drink->beverage) ||
			strcmp(copy->drink->condiments, breakfast->drink->condiments)) {
		ast_test_status_update(test, "Copy's fields do not match original fields\n");
		return AST_TEST_STATUS_FAIL;
	}

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(composite_object_retrieve_by_id)
{
	RAII_VAR(struct ast_sorcery *, sorcery, NULL, ast_sorcery_unref);
	RAII_VAR(struct test_sorcery_breakfast *, breakfast, NULL, ao2_cleanup);
	RAII_VAR(struct test_sorcery_food *, food, NULL, ao2_cleanup);
	RAII_VAR(struct test_sorcery_drink *, drink, NULL, ao2_cleanup);
	RAII_VAR(struct test_sorcery_breakfast *, retrieved_breakfast, NULL, ao2_cleanup);

	switch (cmd) {
	case TEST_INIT:
		info->name = "composite_object_retrieve_by_id";
		info->category = "/main/sorcery_composite/";
		info->summary = "sorcery composite object retrieval test";
		info->description =
			"Test composite object type retrieval in sorcery";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	sorcery = alloc_and_initialize_sorcery();
	if (!sorcery) {
		ast_test_status_update(test, "Failed to create sorcery with basic objects registered\n");
		return AST_TEST_FAIL;
	}

	breakfast = ast_sorcery_alloc(sorcery, "breakfast", "blah");
	if (!breakfast) {
		ast_test_status_update(test, "Failed to allocate breakfast\n");
		return AST_TEST_FAIL;
	}

	if (ast_sorcery_create(sorcery, breakfast)) {
		ast_test_status_update(test, "Failed to create breakfast in sorcery backend\n");
		return AST_TEST_FAIL;
	}

	retrieved_breakfast = ast_sorcery_retrieve_by_id(sorcery, "breakfast", "blah");
	if (!retrieved_breakfast) {
		ast_test_status_update(test, "Failed to retrieve breakfast by ID\n");
		return AST_TEST_FAIL;
	}

	if (retrieved_breakfast != breakfast) {
		ast_test_status_update(test, "Retrieved incorrect breakfast from sorcery\n");
		return AST_TEST_FAIL;
	}

	food = ast_sorcery_retrieve_by_id(sorcery, "food", "blah");
	if (!food) {
		ast_test_status_update(test, "Failed to retrieve food by ID\n");
		return AST_TEST_FAIL;
	}

	if (food != breakfast->food) {
		ast_test_status_update(test, "Retrieved incorrect food from sorcery\n");
		return AST_TEST_FAIL;
	}

	drink = ast_sorcery_retrieve_by_id(sorcery, "drink", "blah");
	if (!drink) {
		ast_test_status_update(test, "Failed to retrieve drink by ID\n");
		return AST_TEST_FAIL;
	}

	if (drink != breakfast->drink) {
		ast_test_status_update(test, "Retrieved incorrect drink from sorcery\n");
		return AST_TEST_FAIL;
	}
}

AST_TEST_DEFINE(composite_object_retrieve_by_fields)
{
	RAII_VAR(struct ast_sorcery *, sorcery, NULL, ast_sorcery_unref);
	RAII_VAR(struct test_sorcery_breakfast *, breakfast, NULL, ao2_cleanup);
	RAII_VAR(struct test_sorcery_breakfast *, retrieved_breakfast, NULL, ao2_cleanup);
	RAII_VAR(struct ast_variable *, fields, NULL, ast_variables_destroy);

	switch (cmd) {
	case TEST_INIT:
		info->name = "composite_object_retrieve_by_fields";
		info->category = "/main/sorcery_composite/";
		info->summary = "sorcery composite object retrieval test";
		info->description =
			"Test composite object type retrieval in sorcery";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	sorcery = alloc_and_initialize_sorcery();
	if (!sorcery) {
		ast_test_status_update(test, "Failed to create sorcery with basic objects registered\n");
		return AST_TEST_FAIL;
	}

	breakfast = ast_sorcery_alloc(sorcery, "breakfast", "blah");
	if (!breakfast) {
		ast_test_status_update(test, "Failed to allocate breakfast\n");
		return AST_TEST_FAIL;
	}

	if (ast_sorcery_create(sorcery, breakfast)) {
		ast_test_status_update(test, "Failed to create breakfast in sorcery backend\n");
		return AST_TEST_FAIL;
	}

	if (!(fields = ast_variable_new("main", DEFAULT_FOOD_MAIN, "")) ||
			!(fields->next = ast_variable_new("beverage", DEFAULT_DRINK_BEVERAGE, ""))) {
		ast_test_status_update(test, "Failed to create variable fields for retrieval\n");
		return AST_TEST_FAIL;
	}

	retrieved_breakfast = ast_sorcery_retrieve_by_fields(sorcery, "breakfast",
			AST_RETRIEVE_FLAG_DEFAULT, fields);
	if (!retrieved_breakfast) {
		ast_test_status_update(test, "Failed to retrieve breakfast using fields\n");
		return AST_TEST_FAIL;
	}

	if (retrieved_breakfast != breakfast) {
		ast_test_status_update(test, "Retrieved incorrect breakfast from sorcery\n");
		return AST_TEST_FAIL;
	}

	return AST_TEST_PASS;
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(composite_object_alloc);
	AST_TEST_UNREGISTER(composite_object_override);
	AST_TEST_UNREGISTER(composite_object_copy);
	AST_TEST_UNREGISTER(composite_object_retrieve_by_id);
	AST_TEST_UNREGISTER(composite_object_retrieve_by_fields);
	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(composite_object_alloc);
	AST_TEST_REGISTER(composite_object_override);
	AST_TEST_REGISTER(composite_object_copy);
	AST_TEST_REGISTER(composite_object_retrieve_by_id);
	AST_TEST_REGISTER(composite_object_retrieve_by_fields);
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Sorcery composite object test  module");
