/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2015, Matt Jordan
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
 * \brief
 *
 * \author\verbatim <Your Name Here> <<Your Email Here>> \endverbatim
 *
 * This is a skeleton for development of an Asterisk test module
 * \ingroup tests
 */

/*** MODULEINFO
	<depend>curl</depend>
	<depend>res_curl</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <curl/curl.h>

#include "asterisk/module.h"
#include "asterisk/bucket.h"
#include "asterisk/sorcery.h"

#define GLOBAL_USERAGENT "asterisk-libcurl-agent/1.0"

struct curl_bucket_file_data {
	struct ast_bucket_file *bucket_file;
	FILE *out_file;
};

static size_t curl_header_callback(char *buffer, size_t size, size_t nitems, void *data)
{
	struct curl_bucket_file_data *cb_data = data;
	size_t realsize;
	size_t offset;
	size_t value_len;
	char *value;
	char *dupd_value;
	char *clean_value;

	realsize = size * nitems;

	/* buffer may not be NULL terminated */
	value = memchr(buffer, ':', realsize);
	if (!value) {
		ast_log(LOG_WARNING, "Failed to split received header in cURL request\n");
		return 0;
	}
	offset = value - buffer;
	value_len = realsize - offset;
	*value++ = '\0';

	if (strcmp(buffer, "ETag")
		&& strcmp(buffer, "Cache-Control")
		&& strcmp(buffer, "Last-Modified")) {
		return realsize;
	}

	dupd_value = ast_malloc(value_len + 1);
	if (!dupd_value) {
		return 0;
	}
	strncpy(dupd_value, value, value_len);
	dupd_value[value_len] = '\0';
	clean_value = dupd_value;
	clean_value = ast_skip_blanks(clean_value);
	clean_value = ast_trim_blanks(clean_value);

	ast_bucket_file_metadata_set(cb_data->bucket_file, buffer, clean_value);

	ast_free(dupd_value);
	return realsize;
}

static size_t curl_body_callback(void *ptr, size_t size, size_t nitems, void *data)
{
	struct curl_bucket_file_data *cb_data = data;
	size_t realsize;

	realsize = fwrite(ptr, size, nitems, cb_data->out_file);

	return realsize;
}

static int bucket_http_wizard_create(const struct ast_sorcery *sorcery, void *data,
	void *object)
{
	char curl_errbuf[CURL_ERROR_SIZE + 1]; /* add one to be safe */
	struct ast_bucket_file *bucket_file = object;
	const char *uri = ast_sorcery_object_get_id(bucket_file);
	CURL *curl;
	struct curl_bucket_file_data cb_data = {
		.bucket_file = bucket_file,
	};

	cb_data.out_file = fopen(bucket_file->path, "wb");
	if (!cb_data.out_file) {
		return -1;
	}

	/* TODO:
	 * -- force a refresh by pulling down the URI
	 * -- populate the object
	 */	
	curl = curl_easy_init();
	if (!curl) {
		fclose(cb_data.out_file);
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_body_callback);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_callback);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, GLOBAL_USERAGENT);

	curl_easy_setopt(curl, CURLOPT_URL, uri);
	curl_easy_setopt(curl, CURLOPT_FILE, (void*)&cb_data);
	curl_errbuf[CURL_ERROR_SIZE] = '\0';
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);

	if (curl_easy_perform(curl)) {
		ast_log(LOG_WARNING, "%s ('%s')\n", curl_errbuf, uri);
	}

	fclose(cb_data.out_file);
	return -1;
}

static int bucket_http_wizard_update(const struct ast_sorcery *sorcery, void *data,
	void *object)
{
	/*if (!strcmp(ast_sorcery_object_get_id(object), VALID_RESOURCE)) {
		return 0;
	}*/

	return -1;
}

static void *bucket_http_wizard_retrieve_id(const struct ast_sorcery *sorcery,
	void *data, const char *type, const char *id)
{
	/* TODO:
	 * -- hit the provided URI and see if we need to download it
	 *   -- if we do, pull it down and update the resource
	 *   -- if not, simply return what's there
	 */
	if (strcmp(type, "file")) {
		return NULL;
	}
	return NULL;
}

static int bucket_http_wizard_delete(const struct ast_sorcery *sorcery, void *data,
	void *object)
{
	return -1;
}

static struct ast_sorcery_wizard bucket_wizard = {
	.name = "http",
	.create = bucket_http_wizard_create,
	.retrieve_id = bucket_http_wizard_retrieve_id,
	.delete = bucket_http_wizard_delete,
};

static struct ast_sorcery_wizard bucket_file_wizard = {
	.name = "http",
	.create = bucket_http_wizard_create,
	.update = bucket_http_wizard_update,
	.retrieve_id = bucket_http_wizard_retrieve_id,
	.delete = bucket_http_wizard_delete,
};


static int unload_module(void)
{
	return 0;
}

static int load_module(void)
{
	if (ast_bucket_scheme_register("http", &bucket_wizard, &bucket_file_wizard,
			NULL, NULL)) {
		ast_log(LOG_ERROR, "Failed to register Bucket HTTP wizard scheme implementation\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "FOOBAR!",
		.support_level = AST_MODULE_SUPPORT_CORE,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_DEFAULT,
	);

