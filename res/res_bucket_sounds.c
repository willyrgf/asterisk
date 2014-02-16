/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
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

/*!
 * \file
 *
 * \brief Bucket 'sounds' scheme implementation
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include <dirent.h>
#include <sys/stat.h>

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/module.h"
#include "asterisk/bucket.h"
#include "asterisk/paths.h" /* use ast_config_AST_DATA_DIR */
#include "asterisk/file.h"
#include "asterisk/cli.h"
#include "asterisk/stasis_message_router.h"
#include "asterisk/stasis_system.h"
#include "asterisk/format.h"

/*! \brief Number of buckets for buckets */
#define BUCKET_BUCKETS 53

/*! \brief Number of buckets for files */
#define FILE_BUCKETS 53

/*! \brief Structure which contains a snapshot of sound buckets and files */
struct sounds_snapshot {
	/*! \brief Container of buckets */
	struct ao2_container *buckets;
	/*! \brief Container of files */
	struct ao2_container *files;
};

/*! \brief Structure for pending snapshot update */
struct sounds_pending {
	/*! \brief Container of directory paths to process */
	struct ao2_container *paths;
	/*! \brief Pending sounds snapshot */
	struct sounds_snapshot *snapshot;
	/*! \brief Top level root bucket */
	struct ast_bucket *root;
	/*! \brief Error occurred during pending snapshot creation */
	unsigned int error:1;
};

/*! \brief Current snapshot */
static AO2_GLOBAL_OBJ_STATIC(sounds_snapshot);

/*! \brief Message router for format registering/unregistering */
static struct stasis_message_router *sounds_system_router;

/*! \brief Hashing function for buckets AND files - this can be common due to usage of sorcery */
static int sounds_snapshot_hash(const void *obj, const int flags)
{
	const char *key;

	switch (flags & (OBJ_POINTER | OBJ_KEY | OBJ_PARTIAL_KEY)) {
	case OBJ_KEY:
		key = obj;
		return ast_str_hash(key);
	case OBJ_POINTER:
		return ast_str_hash(ast_sorcery_object_get_id(obj));
	default:
		ast_assert(0);
		return 0;
	}
}

/*! \brief Comparison function for buckets AND files - this can be common due to usage of sorcery */
static int sounds_snapshot_cmp(void *obj, void *arg, int flags)
{
	const char *id = arg;

	return !strcmp(ast_sorcery_object_get_id(obj), flags & OBJ_KEY ? id : ast_sorcery_object_get_id(arg)) ? CMP_MATCH | CMP_STOP : 0;
}

/*! \brief Destructor for sounds snapshot */
static void sounds_snapshot_destroy(void *obj)
{
	struct sounds_snapshot *snapshot = obj;

	ao2_cleanup(snapshot->buckets);
	ao2_cleanup(snapshot->files);
}

/*! \brief Allocator function for sounds snapshot */
static struct sounds_snapshot *sounds_snapshot_alloc(void)
{
	RAII_VAR(struct sounds_snapshot *, snapshot, NULL, ao2_cleanup);

	snapshot = ao2_alloc(sizeof(*snapshot), sounds_snapshot_destroy);
	if (!snapshot) {
		return NULL;
	}

	snapshot->buckets = ao2_container_alloc_options(AO2_ALLOC_OPT_LOCK_NOLOCK, BUCKET_BUCKETS, sounds_snapshot_hash,
		sounds_snapshot_cmp);
	if (!snapshot->buckets) {
		return NULL;
	}

	snapshot->files = ao2_container_alloc_options(AO2_ALLOC_OPT_LOCK_NOLOCK, FILE_BUCKETS, sounds_snapshot_hash,
		sounds_snapshot_cmp);
	if (!snapshot->files) {
		return NULL;
	}

	ao2_ref(snapshot, +1);
	return snapshot;
}

/*! \brief Callback function for creating a bucket or file which returns failure as sounds are read-only */
static int sounds_create(const struct ast_sorcery *sorcery, void *data, void *object)
{
	return -1;
}

/*! \brief Callback function for retrieving a bucket */
static void *sounds_bucket_retrieve_id(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id)
{
	RAII_VAR(struct sounds_snapshot *, snapshot, ao2_global_obj_ref(sounds_snapshot), ao2_cleanup);

	if (!snapshot) {
		return NULL;
	}

	return ao2_find(snapshot->buckets, id, OBJ_KEY);
}

/*! \brief Callback function for retrieving a file */
static void *sounds_file_retrieve_id(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id)
{
	RAII_VAR(struct sounds_snapshot *, snapshot, ao2_global_obj_ref(sounds_snapshot), ao2_cleanup);

	if (!snapshot) {
		return NULL;
	}

	return ao2_find(snapshot->files, id, OBJ_KEY);
}

/*! \brief Callback function for updating a bucket or file which returns failure as sounds are read-only */
static int sounds_update(const struct ast_sorcery *sorcery, void *data, void *object)
{
	return -1;
}

/*! \brief Callback function for deleting a bucket or file which returns failure as sounds are read-only */
static int sounds_delete(const struct ast_sorcery *sorcery, void *data, void *object)
{
	return -1;
}

/*! \brief Sorcery implementation for buckets */
static struct ast_sorcery_wizard sounds_bucket_wizard = {
	.name = "sounds",
	.create = sounds_create,
	.retrieve_id = sounds_bucket_retrieve_id,
	.update = sounds_update,
	.delete = sounds_delete,
};

/*! \brief Sorcery implementation for files */
static struct ast_sorcery_wizard sounds_file_wizard = {
	.name = "sounds",
	.create = sounds_create,
	.retrieve_id = sounds_file_retrieve_id,
	.update = sounds_update,
	.delete = sounds_delete,
};

/*! \brief Helper function which adds a child bucket to a parent */
static int sounds_bucket_add_child_bucket(struct sounds_pending *pending, struct ast_bucket *parent, const char *parent_path,
	const char *child_path, const char *child_name)
{
	RAII_VAR(struct ast_str *, bucket_uri, ast_str_create(64), ast_free);

	if (!bucket_uri) {
		return -1;
	}

	/* Create a URI for this child and add it to the parent so it can be found */
	ast_str_set(&bucket_uri, 0, "sounds:%s/%s", parent_path + strlen(ast_config_AST_DATA_DIR) + 7, child_name);
	ast_str_container_add(parent->buckets, ast_str_buffer(bucket_uri));

	/* Also add the full filesystem path so on the next iteration it gets processed */
	ast_str_container_add(pending->paths, child_path);

	return 0;
}

/*! \brief Helper function which adds a file to a parent */
static int sounds_bucket_add_file(struct sounds_pending *pending, struct ast_bucket *parent, const char *parent_path,
	const char *file_path, const char *file_name)
{
	RAII_VAR(char *, file_name_stripped, ast_strdup(file_name), ast_free);
	RAII_VAR(char *, language, NULL, ast_free);
	char *extension;
	const struct ast_format *format;
	RAII_VAR(struct ast_str *, file_uri, ast_str_create(64), ast_free);
	RAII_VAR(struct ast_bucket_file *, file, NULL, ao2_cleanup);
	RAII_VAR(struct ast_bucket_metadata *, formats, NULL, ao2_cleanup);

	if (ast_strlen_zero(file_name_stripped) || !file_uri) {
		return -1;
	}

	/* Parse out the extension of the file so we can add it to the file as format metadata */
	extension = strrchr(file_name_stripped, '.');
	if (!extension) {
		ast_log(LOG_WARNING, "Sound file '%s' has no extension, skipping\n", file_path);
		return 0;
	}
	*extension++ = '\0';

	format = ast_get_format_for_file_ext(extension);
	if (!format) {
		return 0;
	}

	/* Top level root bucket files don't have a language */
	if (pending->root != parent) {
		char *trailing;

		/* Parse the language from the path */
		language = ast_strdup(parent_path + strlen(ast_config_AST_DATA_DIR) + 8);
		if (!language) {
			return -1;
		}

		trailing = strchr(language, '/');
		if (trailing) {
			*trailing = '\0';
		}
	}

	/* Find or create a generic bucket file within the root which contains the formats for this sound, description, and language */
	ast_str_set(&file_uri, 0, "sounds:%s", file_name_stripped);

	file = ao2_find(pending->snapshot->files, ast_str_buffer(file_uri), OBJ_KEY);
	if (!file) {
		file = ast_bucket_file_alloc(ast_str_buffer(file_uri));
		if (!file) {
			ast_log(LOG_WARNING, "Could not create a generic top level file for '%s', skipping\n", file_name_stripped);
			return -1;
		}

		/* This is a new file so it will start out with only initial information */
		ast_bucket_file_metadata_set(file, "languages", language);
		ast_copy_string(file->path, file_name_stripped, sizeof(file->path));
		ao2_link(pending->snapshot->files, file);
		ast_str_container_add(pending->root->files, ast_str_buffer(file_uri));
	} else {
		/* The file already exists so we are appending the language to it if not already present */
		RAII_VAR(struct ast_bucket_metadata *, languages, ast_bucket_file_metadata_get(file, "languages"), ao2_cleanup);
		char *tmp = ast_strdupa(languages->value), *current_language;

		/* Iterate through current languages on the top level sound file */
		while ((current_language = strsep(&tmp, " "))) {
			if (!strcmp(current_language, language)) {
				break;
			}
		}

		/* The new language only needs to be added if not already there */
		if (!current_language) {
			char languages_str[strlen(languages->value) + strlen(language) + 2];

			snprintf(languages_str, sizeof(languages_str), "%s %s", languages->value, language);
			ast_bucket_file_metadata_set(file, "languages", languages_str);
		}
	}
	ao2_cleanup(file);

	/* Find or create a generic bucket file within the language which contains the formats for this sound, and description */
	ast_str_set(&file_uri, 0, "sounds:%s/%s", parent_path + strlen(ast_config_AST_DATA_DIR) + 7, file_name_stripped);

	file = ao2_find(pending->snapshot->files, ast_str_buffer(file_uri), OBJ_KEY);
	if (!file) {
		file = ast_bucket_file_alloc(ast_str_buffer(file_uri));
		if (!file) {
			ast_log(LOG_WARNING, "Could not create a generic file for '%s', skipping\n", file_name_stripped);
			return -1;
		}

		snprintf(file->path, sizeof(file->path), "%s/%s", parent_path, file_name_stripped);

		/* This is a new file so it will start out with only one format */
		ast_bucket_file_metadata_set(file, "formats", extension);
		ao2_link(pending->snapshot->files, file);
		ast_str_container_add(parent->files, ast_str_buffer(file_uri));
	} else {
		/* The file already exists so we are appending a new format to it */
		RAII_VAR(struct ast_bucket_metadata *, formats, ast_bucket_file_metadata_get(file, "formats"), ao2_cleanup);
		char formats_str[strlen(formats->value) + strlen(extension) + 2];

		snprintf(formats_str, sizeof(formats_str), "%s %s", formats->value, extension);
		ast_bucket_file_metadata_set(file, "formats", formats_str);
	}
	ao2_cleanup(file);

	/* Create an actual bucket file which points to the real file */
	ast_str_set(&file_uri, 0, "sounds:%s/%s", parent_path + strlen(ast_config_AST_DATA_DIR) + 7, file_name);

	file = ast_bucket_file_alloc(ast_str_buffer(file_uri));
	if (!file) {
		return -1;
	}

	ast_copy_string(file->path, file_path, sizeof(file->path));
	ast_bucket_file_metadata_set(file, "format", extension);

	if (!ast_strlen_zero(language)) {
		ast_bucket_file_metadata_set(file, "language", language);
	}

	ao2_link(pending->snapshot->files, file);
	ast_str_container_add(parent->files, ast_str_buffer(file_uri));

	return 0;
}

/*! \brief Callback function which queries for directories and sound files within a path, and creates bucket objects */
static int sounds_path_populate_callback(void *obj, void *arg, int flags)
{
	char *path = obj;
	size_t path_len = strlen(path);
	struct sounds_pending *pending = arg;
	RAII_VAR(struct ast_str *, bucket_uri, ast_str_create(64), ast_free);
	RAII_VAR(struct ast_bucket *, bucket, NULL, ao2_cleanup);
	struct dirent *entry;
	DIR *directory;

	directory = opendir(path);
	if (!directory) {
		ast_log(LOG_ERROR, "Failed to open path '%s'\n", path);
		pending->error = 1;
		return CMP_MATCH;
	}

	ast_str_set(&bucket_uri, 0, "sounds:%s", path + strlen(ast_config_AST_DATA_DIR) + 7);

	/* If this is not the initial directory create a new bucket, otherwise return the root */
	if (strcmp(ast_str_buffer(bucket_uri), "sounds:")) {
		bucket = ast_bucket_alloc(ast_str_buffer(bucket_uri));
		if (!bucket) {
			ast_log(LOG_ERROR, "Failed to create bucket for '%s'\n", path);
			closedir(directory);
			pending->error = 1;
			return CMP_MATCH;
		}
	} else {
		ao2_ref(pending->root, +1);
		bucket = pending->root;
	}

	while ((entry = readdir(directory)) != NULL) {
		/* Room for / in between and null terminator */
		char child_path[path_len + strlen(entry->d_name) + 2];
		struct stat st;

		/* Ignore anything beginning with '.' as they are not useful files */
		if (!strncmp(entry->d_name, ".", 1)) {
			continue;
		}

		snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);

		if (stat(child_path, &st) < 0) {
			ast_log(LOG_ERROR, "Failed to stat %s\n", child_path);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			if (sounds_bucket_add_child_bucket(pending, bucket, path, child_path, entry->d_name)) {
				pending->error = 1;
				break;
			}
		} else if (S_ISREG(st.st_mode)) {
			if (sounds_bucket_add_file(pending, bucket, path, child_path, entry->d_name)) {
				pending->error = 1;
				break;
			}
		}
	}

	closedir(directory);

	if (!pending->error) {
		ao2_link(pending->snapshot->buckets, bucket);
	}

	return CMP_MATCH;
}

/*! \brief Helper function which parses a description document and applies it to any sounds present */
static int sounds_path_description_apply(struct sounds_pending *pending, const char *parent_path, const char *file_path)
{
	FILE *f;
	size_t len;
	ssize_t read;
	char *line = NULL;

	f = fopen(file_path, "r");
	if (!f) {
		return -1;
	}

	while ((read = getline(&line, &len, f)) != -1) {
		char *description = line, *name;
		RAII_VAR(struct ast_str *, uri, ast_str_create(64), ast_free);
		RAII_VAR(struct ast_bucket_file *, file, NULL, ao2_cleanup);

		/* Skip comments */
		if (*line == ';') {
			continue;
		}

		/* Separate the name and description and remove extra surrounding whitespace */
		name = strsep(&description, ":");
		name = ast_strip(name);
		description = ast_strip(description);

		if (ast_strlen_zero(name) || ast_strlen_zero(description)) {
			continue;
		}

		ast_str_set(&uri, 0, "sounds:%s/%s", parent_path + strlen(ast_config_AST_DATA_DIR) + 7, name);

		file = ao2_find(pending->snapshot->files, ast_str_buffer(uri), OBJ_KEY);
		if (!file) {
			ast_log(LOG_WARNING, "Have description for '%s' but file does not exist\n", ast_str_buffer(uri));
			continue;
		}

		ast_bucket_file_metadata_set(file, "description", description);
	}

	ast_std_free(line);
	fclose(f);

	return 0;
}

/*! \brief Callback function which queries for directories and description files within a path, and updates files */
static int sounds_path_description_callback(void *obj, void *arg, int flags)
{
	char *path = obj;
	size_t path_len = strlen(path);
	struct sounds_pending *pending = arg;
	struct dirent *entry;
	DIR *directory;

	directory = opendir(path);
	if (!directory) {
		ast_log(LOG_ERROR, "Failed to open path '%s'\n", path);
		pending->error = 1;
		return CMP_MATCH;
	}

	while ((entry = readdir(directory)) != NULL) {
		/* Room for / in between and null terminator */
		char child_path[path_len + strlen(entry->d_name) + 2], *extension;
		struct stat st;

		/* Ignore anything beginning with '.' as they are not useful files */
		if (!strncmp(entry->d_name, ".", 1)) {
			continue;
		}

		snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);

		if (stat(child_path, &st) < 0) {
			ast_log(LOG_ERROR, "Failed to stat %s\n", child_path);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			/* The next iteration will process the child path */
			ast_str_container_add(pending->paths, child_path);
			continue;
		} else if (!S_ISREG(st.st_mode)) {
			continue;
		}

		extension = strrchr(entry->d_name, '.');
		if (!extension || strcmp(extension, ".txt")) {
			/* If no extension exists or it is not a text file ignore it */
			continue;
		}

		if (sounds_path_description_apply(pending, path, child_path)) {
			pending->error = 1;
			break;
		}
	}

	closedir(directory);

	return CMP_MATCH;
}

/*! \brief Helper function which reloads the available sounds */
static void sounds_reload(void)
{
	/* Enough room for data directory and /sounds */
	char initial_directory[strlen(ast_config_AST_DATA_DIR) + strlen("/sounds") + 1];
	struct sounds_pending pending = {
		.paths = ao2_container_alloc_options(AO2_ALLOC_OPT_LOCK_NOLOCK, 1, NULL, NULL),
		.snapshot = sounds_snapshot_alloc(),
		.root = ast_bucket_alloc("sounds:all"),
		.error = 0,
	};

	if (!pending.paths || !pending.snapshot || !pending.root) {
		goto cleanup;
	}

	/* Start out at the top of the sounds directory itself and populate buckets/files */
	snprintf(initial_directory, sizeof(initial_directory), "%s/sounds", ast_config_AST_DATA_DIR);
	ast_str_container_add(pending.paths, initial_directory);

	while (ao2_container_count(pending.paths)) {
		ao2_callback(pending.paths, OBJ_NODATA | OBJ_UNLINK | OBJ_NOLOCK, sounds_path_populate_callback, &pending);
	}

	if (pending.error) {
		ast_log(LOG_ERROR, "Error occurred when searching for sounds, aborting reload\n");
		goto cleanup;
	}

	/* Start out at the top of the sounds dirctory itself and populate descriptions */
	ast_str_container_add(pending.paths, initial_directory);

	while (ao2_container_count(pending.paths)) {
		ao2_callback(pending.paths, OBJ_NODATA | OBJ_UNLINK | OBJ_NOLOCK, sounds_path_description_callback, &pending);
	}

	if (pending.error) {
		ast_log(LOG_ERROR, "Error occurred when searching for/applying sound descriptions, aborting reload\n");
		goto cleanup;
	}

	ast_verb(2, "Found %d sound directories with a total of %d sounds\n", ao2_container_count(pending.snapshot->buckets),
		ao2_container_count(pending.snapshot->files));

	ao2_global_obj_replace_unref(sounds_snapshot, pending.snapshot);

cleanup:
	ao2_cleanup(pending.paths);
	ao2_cleanup(pending.snapshot);
	ao2_cleanup(pending.root);
}

/*! \brief Callback function for creating a file */
static int sounds_file_create(struct ast_bucket_file *file)
{
	return 0;
}

static int show_buckets_cb(void *obj, void *arg, int flags)
{
	struct ast_cli_args *a = arg;

	ast_cli(a->fd, "%s\n", ast_sorcery_object_get_id(obj));

	return 0;
}

/*! \brief Show a list of buckets available on the system */
static char *handle_cli_buckets_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	RAII_VAR(struct sounds_snapshot *, snapshot, NULL, ao2_cleanup);

	switch (cmd) {
	case CLI_INIT:
		e->command = "sounds show buckets";
		e->usage =
			"Usage: sounds show buckets\n"
			"       Shows a listing of buckets which contain sounds.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	snapshot = ao2_global_obj_ref(sounds_snapshot);
	if (!snapshot) {
		return CLI_FAILURE;
	}

	ast_cli(a->fd, "Discovered sound buckets:\n");
	ao2_callback(snapshot->buckets, OBJ_MULTIPLE | OBJ_NODATA, show_buckets_cb, a);

	return CLI_SUCCESS;
}

static int show_files_cb(void *obj, void *arg, int flags)
{
	struct ast_cli_args *a = arg;

	ast_cli(a->fd, "%s\n", ast_sorcery_object_get_id(obj));

	return 0;
}

/*! \brief Show a list of files available on the system */
static char *handle_cli_files_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	RAII_VAR(struct sounds_snapshot *, snapshot, NULL, ao2_cleanup);

	switch (cmd) {
	case CLI_INIT:
		e->command = "sounds show files";
		e->usage =
			"Usage: sounds show files\n"
			"       Shows a listing of sound files.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	snapshot = ao2_global_obj_ref(sounds_snapshot);
	if (!snapshot) {
		return CLI_FAILURE;
	}

	ast_cli(a->fd, "Discovered sound files:\n");
	ao2_callback(snapshot->files, OBJ_MULTIPLE | OBJ_NODATA, show_files_cb, a);

	return CLI_SUCCESS;
}

/*! \brief Show information about a specific bucket */
static char *handle_cli_bucket_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	RAII_VAR(struct sounds_snapshot *, snapshot, NULL, ao2_cleanup);
	RAII_VAR(struct ast_bucket *, bucket, NULL, ao2_cleanup);
	struct ao2_iterator it_files;
	char *uri;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sounds show bucket";
		e->usage =
			"Usage: sounds show bucket [uri]\n"
			"       Shows information about the specified bucket.\n";
		return NULL;
	case CLI_GENERATE:
	{
		int length = strlen(a->word);
        int which = 0;
        struct ao2_iterator it_buckets;
		char *match = NULL;
		void *object;

		snapshot = ao2_global_obj_ref(sounds_snapshot);
		if (!snapshot) {
			return NULL;
		}

		it_buckets = ao2_iterator_init(snapshot->buckets, 0);
        while ((object = ao2_iterator_next(&it_buckets))) {
            if (!strncasecmp(a->word, ast_sorcery_object_get_id(object), length) && ++which > a->n) {
                match = ast_strdup(ast_sorcery_object_get_id(object));
                ao2_ref(object, -1);
                break;
            }
            ao2_ref(object, -1);
        }
        ao2_iterator_destroy(&it_buckets);
        return match;
	}
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}

	snapshot = ao2_global_obj_ref(sounds_snapshot);
	if (!snapshot) {
		ast_cli(a->fd, "No sound information available\n");
		return CLI_FAILURE;
	}

	bucket = ao2_find(snapshot->buckets, a->argv[3], OBJ_KEY);
	if (!bucket) {
		ast_cli(a->fd, "No bucket found with URI '%s'\n", a->argv[3]);
		return CLI_FAILURE;
	}

	ast_cli(a->fd, "URI: %s\n", ast_sorcery_object_get_id(bucket));
	ast_cli(a->fd, "Scheme: %s\n", bucket->scheme);
	ast_cli(a->fd, "Files:\n");

	it_files = ao2_iterator_init(bucket->files, 0);
	for (; (uri = ao2_iterator_next(&it_files)); ao2_ref(uri, -1)) {
		ast_cli(a->fd, "\t%s\n", uri);
	}
	ao2_iterator_destroy(&it_files);

	return CLI_SUCCESS;
}

/*! \brief Show information about a specific file */
static char *handle_cli_file_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	RAII_VAR(struct sounds_snapshot *, snapshot, NULL, ao2_cleanup);
	RAII_VAR(struct ast_bucket_file *, file, NULL, ao2_cleanup);
	struct ao2_iterator it_metadata;
	struct ast_bucket_metadata *metadata;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sounds show file";
		e->usage =
			"Usage: sounds show file [uri]\n"
			"       Shows information about the specified file.\n";
		return NULL;
	case CLI_GENERATE:
	{
		int length = strlen(a->word);
        int which = 0;
        struct ao2_iterator it_files;
		char *match = NULL;
		void *object;

		snapshot = ao2_global_obj_ref(sounds_snapshot);
		if (!snapshot) {
			return NULL;
		}

		it_files = ao2_iterator_init(snapshot->files, 0);
        while ((object = ao2_iterator_next(&it_files))) {
            if (!strncasecmp(a->word, ast_sorcery_object_get_id(object), length) && ++which > a->n) {
                match = ast_strdup(ast_sorcery_object_get_id(object));
                ao2_ref(object, -1);
                break;
            }
            ao2_ref(object, -1);
        }
        ao2_iterator_destroy(&it_files);
        return match;
	}
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}

	snapshot = ao2_global_obj_ref(sounds_snapshot);
	if (!snapshot) {
		ast_cli(a->fd, "No sound information available\n");
		return CLI_FAILURE;
	}

	file = ao2_find(snapshot->files, a->argv[3], OBJ_KEY);
	if (!file) {
		ast_cli(a->fd, "No files found with URI '%s'\n", a->argv[3]);
		return CLI_FAILURE;
	}

	ast_cli(a->fd, "URI: %s\n", ast_sorcery_object_get_id(file));
	ast_cli(a->fd, "Scheme: %s\n", file->scheme);
	ast_cli(a->fd, "Path: %s\n", file->path);
	ast_cli(a->fd, "Metadata:\n");

	it_metadata = ao2_iterator_init(file->metadata, 0);
	for (; (metadata = ao2_iterator_next(&it_metadata)); ao2_ref(metadata, -1)) {
		ast_cli(a->fd, "\t%s: %s\n", metadata->name, metadata->value);
	}
	ao2_iterator_destroy(&it_metadata);

	return CLI_SUCCESS;
}

/*! \brief Struct for registering CLI commands */
static struct ast_cli_entry cli_sounds[] = {
	AST_CLI_DEFINE(handle_cli_buckets_show, "Shows available sound buckets"),
	AST_CLI_DEFINE(handle_cli_files_show, "Shows available sound files"),
	AST_CLI_DEFINE(handle_cli_bucket_show, "Shows information about a given bucket"),
	AST_CLI_DEFINE(handle_cli_file_show, "Shows information about a given file"),
};

/*! \brief Callback function invoked when formats are registered or unregistered */
static void format_update_cb(void *data, struct stasis_subscription *sub,
	struct stasis_message *message)
{
	sounds_reload();
}

static int load_module(void)
{
	sounds_system_router = stasis_message_router_create(ast_system_topic());
	if (!sounds_system_router) {
		return AST_MODULE_LOAD_FAILURE;
	}

	if (stasis_message_router_add(sounds_system_router, ast_format_register_type(), format_update_cb, NULL) ||
		stasis_message_router_add(sounds_system_router, ast_format_unregister_type(), format_update_cb, NULL) ||
		ast_cli_register_multiple(cli_sounds, ARRAY_LEN(cli_sounds))) {
		stasis_message_router_unsubscribe_and_join(sounds_system_router);
		return AST_MODULE_LOAD_FAILURE;
	}

	if (ast_bucket_scheme_register("sounds", &sounds_bucket_wizard, &sounds_file_wizard, sounds_file_create, NULL)) {
		ast_cli_unregister_multiple(cli_sounds, ARRAY_LEN(cli_sounds));
		stasis_message_router_unsubscribe_and_join(sounds_system_router);
		return AST_MODULE_LOAD_FAILURE;
	}

	sounds_reload();

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	/* This will never get called - once loaded it can't be loaded */
	return 0;
}

static int reload_module(void)
{
	sounds_reload();
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Bucket 'sounds' URI scheme",
	.load = load_module,
	.unload = unload_module,
	.reload = reload_module,
	.load_pri = AST_MODPRI_REALTIME_DRIVER,
);
