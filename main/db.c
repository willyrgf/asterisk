/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2015, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
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
 * \brief ASTdb Management
 *
 * \author Mark Spencer <markster@digium.com>
 *
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/_private.h"
#include "asterisk/paths.h"	/* use ast_config_AST_DB */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sqlite3.h>

#include "asterisk/file.h"
#include "asterisk/utils.h"
#include "asterisk/astdb.h"
#include "asterisk/stasis.h"
#include "asterisk/stasis_message_router.h"
#include "asterisk/app.h"
#include "asterisk/cli.h"
#include "asterisk/utils.h"
#include "asterisk/manager.h"

/*** DOCUMENTATION
	<manager name="DBGet" language="en_US">
		<synopsis>
			Get DB Entry.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Family" required="true" />
			<parameter name="Key" required="true" />
		</syntax>
		<description>
		</description>
	</manager>
	<manager name="DBPut" language="en_US">
		<synopsis>
			Put DB entry.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Family" required="true" />
			<parameter name="Key" required="true" />
			<parameter name="Val" />
		</syntax>
		<description>
		</description>
	</manager>
	<manager name="DBDel" language="en_US">
		<synopsis>
			Delete DB entry.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Family" required="true" />
			<parameter name="Key" required="true" />
		</syntax>
		<description>
		</description>
	</manager>
	<manager name="DBDelTree" language="en_US">
		<synopsis>
			Delete DB Tree.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Family" required="true" />
			<parameter name="Key" />
		</syntax>
		<description>
		</description>
	</manager>
 ***/

#define MAX_DB_FIELD 256
AST_MUTEX_DEFINE_STATIC(dblock);
static ast_cond_t dbcond;
static sqlite3 *astdb;
static pthread_t syncthread;
static int doexit;
static int dosync;

/*!
 * \brief A container of families to share across Asterisk instances.
 * \note Entries in this container should be treated as immutable. The container
 *       needs locking; the entries do not.
 */
static struct ao2_container *shared_families;

/*! \brief The Stasis topic for shared families */
static struct stasis_topic *db_cluster_topic;

/*! \brief A Stasis message router for handling external AstDB updates */
static struct stasis_message_router *message_router;

static void db_sync(void);

/*! \brief The AstDB key used to store which families are shared across restarts */
#define SHARED_FAMILY "__asterisk_shared_family"

#define DEFINE_SQL_STATEMENT(stmt,sql) static sqlite3_stmt *stmt; \
	const char stmt##_sql[] = sql;

DEFINE_SQL_STATEMENT(put_stmt, "INSERT OR REPLACE INTO astdb (key, value) VALUES (?, ?)")
DEFINE_SQL_STATEMENT(get_stmt, "SELECT value FROM astdb WHERE key=?")
DEFINE_SQL_STATEMENT(del_stmt, "DELETE FROM astdb WHERE key=?")
DEFINE_SQL_STATEMENT(deltree_stmt, "DELETE FROM astdb WHERE key || '/' LIKE ? || '/' || '%'")
DEFINE_SQL_STATEMENT(deltree_all_stmt, "DELETE FROM astdb")
DEFINE_SQL_STATEMENT(gettree_stmt, "SELECT key, value FROM astdb WHERE key || '/' LIKE ? || '/' || '%' ORDER BY key")
DEFINE_SQL_STATEMENT(gettree_all_stmt, "SELECT key, value FROM astdb ORDER BY key")
DEFINE_SQL_STATEMENT(showkey_stmt, "SELECT key, value FROM astdb WHERE key LIKE '%' || '/' || ? ORDER BY key")
DEFINE_SQL_STATEMENT(create_astdb_stmt, "CREATE TABLE IF NOT EXISTS astdb(key VARCHAR(256), value VARCHAR(256), PRIMARY KEY(key))")

static int init_stmt(sqlite3_stmt **stmt, const char *sql, size_t len)
{
	ast_mutex_lock(&dblock);
	if (sqlite3_prepare(astdb, sql, len, stmt, NULL) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Couldn't prepare statement '%s': %s\n", sql, sqlite3_errmsg(astdb));
		ast_mutex_unlock(&dblock);
		return -1;
	}
	ast_mutex_unlock(&dblock);

	return 0;
}

/*! \internal
 * \brief Clean up the prepared SQLite3 statement
 * \note dblock should already be locked prior to calling this method
 */
static int clean_stmt(sqlite3_stmt **stmt, const char *sql)
{
	if (sqlite3_finalize(*stmt) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Couldn't finalize statement '%s': %s\n", sql, sqlite3_errmsg(astdb));
		*stmt = NULL;
		return -1;
	}
	*stmt = NULL;
	return 0;
}

/*! \internal
 * \brief Clean up all prepared SQLite3 statements
 * \note dblock should already be locked prior to calling this method
 */
static void clean_statements(void)
{
	clean_stmt(&get_stmt, get_stmt_sql);
	clean_stmt(&del_stmt, del_stmt_sql);
	clean_stmt(&deltree_stmt, deltree_stmt_sql);
	clean_stmt(&deltree_all_stmt, deltree_all_stmt_sql);
	clean_stmt(&gettree_stmt, gettree_stmt_sql);
	clean_stmt(&gettree_all_stmt, gettree_all_stmt_sql);
	clean_stmt(&showkey_stmt, showkey_stmt_sql);
	clean_stmt(&put_stmt, put_stmt_sql);
	clean_stmt(&create_astdb_stmt, create_astdb_stmt_sql);
}

static int init_statements(void)
{
	/* Don't initialize create_astdb_statment here as the astdb table needs to exist
	 * brefore these statments can be initialized */
	return init_stmt(&get_stmt, get_stmt_sql, sizeof(get_stmt_sql))
	|| init_stmt(&del_stmt, del_stmt_sql, sizeof(del_stmt_sql))
	|| init_stmt(&deltree_stmt, deltree_stmt_sql, sizeof(deltree_stmt_sql))
	|| init_stmt(&deltree_all_stmt, deltree_all_stmt_sql, sizeof(deltree_all_stmt_sql))
	|| init_stmt(&gettree_stmt, gettree_stmt_sql, sizeof(gettree_stmt_sql))
	|| init_stmt(&gettree_all_stmt, gettree_all_stmt_sql, sizeof(gettree_all_stmt_sql))
	|| init_stmt(&showkey_stmt, showkey_stmt_sql, sizeof(showkey_stmt_sql))
	|| init_stmt(&put_stmt, put_stmt_sql, sizeof(put_stmt_sql));
}

static int convert_bdb_to_sqlite3(void)
{
	char *cmd;
	int res;

	ast_asprintf(&cmd, "%s/astdb2sqlite3 '%s'\n", ast_config_AST_SBIN_DIR, ast_config_AST_DB);
	res = ast_safe_system(cmd);
	ast_free(cmd);

	return res;
}

struct ast_db_entry *ast_db_entry_create(const char *key, const char *value)
{
	struct ast_db_entry *entry;

	entry = ast_malloc(sizeof(*entry) + strlen(key) + strlen(value) + 2);
	if (!entry) {
		return NULL;
	}
	entry->next = NULL;
	entry->key = entry->data + strlen(value) + 1;
	strcpy(entry->data, value); /* safe */
	strcpy(entry->key, key); /* safe */

	return entry;
}

/*! \internal \brief AO2 destructor for \c ast_db_shared_family */
static void shared_db_family_dtor(void *obj)
{
	struct ast_db_shared_family *family = obj;

	ast_db_freetree(family->entries);
}

struct ast_db_shared_family *ast_db_shared_family_alloc(const char *family, enum ast_db_shared_type share_type)
{
	struct ast_db_shared_family *shared_family;

	shared_family = ao2_alloc_options(sizeof(*shared_family) + strlen(family) + 1,
		shared_db_family_dtor, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!shared_family) {
		return NULL;
	}
	strcpy(shared_family->name, family); /* safe */
	shared_family->share_type = share_type;

	return shared_family;
}

/*! \internal
 * \brief Clone a \c ast_db_shared_family
 */
static struct ast_db_shared_family *db_shared_family_clone(const struct ast_db_shared_family *shared_family)
{
	return ast_db_shared_family_alloc(shared_family->name, shared_family->share_type);
}

/*! \internal
 * \brief AO2 container sort function for \c ast_db_shared_family
 */
static int db_shared_family_sort_fn(const void *obj_left, const void *obj_right, int flags)
{
	const struct ast_db_shared_family *left = obj_left;
	const struct ast_db_shared_family *right = obj_right;
	const char *right_key = obj_right;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = right->name;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(left->name, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		cmp = strncmp(left->name, right_key, strlen(right_key));
		break;
	default:
		ast_assert(0);
		cmp = 0;
		break;
	}
	return cmp;
}

static int db_create_astdb(void)
{
	int res = 0;

	if (!create_astdb_stmt) {
		init_stmt(&create_astdb_stmt, create_astdb_stmt_sql, sizeof(create_astdb_stmt_sql));
	}

	ast_mutex_lock(&dblock);
	if (sqlite3_step(create_astdb_stmt) != SQLITE_DONE) {
		ast_log(LOG_WARNING, "Couldn't create astdb table: %s\n", sqlite3_errmsg(astdb));
		res = -1;
	}
	sqlite3_reset(create_astdb_stmt);
	db_sync();
	ast_mutex_unlock(&dblock);

	return res;
}

static int db_open(void)
{
	char *dbname;
	struct stat dont_care;

	if (!(dbname = ast_alloca(strlen(ast_config_AST_DB) + sizeof(".sqlite3")))) {
		return -1;
	}
	strcpy(dbname, ast_config_AST_DB);
	strcat(dbname, ".sqlite3");

	if (stat(dbname, &dont_care) && !stat(ast_config_AST_DB, &dont_care)) {
		if (convert_bdb_to_sqlite3()) {
			ast_log(LOG_ERROR, "*** Database conversion failed!\n");
			ast_log(LOG_ERROR, "*** Asterisk now uses SQLite3 for its internal\n");
			ast_log(LOG_ERROR, "*** database. Conversion from the old astdb\n");
			ast_log(LOG_ERROR, "*** failed. Most likely the astdb2sqlite3 utility\n");
			ast_log(LOG_ERROR, "*** was not selected for build. To convert the\n");
			ast_log(LOG_ERROR, "*** old astdb, please delete '%s'\n", dbname);
			ast_log(LOG_ERROR, "*** and re-run 'make menuselect' and select astdb2sqlite3\n");
			ast_log(LOG_ERROR, "*** in the Utilities section, then 'make && make install'.\n");
			ast_log(LOG_ERROR, "*** It is also imperative that the user under which\n");
			ast_log(LOG_ERROR, "*** Asterisk runs have write permission to the directory\n");
			ast_log(LOG_ERROR, "*** where the database resides.\n");
			sleep(5);
		} else {
			ast_log(LOG_NOTICE, "Database conversion succeeded!\n");
		}
	}

	ast_mutex_lock(&dblock);
	if (sqlite3_open(dbname, &astdb) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Unable to open Asterisk database '%s': %s\n", dbname, sqlite3_errmsg(astdb));
		sqlite3_close(astdb);
		ast_mutex_unlock(&dblock);
		return -1;
	}

	ast_mutex_unlock(&dblock);

	return 0;
}

static int db_init(void)
{
	if (astdb) {
		return 0;
	}

	if (db_open() || db_create_astdb() || init_statements()) {
		return -1;
	}

	return 0;
}

/* We purposely don't lock around the sqlite3 call because the transaction
 * calls will be called with the database lock held. For any other use, make
 * sure to take the dblock yourself. */
static int db_execute_sql(const char *sql, int (*callback)(void *, int, char **, char **), void *arg)
{
	char *errmsg = NULL;
	int res =0;

	if (sqlite3_exec(astdb, sql, callback, arg, &errmsg) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Error executing SQL (%s): %s\n", sql, errmsg);
		sqlite3_free(errmsg);
		res = -1;
	}

	return res;
}

static int ast_db_begin_transaction(void)
{
	return db_execute_sql("BEGIN TRANSACTION", NULL, NULL);
}

static int ast_db_commit_transaction(void)
{
	return db_execute_sql("COMMIT", NULL, NULL);
}

static int ast_db_rollback_transaction(void)
{
	return db_execute_sql("ROLLBACK", NULL, NULL);
}

static int db_put_common(const char *family, const char *key, const char *value, int share);

int ast_db_put_shared(const char *family, enum ast_db_shared_type share_type)
{
	struct ast_db_shared_family *shared_family;

	if (ast_strlen_zero(family)) {
		return -1;
	}

	ao2_lock(shared_families);

	shared_family = ao2_find(shared_families, family, OBJ_SEARCH_KEY | OBJ_NOLOCK);
	if (shared_family) {
		ao2_ref(shared_family, -1);
		ao2_unlock(shared_families);
		return -1;
	}

	shared_family = ast_db_shared_family_alloc(family, share_type);
	if (!shared_family) {
		ao2_unlock(shared_families);
		return -1;
	}

	ao2_link_flags(shared_families, shared_family, OBJ_NOLOCK);
	ao2_unlock(shared_families);

	db_put_common(SHARED_FAMILY, shared_family->name,
		share_type == DB_SHARE_TYPE_UNIQUE ? "UNIQUE" : "GLOBAL", 0);

	ao2_ref(shared_family, -1);

	return 0;
}

int ast_db_is_shared(const char *family)
{
	struct ast_db_shared_family *shared_family;
	int res = 0;

	shared_family = ao2_find(shared_families, family, OBJ_SEARCH_KEY);
	if (shared_family) {
		res = 1;
		ao2_ref(shared_family, -1);
	}

	return res;
}

/*!
 * \internal
 * \brief Update remote instances that a shared family key/value was updated
 *
 * \param family The AstDB family
 * \param key The AstDB key
 * \param value The AstDB value
 *
 * \retval 0 entry was processed successfully
 * \retval -1 error
 */
static int db_entry_put_shared(const char *family, const char *key, const char *value)
{
	struct ast_db_shared_family *shared_family;
	struct ast_db_shared_family *clone;

	/* See if we are shared */
	shared_family = ao2_find(shared_families, family, OBJ_SEARCH_KEY);
	if (!shared_family) {
		return 0;
	}

	/* Create a Stasis message for the new item */
	clone = db_shared_family_clone(shared_family);
	if (!clone) {
		ao2_ref(shared_family, -1);
		return -1;
	}
	clone->entries = ast_db_entry_create(key, value);
	if (!clone->entries) {
		ao2_ref(shared_family, -1);
		ao2_ref(clone, -1);
		return -1;
	}

	/* Publish */
	ast_db_publish_shared_message(ast_db_put_shared_type(), clone, NULL);

	ao2_ref(shared_family, -1);
	ao2_ref(clone, -1);

	return 0;
}

/*!
 * \internal
 * \brief Update remote instances that a shared family key/value was deleted
 *
 * \param family The AstDB family
 * \param key The AstDB key
 * \param value The AstDB value
 *
 * \retval 0 entry was processed successfully
 * \retval -1 error
 */
static int db_entry_del_shared(const char *family, const char *key)
{
	struct ast_db_shared_family *shared_family;
	struct ast_db_shared_family *clone;

	/* See if we are shared */
	shared_family = ao2_find(shared_families, family, OBJ_SEARCH_KEY);
	if (!shared_family) {
		return 0;
	}

	if (ast_strlen_zero(key)) {
		clone = ao2_bump(shared_family);
	} else {
		clone = db_shared_family_clone(shared_family);
		if (!clone) {
			ao2_ref(shared_family, -1);
			return -1;
		}
		clone->entries = ast_db_entry_create(key, "");
		if (!clone->entries) {
			ao2_ref(shared_family, -1);
			ao2_ref(clone, -1);
			return -1;
		}
	}

	/* Publish */
	ast_db_publish_shared_message(ast_db_del_shared_type(), clone, NULL);

	ao2_ref(shared_family, -1);
	ao2_ref(clone, -1);

	return 0;
}

static int db_del_common(const char *family, const char *key, int share);

int ast_db_del_shared(const char *family)
{
	struct ast_db_shared_family *shared_family;
	int res = 0;

	if (ast_strlen_zero(family)) {
		return -1;
	}

	ao2_lock(shared_families);

	shared_family = ao2_find(shared_families, family, OBJ_SEARCH_KEY | OBJ_NOLOCK);
	if (shared_family) {
		ao2_unlink_flags(shared_families, shared_family, OBJ_NOLOCK);
		ao2_unlock(shared_families);

		db_del_common(SHARED_FAMILY, shared_family->name, 0);
		ao2_ref(shared_family, -1);
	} else {
		ao2_unlock(shared_families);
		res = -1;
	}

	return res;
}

/*!
 * \internal
 * \brief Common routine to update an entry in the AstDB
 *
 * \param family The AstDB family
 * \param key The AstDB key
 * \param value The AstDB value
 * \param share If non-zero, try to inform other instances that the key was updated
 *
 * \retval 0 success
 * \retval -1 error
 */
static int db_put_common(const char *family, const char *key, const char *value, int share)
{
	char fullkey[MAX_DB_FIELD];
	size_t fullkey_len;
	int res = 0;

	if (strlen(family) + strlen(key) + 2 > sizeof(fullkey) - 1) {
		ast_log(LOG_WARNING, "Family and key length must be less than %zu bytes\n", sizeof(fullkey) - 3);
		return -1;
	}

	fullkey_len = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, key);

	ast_mutex_lock(&dblock);
	if (sqlite3_bind_text(put_stmt, 1, fullkey, fullkey_len, SQLITE_STATIC) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Couldn't bind key to stmt: %s\n", sqlite3_errmsg(astdb));
		res = -1;
	} else if (sqlite3_bind_text(put_stmt, 2, value, -1, SQLITE_STATIC) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Couldn't bind value to stmt: %s\n", sqlite3_errmsg(astdb));
		res = -1;
	} else if (sqlite3_step(put_stmt) != SQLITE_DONE) {
		ast_log(LOG_WARNING, "Couldn't execute statment: %s\n", sqlite3_errmsg(astdb));
		res = -1;
	}

	sqlite3_reset(put_stmt);
	db_sync();
	if (share) {
		db_entry_put_shared(family, key, value);
	}
	ast_mutex_unlock(&dblock);

	return res;
}

int ast_db_put(const char *family, const char *key, const char *value)
{
	return db_put_common(family, key, value, 1);
}

/*!
 * \internal
 * \brief Get key value specified by family/key.
 *
 * Gets the value associated with the specified \a family and \a key, and
 * stores it, either into the fixed sized buffer specified by \a buffer
 * and \a bufferlen, or as a heap allocated string if \a bufferlen is -1.
 *
 * \note If \a bufferlen is -1, \a buffer points to heap allocated memory
 *       and must be freed by calling ast_free().
 *
 * \retval -1 An error occurred
 * \retval 0 Success
 */
static int db_get_common(const char *family, const char *key, char **buffer, int bufferlen)
{
	const unsigned char *result;
	char fullkey[MAX_DB_FIELD];
	size_t fullkey_len;
	int res = 0;

	if (strlen(family) + strlen(key) + 2 > sizeof(fullkey) - 1) {
		ast_log(LOG_WARNING, "Family and key length must be less than %zu bytes\n", sizeof(fullkey) - 3);
		return -1;
	}

	fullkey_len = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, key);

	ast_mutex_lock(&dblock);
	if (sqlite3_bind_text(get_stmt, 1, fullkey, fullkey_len, SQLITE_STATIC) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Couldn't bind key to stmt: %s\n", sqlite3_errmsg(astdb));
		res = -1;
	} else if (sqlite3_step(get_stmt) != SQLITE_ROW) {
		ast_debug(1, "Unable to find key '%s' in family '%s'\n", key, family);
		res = -1;
	} else if (!(result = sqlite3_column_text(get_stmt, 0))) {
		ast_log(LOG_WARNING, "Couldn't get value\n");
		res = -1;
	} else {
		const char *value = (const char *) result;

		if (bufferlen == -1) {
			*buffer = ast_strdup(value);
		} else {
			ast_copy_string(*buffer, value, bufferlen);
		}
	}
	sqlite3_reset(get_stmt);
	ast_mutex_unlock(&dblock);

	return res;
}

int ast_db_get(const char *family, const char *key, char *value, int valuelen)
{
	ast_assert(value != NULL);

	/* Make sure we initialize */
	value[0] = 0;

	return db_get_common(family, key, &value, valuelen);
}

int ast_db_get_allocated(const char *family, const char *key, char **out)
{
	*out = NULL;

	return db_get_common(family, key, out, -1);
}

/*!
 * \internal
 * \brief Common routine to delete an entry in the AstDB
 *
 * \param family The AstDB family
 * \param key The AstDB key
 * \param share If non-zero, try to inform other instances that the key was deleted
 *
 * \retval 0 success
 * \retval -1 error
 */
static int db_del_common(const char *family, const char *key, int share)
{
	char fullkey[MAX_DB_FIELD];
	size_t fullkey_len;
	int res = 0;

	if (strlen(family) + strlen(key) + 2 > sizeof(fullkey) - 1) {
		ast_log(LOG_WARNING, "Family and key length must be less than %zu bytes\n", sizeof(fullkey) - 3);
		return -1;
	}

	fullkey_len = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, key);

	ast_mutex_lock(&dblock);
	if (sqlite3_bind_text(del_stmt, 1, fullkey, fullkey_len, SQLITE_STATIC) != SQLITE_OK) {
		ast_log(LOG_WARNING, "Couldn't bind key to stmt: %s\n", sqlite3_errmsg(astdb));
		res = -1;
	} else if (sqlite3_step(del_stmt) != SQLITE_DONE) {
		ast_debug(1, "Unable to find key '%s' in family '%s'\n", key, family);
		res = -1;
	}
	sqlite3_reset(del_stmt);
	db_sync();
	if (share) {
		db_entry_del_shared(family, key);
	}
	ast_mutex_unlock(&dblock);

	return res;
}

int ast_db_del(const char *family, const char *key)
{
	return db_del_common(family, key, 1);
}

/*!
 * \internal
 * \brief Common routine to delete an entire tree in the AstDB
 *
 * \param family The AstDB family
 * \param key The AstDB key. May be NULL.
 * \param share If non-zero, try to inform other instances that the key was deleted
 *
 * \retval 0 success
 * \retval -1 error
 */
static int db_deltree_common(const char *family, const char *keytree, int share)
{
	sqlite3_stmt *stmt = deltree_stmt;
	char prefix[MAX_DB_FIELD];
	int res = 0;

	if (!ast_strlen_zero(family)) {
		if (!ast_strlen_zero(keytree)) {
			/* Family and key tree */
			snprintf(prefix, sizeof(prefix), "/%s/%s", family, keytree);
		} else {
			/* Family only */
			snprintf(prefix, sizeof(prefix), "/%s", family);
		}
	} else {
		prefix[0] = '\0';
		stmt = deltree_all_stmt;
	}

	ast_mutex_lock(&dblock);
	if (!ast_strlen_zero(prefix) && (sqlite3_bind_text(stmt, 1, prefix, -1, SQLITE_STATIC) != SQLITE_OK)) {
		ast_log(LOG_WARNING, "Could bind %s to stmt: %s\n", prefix, sqlite3_errmsg(astdb));
		res = -1;
	} else if (sqlite3_step(stmt) != SQLITE_DONE) {
		ast_log(LOG_WARNING, "Couldn't execute stmt: %s\n", sqlite3_errmsg(astdb));
		res = -1;
	}
	res = sqlite3_changes(astdb);
	sqlite3_reset(stmt);
	db_sync();
	if (share) {
		db_entry_del_shared(prefix, NULL);
	}
	ast_mutex_unlock(&dblock);

	return res;
}

int ast_db_deltree(const char *family, const char *keytree)
{
	return db_deltree_common(family, keytree, 1);
}

struct ast_db_entry *ast_db_gettree(const char *family, const char *keytree)
{
	char prefix[MAX_DB_FIELD];
	sqlite3_stmt *stmt = gettree_stmt;
	struct ast_db_entry *cur, *last = NULL, *ret = NULL;

	if (!ast_strlen_zero(family)) {
		if (!ast_strlen_zero(keytree)) {
			/* Family and key tree */
			snprintf(prefix, sizeof(prefix), "/%s/%s", family, keytree);
		} else {
			/* Family only */
			snprintf(prefix, sizeof(prefix), "/%s", family);
		}
	} else {
		prefix[0] = '\0';
		stmt = gettree_all_stmt;
	}

	ast_mutex_lock(&dblock);
	if (!ast_strlen_zero(prefix) && (sqlite3_bind_text(stmt, 1, prefix, -1, SQLITE_STATIC) != SQLITE_OK)) {
		ast_log(LOG_WARNING, "Could bind %s to stmt: %s\n", prefix, sqlite3_errmsg(astdb));
		sqlite3_reset(stmt);
		ast_mutex_unlock(&dblock);
		return NULL;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *key_s, *value_s;
		if (!(key_s = (const char *) sqlite3_column_text(stmt, 0))) {
			break;
		}
		if (!(value_s = (const char *) sqlite3_column_text(stmt, 1))) {
			break;
		}
		cur = ast_db_entry_create(key_s, value_s);
		if (!cur) {
			break;
		}
		if (last) {
			last->next = cur;
		} else {
			ret = cur;
		}
		last = cur;
	}
	sqlite3_reset(stmt);
	ast_mutex_unlock(&dblock);

	return ret;
}

void ast_db_freetree(struct ast_db_entry *dbe)
{
	struct ast_db_entry *last;
	while (dbe) {
		last = dbe;
		dbe = dbe->next;
		ast_free(last);
	}
}

static char *handle_cli_database_put(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int res;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database put";
		e->usage =
			"Usage: database put <family> <key> <value>\n"
			"       Adds or updates an entry in the Asterisk database for\n"
			"       a given family, key, and value.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 5)
		return CLI_SHOWUSAGE;
	res = ast_db_put(a->argv[2], a->argv[3], a->argv[4]);
	if (res)  {
		ast_cli(a->fd, "Failed to update entry\n");
	} else {
		ast_cli(a->fd, "Updated database successfully\n");
	}
	return CLI_SUCCESS;
}

static char *handle_cli_database_get(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int res;
	char tmp[MAX_DB_FIELD];

	switch (cmd) {
	case CLI_INIT:
		e->command = "database get";
		e->usage =
			"Usage: database get <family> <key>\n"
			"       Retrieves an entry in the Asterisk database for a given\n"
			"       family and key.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4)
		return CLI_SHOWUSAGE;
	res = ast_db_get(a->argv[2], a->argv[3], tmp, sizeof(tmp));
	if (res) {
		ast_cli(a->fd, "Database entry not found.\n");
	} else {
		ast_cli(a->fd, "Value: %s\n", tmp);
	}
	return CLI_SUCCESS;
}

static char *handle_cli_database_del(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int res;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database del";
		e->usage =
			"Usage: database del <family> <key>\n"
			"       Deletes an entry in the Asterisk database for a given\n"
			"       family and key.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4)
		return CLI_SHOWUSAGE;
	res = ast_db_del(a->argv[2], a->argv[3]);
	if (res) {
		ast_cli(a->fd, "Database entry does not exist.\n");
	} else {
		ast_cli(a->fd, "Database entry removed.\n");
	}
	return CLI_SUCCESS;
}

static char *handle_cli_database_put_shared(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int res;
	enum ast_db_shared_type share_type;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database put shared";
		e->usage =
			"Usage: database put shared <family> <type>\n"
			"       Creates a new shared family of the given type,\n"
			"       where type is either 'unique' or 'global'.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 5) {
		return CLI_SHOWUSAGE;
	}

	if (!strcasecmp(a->argv[4], "unique")) {
		share_type = DB_SHARE_TYPE_UNIQUE;
	} else if (!strcasecmp(a->argv[4], "global")) {
		share_type = DB_SHARE_TYPE_GLOBAL;
	} else {
		ast_cli(a->fd, "Unknown share type: '%s'\n", a->argv[4]);
		return CLI_SUCCESS;
	}

	res = ast_db_put_shared(a->argv[3], share_type);
	if (res) {
		ast_cli(a->fd, "Could not share family '%s' (is it already shared?)\n", a->argv[3]);
	} else {
		ast_cli(a->fd, "Shared database family '%s'.\n", a->argv[3]);
	}
	return CLI_SUCCESS;
}

static char *handle_cli_database_del_shared(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int res;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database del shared";
		e->usage =
			"Usage: database del shared <family>\n"
			"       Deletes the shared status of a database family.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}
	res = ast_db_del_shared(a->argv[3]);
	if (res) {
		ast_cli(a->fd, "Shared family '%s' does not exist.\n", a->argv[3]);
	} else {
		ast_cli(a->fd, "Shared database family '%s' removed.\n", a->argv[3]);
	}
	return CLI_SUCCESS;
}
static char *handle_cli_database_deltree(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int num_deleted;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database deltree";
		e->usage =
			"Usage: database deltree <family> [keytree]\n"
			"   OR: database deltree <family>[/keytree]\n"
			"       Deletes a family or specific keytree within a family\n"
			"       in the Asterisk database.  The two arguments may be\n"
			"       separated by either a space or a slash.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if ((a->argc < 3) || (a->argc > 4))
		return CLI_SHOWUSAGE;
	if (a->argc == 4) {
		num_deleted = ast_db_deltree(a->argv[2], a->argv[3]);
	} else {
		num_deleted = ast_db_deltree(a->argv[2], NULL);
	}
	if (num_deleted < 0) {
		ast_cli(a->fd, "Database unavailable.\n");
	} else if (num_deleted == 0) {
		ast_cli(a->fd, "Database entries do not exist.\n");
	} else {
		ast_cli(a->fd, "%d database entries removed.\n",num_deleted);
	}
	return CLI_SUCCESS;
}

/*! \internal \brief Helper for CLI commands that print the AstDB */
static int print_database_show(struct ast_cli_args *a, sqlite3_stmt *stmt)
{
	int counter = 0;

	ast_cli(a->fd, "%-50s: %-25s %s\n", "Key", "Data", "Shared");
	ast_cli(a->fd, "--------------------------------------------------  ------------------------- ------\n");
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		struct ast_db_shared_family *shared_family;
		const char *key_s;
		const char *value_s;
		char *family_s;
		char *delim;

		if (!(key_s = (const char *) sqlite3_column_text(stmt, 0))) {
			break;
		}
		if (!(value_s = (const char *) sqlite3_column_text(stmt, 1))) {
			break;
		}
		family_s = ast_strdup(key_s);
		if (!family_s) {
			break;
		}
		delim = strchr(family_s + 1, '/');
		*delim = '\0';

		shared_family = ao2_find(shared_families, family_s + 1, OBJ_SEARCH_KEY);

		++counter;
		ast_cli(a->fd, "%-50s: %-25s %s\n", key_s, value_s,
			shared_family ? (shared_family->share_type == DB_SHARE_TYPE_UNIQUE ? "(U)" : "(G)") : "");

		ao2_cleanup(shared_family);
		ast_free(family_s);
	}

	return counter;
}

static char *handle_cli_database_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char prefix[MAX_DB_FIELD];
	int counter = 0;
	sqlite3_stmt *stmt = gettree_stmt;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database show";
		e->usage =
			"Usage: database show [family [keytree]]\n"
			"   OR: database show [family[/keytree]]\n"
			"       Shows Asterisk database contents, optionally restricted\n"
			"       to a given family, or family and keytree. The two arguments\n"
			"       may be separated either by a space or by a slash.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc == 4) {
		/* Family and key tree */
		snprintf(prefix, sizeof(prefix), "/%s/%s", a->argv[2], a->argv[3]);
	} else if (a->argc == 3) {
		/* Family only */
		snprintf(prefix, sizeof(prefix), "/%s", a->argv[2]);
	} else if (a->argc == 2) {
		/* Neither */
		prefix[0] = '\0';
		stmt = gettree_all_stmt;

	} else {
		return CLI_SHOWUSAGE;
	}

	ast_mutex_lock(&dblock);
	if (!ast_strlen_zero(prefix) && (sqlite3_bind_text(stmt, 1, prefix, -1, SQLITE_STATIC) != SQLITE_OK)) {
		ast_log(LOG_WARNING, "Could bind %s to stmt: %s\n", prefix, sqlite3_errmsg(astdb));
		sqlite3_reset(stmt);
		ast_mutex_unlock(&dblock);
		return NULL;
	}

	counter = print_database_show(a, stmt);

	sqlite3_reset(stmt);
	ast_mutex_unlock(&dblock);

	ast_cli(a->fd, "%d results found.\n", counter);
	return CLI_SUCCESS;
}

static char *handle_cli_database_showkey(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int counter = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database showkey";
		e->usage =
			"Usage: database showkey <keytree>\n"
			"       Shows Asterisk database contents, restricted to a given key.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	ast_mutex_lock(&dblock);
	if (!ast_strlen_zero(a->argv[2]) && (sqlite3_bind_text(showkey_stmt, 1, a->argv[2], -1, SQLITE_STATIC) != SQLITE_OK)) {
		ast_log(LOG_WARNING, "Could bind %s to stmt: %s\n", a->argv[2], sqlite3_errmsg(astdb));
		sqlite3_reset(showkey_stmt);
		ast_mutex_unlock(&dblock);
		return NULL;
	}

	counter = print_database_show(a, showkey_stmt);

	sqlite3_reset(showkey_stmt);
	ast_mutex_unlock(&dblock);

	ast_cli(a->fd, "%d results found.\n", counter);
	return CLI_SUCCESS;
}

static int display_results(void *arg, int columns, char **values, char **colnames)
{
	struct ast_cli_args *a = arg;
	size_t x;

	for (x = 0; x < columns; x++) {
		ast_cli(a->fd, "%-5s: %-50s\n", colnames[x], values[x]);
	}
	ast_cli(a->fd, "\n");

	return 0;
}

static char *handle_cli_database_query(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{

	switch (cmd) {
	case CLI_INIT:
		e->command = "database query";
		e->usage =
			"Usage: database query \"<SQL Statement>\"\n"
			"       Run a user-specified SQL query on the database. Be careful.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	ast_mutex_lock(&dblock);
	db_execute_sql(a->argv[2], display_results, a);
	db_sync(); /* Go ahead and sync the db in case they write */
	ast_mutex_unlock(&dblock);

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_database[] = {
	AST_CLI_DEFINE(handle_cli_database_show,       "Shows database contents"),
	AST_CLI_DEFINE(handle_cli_database_showkey,    "Shows database contents"),
	AST_CLI_DEFINE(handle_cli_database_get,        "Gets database value"),
	AST_CLI_DEFINE(handle_cli_database_put,        "Adds/updates database value"),
	AST_CLI_DEFINE(handle_cli_database_del,        "Removes database key/value"),
	AST_CLI_DEFINE(handle_cli_database_put_shared, "Add a shared family"),
	AST_CLI_DEFINE(handle_cli_database_del_shared, "Remove a shared family"),
	AST_CLI_DEFINE(handle_cli_database_deltree,    "Removes database keytree/values"),
	AST_CLI_DEFINE(handle_cli_database_query,      "Run a user-specified query on the astdb"),
};

static int manager_dbput(struct mansession *s, const struct message *m)
{
	const char *family = astman_get_header(m, "Family");
	const char *key = astman_get_header(m, "Key");
	const char *val = astman_get_header(m, "Val");
	int res;

	if (ast_strlen_zero(family)) {
		astman_send_error(s, m, "No family specified");
		return 0;
	}
	if (ast_strlen_zero(key)) {
		astman_send_error(s, m, "No key specified");
		return 0;
	}

	res = ast_db_put(family, key, S_OR(val, ""));
	if (res) {
		astman_send_error(s, m, "Failed to update entry");
	} else {
		astman_send_ack(s, m, "Updated database successfully");
	}
	return 0;
}

static int manager_dbget(struct mansession *s, const struct message *m)
{
	const char *id = astman_get_header(m,"ActionID");
	char idText[256];
	const char *family = astman_get_header(m, "Family");
	const char *key = astman_get_header(m, "Key");
	char tmp[MAX_DB_FIELD];
	int res;

	if (ast_strlen_zero(family)) {
		astman_send_error(s, m, "No family specified.");
		return 0;
	}
	if (ast_strlen_zero(key)) {
		astman_send_error(s, m, "No key specified.");
		return 0;
	}

	idText[0] = '\0';
	if (!ast_strlen_zero(id))
		snprintf(idText, sizeof(idText) ,"ActionID: %s\r\n", id);

	res = ast_db_get(family, key, tmp, sizeof(tmp));
	if (res) {
		astman_send_error(s, m, "Database entry not found");
	} else {
		astman_send_listack(s, m, "Result will follow", "start");

		astman_append(s, "Event: DBGetResponse\r\n"
				"Family: %s\r\n"
				"Key: %s\r\n"
				"Val: %s\r\n"
				"%s"
				"\r\n",
				family, key, tmp, idText);

		astman_send_list_complete_start(s, m, "DBGetComplete", 1);
		astman_send_list_complete_end(s);
	}
	return 0;
}

static int manager_dbdel(struct mansession *s, const struct message *m)
{
	const char *family = astman_get_header(m, "Family");
	const char *key = astman_get_header(m, "Key");
	int res;

	if (ast_strlen_zero(family)) {
		astman_send_error(s, m, "No family specified.");
		return 0;
	}

	if (ast_strlen_zero(key)) {
		astman_send_error(s, m, "No key specified.");
		return 0;
	}

	res = ast_db_del(family, key);
	if (res)
		astman_send_error(s, m, "Database entry not found");
	else
		astman_send_ack(s, m, "Key deleted successfully");

	return 0;
}

static int manager_dbdeltree(struct mansession *s, const struct message *m)
{
	const char *family = astman_get_header(m, "Family");
	const char *key = astman_get_header(m, "Key");
	int num_deleted;

	if (ast_strlen_zero(family)) {
		astman_send_error(s, m, "No family specified.");
		return 0;
	}

	if (!ast_strlen_zero(key)) {
		num_deleted = ast_db_deltree(family, key);
	} else {
		num_deleted = ast_db_deltree(family, NULL);
	}

	if (num_deleted < 0) {
		astman_send_error(s, m, "Database unavailable");
	} else if (num_deleted == 0) {
		astman_send_error(s, m, "Database entry not found");
	} else {
		astman_send_ack(s, m, "Key tree deleted successfully");
	}

	return 0;
}

/*!
 * \internal
 * \brief Signal the astdb sync thread to do its thing.
 *
 * \note dblock is assumed to be held when calling this function.
 */
static void db_sync(void)
{
	dosync = 1;
	ast_cond_signal(&dbcond);
}

/*!
 * \internal
 * \brief astdb sync thread
 *
 * This thread is in charge of syncing astdb to disk after a change.
 * By pushing it off to this thread to take care of, this I/O bound operation
 * will not block other threads from performing other critical processing.
 * If changes happen rapidly, this thread will also ensure that the sync
 * operations are rate limited.
 */
static void *db_sync_thread(void *data)
{
	ast_mutex_lock(&dblock);
	ast_db_begin_transaction();
	for (;;) {
		/* If dosync is set, db_sync() was called during sleep(1), 
		 * and the pending transaction should be committed. 
		 * Otherwise, block until db_sync() is called.
		 */
		while (!dosync) {
			ast_cond_wait(&dbcond, &dblock);
		}
		dosync = 0;
		if (ast_db_commit_transaction()) {
			ast_db_rollback_transaction();
		}
		if (doexit) {
			ast_mutex_unlock(&dblock);
			break;
		}
		ast_db_begin_transaction();
		ast_mutex_unlock(&dblock);
		sleep(1);
		ast_mutex_lock(&dblock);
	}

	return NULL;
}

int ast_db_publish_shared_message(struct stasis_message_type *type,
	struct ast_db_shared_family *shared_family, struct ast_eid *eid)
{
	struct stasis_message *message;

	/* Aggregate doesn't really apply to the AstDB; as such, if we aren't
	 * provided an EID use our own.
	 */
	if (!eid) {
		eid = &ast_eid_default;
	}

	message = stasis_message_create_full(type, shared_family, eid);
	if (!message) {
		return -1;
	}
	stasis_publish(ast_db_cluster_topic(), message);

	return 0;
}

void ast_db_refresh_shared(void)
{
	struct ao2_iterator it_shared_families;
	struct ast_db_shared_family *shared_family;

	it_shared_families = ao2_iterator_init(shared_families, 0);
	while ((shared_family = ao2_iterator_next(&it_shared_families))) {
		struct ast_db_shared_family *clone;

		clone = db_shared_family_clone(shared_family);
		if (!clone) {
			ao2_ref(shared_family, -1);
			continue;
		}

		clone->entries = ast_db_gettree(shared_family->name, "");
		if (!clone->entries) {
			ao2_ref(clone, -1);
			ao2_ref(shared_family, -1);
			continue;
		}
		ast_db_publish_shared_message(ast_db_put_shared_type(), clone, NULL);

		ao2_ref(clone, -1);
		ao2_ref(shared_family, -1);
	}
	ao2_iterator_destroy(&it_shared_families);
}

static struct ast_json *db_entries_to_json(struct ast_db_entry *entry)
{
	struct ast_json *json;
	struct ast_db_entry *cur;

	if (!entry) {
		return ast_json_null();
	}

	json = ast_json_array_create();
	if (!json) {
		return NULL;
	}

	for (cur = entry; cur; cur = cur->next) {
		struct ast_json *json_entry;

		json_entry = ast_json_pack("{s: s, s: s}",
			"key", cur->key,
			"data", cur->data);
		if (!json_entry) {
			ast_json_unref(json);
			return NULL;
		}

		if (ast_json_array_append(json, json_entry)) {
			ast_json_unref(json);
			return NULL;
		}
	}

	return json;
}

static struct ast_json *db_shared_family_to_json(struct stasis_message *message,
	const struct stasis_message_sanitizer *sanitize)
{
	struct stasis_message_type *type = stasis_message_type(message);
	struct ast_db_shared_family *shared_family;
	struct ast_json *entries;

	if (type != ast_db_put_shared_type() && type != ast_db_del_shared_type()) {
		return NULL;
	}

	shared_family = stasis_message_data(message);
	if (!shared_family) {
		return NULL;
	}

	entries = db_entries_to_json(shared_family->entries);
	if (!entries) {
		return NULL;
	}

	return ast_json_pack("{s: s, s: s, s: s, s: o}",
		"verb", type == ast_db_put_shared_type() ? "put" : "delete",
		"family", shared_family->name,
		"share_type", shared_family->share_type == DB_SHARE_TYPE_UNIQUE ? "unique" : "global",
		"entries", entries);
}

struct stasis_topic *ast_db_cluster_topic(void)
{
	return db_cluster_topic;
}

STASIS_MESSAGE_TYPE_DEFN(ast_db_put_shared_type,
		.to_json = db_shared_family_to_json,
	);
STASIS_MESSAGE_TYPE_DEFN(ast_db_del_shared_type,
		.to_json = db_shared_family_to_json,
	);

/*! \internal
 * \brief Stasis message callback for external updates to AstDB shared families
 */
static void db_put_shared_msg_cb(void *data, struct stasis_subscription *sub, struct stasis_message *message)
{
	struct ast_db_shared_family *shared_family;
	struct ast_db_shared_family *shared_check;
	struct ast_db_entry *cur;
	const struct ast_eid *eid;
	char *family_id;

	shared_family = stasis_message_data(message);
	if (!shared_family) {
		return;
	}

	/* Pass on any updates that originated from ourselves */
	eid = stasis_message_eid(message);
	if (!eid || !ast_eid_cmp(eid, &ast_eid_default)) {
		return;
	}

	/* Don't update if we don't have this area shared on this server */
	shared_check = ao2_find(shared_families, shared_family->name, OBJ_SEARCH_KEY);
	if (!shared_check) {
		return;
	}
	ao2_ref(shared_check, -1);

	if (shared_family->share_type == DB_SHARE_TYPE_UNIQUE) {
		char eid_workspace[20];

		/* Length is family + '/' + EID length (20) + 1 */
		family_id = ast_alloca(strlen(shared_family->name) + 22);
		ast_eid_to_str(eid_workspace, sizeof(eid_workspace), eid);
		sprintf(family_id, "%s/%s", eid_workspace, shared_family->name); /* safe */
	} else {
		family_id = shared_family->name;
	}

	for (cur = shared_family->entries; cur; cur = cur->next) {
		db_put_common(family_id, cur->key, cur->data, 0);
	}
}

/*! \internal
 * \brief Stasis message callback for external deletes to AstDB shared families
 */
static void db_del_shared_msg_cb(void *data, struct stasis_subscription *sub, struct stasis_message *message)
{
	struct ast_db_shared_family *shared_family;
	struct ast_db_entry *cur;
	const struct ast_eid *eid;

	shared_family = stasis_message_data(message);
	if (!shared_family) {
		return;
	}

	/* Pass on any updates that originated from ourselves */
	eid = stasis_message_eid(message);
	if (!eid || !ast_eid_cmp(eid, &ast_eid_default)) {
		return;
	}

	cur = shared_family->entries;
	if (!cur) {
		db_deltree_common(shared_family->name, NULL, 0);
		return;
	}

	for (; cur; cur = cur->next) {
		db_del_common(shared_family->name, cur->key, 0);
	}
}

/*!
 * \internal
 * \brief Clean up resources on Asterisk shutdown
 */
static void astdb_atexit(void)
{
	ast_cli_unregister_multiple(cli_database, ARRAY_LEN(cli_database));
	ast_manager_unregister("DBGet");
	ast_manager_unregister("DBPut");
	ast_manager_unregister("DBDel");
	ast_manager_unregister("DBDelTree");

	stasis_message_router_unsubscribe_and_join(message_router);
	message_router = NULL;
	ao2_ref(db_cluster_topic, -1);
	db_cluster_topic = NULL;
	STASIS_MESSAGE_TYPE_CLEANUP(ast_db_put_shared_type);
	STASIS_MESSAGE_TYPE_CLEANUP(ast_db_del_shared_type);

	/* Set doexit to 1 to kill thread. db_sync must be called with
	 * mutex held. */
	ast_mutex_lock(&dblock);
	doexit = 1;
	db_sync();
	ast_mutex_unlock(&dblock);

	pthread_join(syncthread, NULL);
	ast_mutex_lock(&dblock);

	ao2_ref(shared_families, -1);
	shared_families = NULL;

	clean_statements();
	if (sqlite3_close(astdb) == SQLITE_OK) {
		astdb = NULL;
	}
	ast_mutex_unlock(&dblock);
}

/*! \internal
 * \brief Rebuild shared families from any stored in the AstDB
 */
static void restore_shared_families(void)
{
	struct ast_db_entry *entry;
	struct ast_db_entry *cur;

	entry = ast_db_gettree(SHARED_FAMILY, "");
	for (cur = entry; cur; cur = cur->next) {
		enum ast_db_shared_type share_type;
		const char *family;

		/* Find the 'key', which is the name of the shared family */
		family = strchr(cur->key + 1, '/');
		if (!family) {
			continue;
		}
		family++;

		if (!strcasecmp(cur->data, "unique")) {
			share_type = DB_SHARE_TYPE_UNIQUE;
		} else if (!strcasecmp(cur->data, "global")) {
			share_type = DB_SHARE_TYPE_GLOBAL;
		} else {
			continue;
		}

		ast_db_put_shared(family, share_type);
	}

	ast_db_freetree(entry);
}

int astdb_init(void)
{
	shared_families = ao2_container_alloc_rbtree(AO2_ALLOC_OPT_LOCK_MUTEX,
		AO2_CONTAINER_ALLOC_OPT_DUPS_REJECT | AO2_CONTAINER_ALLOC_OPT_DUPS_OBJ_REJECT,
		db_shared_family_sort_fn, NULL);
	if (!shared_families) {
		return -1;
	}

	db_cluster_topic = stasis_topic_create("ast_db_cluster_topic");
	if (!db_cluster_topic) {
		goto error_cleanup;
	}

	STASIS_MESSAGE_TYPE_INIT(ast_db_put_shared_type);
	STASIS_MESSAGE_TYPE_INIT(ast_db_del_shared_type);

	message_router = stasis_message_router_create_pool(ast_db_cluster_topic());
	if (!message_router) {
		goto error_cleanup;
	}
	stasis_message_router_add(message_router, ast_db_put_shared_type(),
		db_put_shared_msg_cb, NULL);
	stasis_message_router_add(message_router, ast_db_del_shared_type(),
		db_del_shared_msg_cb, NULL);

	if (db_init()) {
		goto error_cleanup;
	}

	restore_shared_families();

	ast_cond_init(&dbcond, NULL);
	if (ast_pthread_create_background(&syncthread, NULL, db_sync_thread, NULL)) {
		goto error_cleanup;
	}

	ast_register_atexit(astdb_atexit);
	ast_cli_register_multiple(cli_database, ARRAY_LEN(cli_database));
	ast_manager_register_xml_core("DBGet", EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_dbget);
	ast_manager_register_xml_core("DBPut", EVENT_FLAG_SYSTEM, manager_dbput);
	ast_manager_register_xml_core("DBDel", EVENT_FLAG_SYSTEM, manager_dbdel);
	ast_manager_register_xml_core("DBDelTree", EVENT_FLAG_SYSTEM, manager_dbdeltree);
	return 0;

error_cleanup:
	stasis_message_router_unsubscribe_and_join(message_router);
	ao2_cleanup(db_cluster_topic);
	STASIS_MESSAGE_TYPE_CLEANUP(ast_db_put_shared_type);
	STASIS_MESSAGE_TYPE_CLEANUP(ast_db_del_shared_type);
	ao2_cleanup(shared_families);
	return -1;
}
