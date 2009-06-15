/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
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
 * \note DB3 is licensed under Sleepycat Public License and is thus incompatible
 * with GPL.  To avoid having to make another exception (and complicate 
 * licensing even further) we elect to use DB1 which is BSD licensed 
 * 
 * \note AstDB realtime
 * AstDB realtime works with the basic operations - put, get, del
 * Database show also works.
 * 
 * The tree/family operations doesn't currently work. Maybe tree and family needs
 * to be separate fields in the database, instead of one single field as I've tried with.
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/_private.h"
#include "asterisk/paths.h"	/* use ast_config_AST_DB */
#include <sys/time.h>
#include <signal.h>
#include <dirent.h>

#include "asterisk/channel.h"
#include "asterisk/file.h"
#include "asterisk/app.h"
#include "asterisk/dsp.h"
#include "asterisk/astdb.h"
#include "asterisk/cli.h"
#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/manager.h"
#include "asterisk/config.h"
#include "db1-ast/include/db.h"

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

static DB *astdb;
AST_MUTEX_DEFINE_STATIC(dblock);

static int db_rt;			/*!< Flag for realtime system */
static char *db_rt_rtfamily = "astdb";	/*!< Realtime name tag */
static char *db_rt_value = "value";	/*!< Database field name for values */
static char *db_rt_family = "family";   /*!< Database field name for family */
static char *db_rt_key = "keyname";     /*!< Database field name for key */
static char *db_rt_sysnamelabel = "systemname"; /*!< Database field name for system name */
static const char *db_rt_sysname;       /*!< From asterisk.conf or "asterisk" */

/*! \brief Initialize either realtime support or Asterisk ast-db. 

	Note: Since realtime support is loaded after astdb, we can not do this early, but has to do the
	check on need. Now, there's a risk an internal module (not a loaded module) use astdb before 
	realtime is checked, but that's something we propably have to live with until we solve it.

	Make sure that realtime modules are loaded before dundi and the channels.
*/
static int dbinit(void) 
{
	if (db_rt) {
		return 0;
	}
	db_rt = ast_check_realtime(db_rt_rtfamily);
	if (!db_rt && !astdb && !(astdb = dbopen(ast_config_AST_DB, O_CREAT | O_RDWR, AST_FILE_MODE, DB_BTREE, NULL))) {
		ast_log(LOG_WARNING, "Unable to open Asterisk database '%s': %s\n", ast_config_AST_DB, strerror(errno));
		return -1;
	}
	return 0;
}

/*! \brief Load a set of entries from astdb/realtime. This is for all operations that
   	work on a whole "tree" or "family" 
	\note the calling function needs to destroy the result set with ast_config_destroy(resultset) 
*/
static struct ast_variable *db_realtime_getall(const char *family, const char *key)
{
	struct ast_variable *data, *returnset = NULL;
	const char *keyname = NULL, *familyname = NULL;
	struct ast_config *variablelist = NULL;
	const char *cat = NULL;
	char buf[512];

	ast_debug(2, ">>>>>> getall family: %s Key %s \n", family, key);

	if (ast_strlen_zero(family)) {
		/* Load all entries in the astdb */
		if (ast_strlen_zero(key)) {
			/* No variables given */
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, SENTINEL);
		} else {
			/* Only key given */
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_key, key, SENTINEL);
		}
	} else {
		if (ast_strlen_zero(key)) {
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, SENTINEL);
		} else {
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, key, SENTINEL);
		}
	}
	if (!variablelist) {
		return NULL;
	}
	/* Now we need to start converting all this stuff. We have thre ast_variable sets per record in the result set */
	while ((cat = ast_category_browse(variablelist, cat))) {
		struct ast_variable *resultset, *cur;

		cur = resultset = ast_variable_browse(variablelist, cat);
	
		/* skip the system name */
		while (cur) {
			ast_debug(2, ">>>> Found name %s ...\n", cur->name);
			if (!strcmp(cur->name, db_rt_family)) {
				familyname = cur->value;
			} else if (!strcmp(cur->name, db_rt_key)) {
				keyname = cur->value;
			} else if (!strcmp(cur->name, db_rt_value)) {
				snprintf(buf, sizeof(buf), "/%s/%s", S_OR(familyname, ""), S_OR(keyname, ""));
				data = ast_variable_new(buf, S_OR(cur->value, "astdb-realtime"), "");
				familyname = keyname = NULL;
				ast_debug(2, "#### Found Variable %s with value %s \n", buf, cur->value);
				/* Add this to the returnset */
				data->next = returnset;
				returnset = data;
			} else {
				if (ast_strlen_zero(cur->name)) {
					ast_debug(2, "#### Skipping  strange record \n");
				} else {
					ast_debug(2, "#### Skipping  %s with value %s \n", cur->name, cur->value);
				}
			}
			cur = cur->next;
		}
		//if (resultset)
			//ast_variables_destroy(resultset);
	}

	/* Clean up the resultset */
	ast_config_destroy(variablelist);
	
	return returnset;
}

static inline int keymatch(const char *key, const char *prefix)
{
	int preflen = strlen(prefix);
	if (!preflen)
		return 1;
	if (!strcasecmp(key, prefix))
		return 1;
	if ((strlen(key) > preflen) && !strncasecmp(key, prefix, preflen)) {
		if (key[preflen] == '/')
			return 1;
	}
	return 0;
}

static inline int subkeymatch(const char *key, const char *suffix)
{
	int suffixlen = strlen(suffix);
	if (suffixlen) {
		const char *subkey = key + strlen(key) - suffixlen;
		if (subkey < key)
			return 0;
		if (!strcasecmp(subkey, suffix))
			return 1;
	}
	return 0;
}

int ast_db_deltree(const char *family, const char *keytree)
{
	char prefix[256];
	DBT key, data;
	char *keys;
	int res;
	int pass;
	int counter = 0;
	
	if (family) {
		if (keytree) {
			snprintf(prefix, sizeof(prefix), "/%s/%s", family, keytree);
		} else {
			snprintf(prefix, sizeof(prefix), "/%s", family);
		}
	} else if (keytree) {
		return -1;
	} else {
		prefix[0] = '\0';
	}
	
	if (!db_rt) {
		ast_mutex_lock(&dblock);
		if (dbinit()) {
			ast_mutex_unlock(&dblock);
			return -1;
		}
		if (db_rt) {
			ast_mutex_unlock(&dblock);
		}
	}
	if (db_rt) {
		struct ast_variable *murderlist, *cur;
		cur = murderlist = db_realtime_getall(family, S_OR(keytree, ""));
		while (cur) {
			int res;
			char *familyname = ast_strdupa(&cur->name[1]);	/* Skip the first slash */
			char *keyname = familyname;
			familyname = strsep(&keyname, "/");

			res = ast_destroy_realtime(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, familyname, db_rt_key, keyname, SENTINEL);
			if (res >= 0)
				counter ++;
			cur = cur->next;
		}

		ast_variables_destroy(murderlist);
		
		return counter;
	}
	
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	pass = 0;
	while (!(res = astdb->seq(astdb, &key, &data, pass++ ? R_NEXT : R_FIRST))) {
		if (key.size) {
			keys = key.data;
			keys[key.size - 1] = '\0';
		} else {
			keys = "<bad key>";
		}
		if (keymatch(keys, prefix)) {
			astdb->del(astdb, &key, 0);
			counter++;
		}
	}
	astdb->sync(astdb, 0);
	ast_mutex_unlock(&dblock);
	return counter;
}

int ast_db_put(const char *family, const char *keys, const char *value)
{
	DBT key, data;
	int res;

	if (!db_rt) {
		ast_mutex_lock(&dblock);
		if (dbinit()) {
			ast_mutex_unlock(&dblock);
			return -1;
		}
		if (db_rt)
			ast_mutex_unlock(&dblock);
	}

	if (db_rt) {
		int rowsaffected ;
		/* Now, the question here is if we're overwriting or adding 
			First, let's try updating it.
		*/
		ast_debug(2, ".... Trying ast_update_realtime\n");
		/* Update_realtime with mysql returns the number of rows affected */
		rowsaffected = ast_update2_realtime(db_rt_rtfamily, db_rt_family, family, db_rt_key, keys, db_rt_sysnamelabel, db_rt_sysname, SENTINEL, db_rt_value, value, SENTINEL);
		res = rowsaffected > 0 ? 0 : 1;
		if (res) {
			ast_debug(2, ".... Trying ast_store_realtime\n");
			/* Update failed, let's try adding a new record */
			res = ast_store_realtime(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, keys, db_rt_value, value, SENTINEL);
			/* Ast_store_realtime with mysql returns 0 if ok, -1 if bad */

		}
	} else {
		int fullkeylen;
		char fullkey[256];
		fullkeylen = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, keys);
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.data = fullkey;
		key.size = fullkeylen + 1;
		data.data = (char *) value;
		data.size = strlen(value) + 1;
		res = astdb->put(astdb, &key, &data, 0);
		astdb->sync(astdb, 0);
	}
	ast_mutex_unlock(&dblock);
	if (res)
		ast_log(LOG_WARNING, "Unable to put value '%s' for key '%s' in family '%s'\n", value, keys, family);
	return res;
}

int ast_db_get(const char *family, const char *keys, char *value, int valuelen)
{
	char fullkey[256] = "";
	DBT key, data;
	int res, fullkeylen;

	if (!db_rt) {
		ast_mutex_lock(&dblock);
		if (dbinit()) {
			ast_mutex_unlock(&dblock);
			return -1;
		}
		if (db_rt) {
			ast_mutex_unlock(&dblock);
		}
	}

	if (db_rt) {
		struct ast_variable *var, *res;
		memset(value, 0, valuelen);

		res = var = ast_load_realtime(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, keys, SENTINEL);
		if (!var) {
			return 1;
		} 
		/* We should only have one value here, so let's make this simple... */
		while (res) {
			if (!strcasecmp(res->name, db_rt_value)) {
				ast_copy_string(value, res->value, (valuelen > strlen(res->value) ) ? strlen(res->value) +1: valuelen);
				res = NULL;
			} else {
				res = res->next;
			}
		}
		
		ast_variables_destroy(var);
		return 0;
	} 
	fullkeylen = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, keys);
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	memset(value, 0, valuelen);
	key.data = fullkey;
	key.size = fullkeylen + 1;

	res = astdb->get(astdb, &key, &data, 0);

	/* Be sure to NULL terminate our data either way */
	if (res) {
		ast_debug(1, "Unable to find key '%s' in family '%s'\n", keys, family);
	} else {
#if 0
		printf("Got value of size %d\n", data.size);
#endif
		if (data.size) {
			((char *)data.data)[data.size - 1] = '\0';
			/* Make sure that we don't write too much to the dst pointer or we don't read too much from the source pointer */
			ast_copy_string(value, data.data, (valuelen > data.size) ? data.size : valuelen);
		} else {
			ast_log(LOG_NOTICE, "Strange, empty value for /%s/%s\n", family, keys);
		}
	}

	/* Data is not fully isolated for concurrency, so the lock must be extended
	 * to after the copy to the output buffer. */
	ast_mutex_unlock(&dblock);

	return res;
}

int ast_db_del(const char *family, const char *keys)
{
	char fullkey[256];
	DBT key;
	int res, fullkeylen;

	if (!db_rt) {
		ast_mutex_lock(&dblock);
		if (dbinit()) {
			ast_mutex_unlock(&dblock);
			return -1;
		}
		if (db_rt)
			ast_mutex_unlock(&dblock);
	}
	
	if (db_rt) {
		int rowcount = ast_destroy_realtime(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, keys, SENTINEL);
		res = rowcount > 0 ? 0 : 1;
	} else {
		fullkeylen = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, keys);
		memset(&key, 0, sizeof(key));
		key.data = fullkey;
		key.size = fullkeylen + 1;
	
		res = astdb->del(astdb, &key, 0);
		astdb->sync(astdb, 0);
		ast_mutex_unlock(&dblock);
	}

	if (res) {
		ast_debug(1, "Unable to find key '%s' in family '%s'\n", keys, family);
	}
	return res;
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
	char tmp[256];

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

static char *handle_cli_database_deltree(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int res;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database deltree";
		e->usage =
			"Usage: database deltree <family> [keytree]\n"
			"       Deletes a family or specific keytree within a family\n"
			"       in the Asterisk database.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if ((a->argc < 3) || (a->argc > 4))
		return CLI_SHOWUSAGE;
	if (a->argc == 4) {
		res = ast_db_deltree(a->argv[2], a->argv[3]);
	} else {
		res = ast_db_deltree(a->argv[2], NULL);
	}
	if (res < 0) {
		ast_cli(a->fd, "Database entries do not exist.\n");
	} else {
		ast_cli(a->fd, "%d database entries removed.\n",res);
	}
	return CLI_SUCCESS;
}

static void handle_cli_database_show_realtime(struct ast_cli_args *a, const char *family, const char *key)
{
	struct ast_variable *resultset;
	struct ast_variable *cur;
	int counter = 0;

	dbinit();
	if (!db_rt) {
		ast_cli(a->fd, "Error: Can't connect to astdb/realtime\n");
		return;
	}

	cur = resultset = db_realtime_getall(family, key);
	while (cur) {
		ast_cli(a->fd, "%-40s: %-25s\n", cur->name, S_OR(cur->value, ""));
		cur = cur->next;
		counter++;
	}
	ast_cli(a->fd, "%d results found.\n", counter);
	ast_variables_destroy(resultset);
}


static char *handle_cli_database_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char prefix[256];
	DBT key, data;
	char *keys, *values;
	int res;
	int pass;
	int counter = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "database show";
		e->usage =
			"Usage: database show [family [keytree]]\n"
			"       Shows Asterisk database contents, optionally restricted\n"
			"       to a given family, or family and keytree.\n";
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
	} else {
		return CLI_SHOWUSAGE;
	}
	if (db_rt) {
		handle_cli_database_show_realtime(a, a->argc >= 3 ? a->argv[2] : "", a->argc == 4 ? a->argv[3] : "");
		return CLI_SUCCESS;	
	}
	ast_mutex_lock(&dblock);
	if (dbinit()) {
		ast_mutex_unlock(&dblock);
		ast_cli(a->fd, "Database unavailable\n");
		return CLI_SUCCESS;	
	}
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	pass = 0;
	while (!(res = astdb->seq(astdb, &key, &data, pass++ ? R_NEXT : R_FIRST))) {
		if (key.size) {
			keys = key.data;
			keys[key.size - 1] = '\0';
		} else {
			keys = "<bad key>";
		}
		if (data.size) {
			values = data.data;
			values[data.size - 1]='\0';
		} else {
			values = "<bad value>";
		}
		if (keymatch(keys, prefix)) {
			ast_cli(a->fd, "%-50s: %-25s\n", keys, values);
			counter++;
		}
	}
	ast_mutex_unlock(&dblock);
	ast_cli(a->fd, "%d results found.\n", counter);
	return CLI_SUCCESS;	
}

static char *handle_cli_database_showkey(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char suffix[256];
	DBT key, data;
	char *keys, *values;
	int res;
	int pass;
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

	if (a->argc == 3) {
		/* Key only */
		snprintf(suffix, sizeof(suffix), "/%s", a->argv[2]);
	} else {
		return CLI_SHOWUSAGE;
	}
	ast_mutex_lock(&dblock);
	if (dbinit()) {
		ast_mutex_unlock(&dblock);
		ast_cli(a->fd, "Database unavailable\n");
		return CLI_SUCCESS;	
	}

	if (db_rt) {
		ast_mutex_unlock(&dblock);
		handle_cli_database_show_realtime(a, "", a->argv[2]);
		return CLI_SUCCESS;	
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	pass = 0;
	while (!(res = astdb->seq(astdb, &key, &data, pass++ ? R_NEXT : R_FIRST))) {
		if (key.size) {
			keys = key.data;
			keys[key.size - 1] = '\0';
		} else {
			keys = "<bad key>";
		}
		if (data.size) {
			values = data.data;
			values[data.size - 1]='\0';
		} else {
			values = "<bad value>";
		}
		if (subkeymatch(keys, suffix)) {
			ast_cli(a->fd, "%-50s: %-25s\n", keys, values);
			counter++;
		}
	}
	ast_mutex_unlock(&dblock);
	ast_cli(a->fd, "%d results found.\n", counter);
	return CLI_SUCCESS;	
}

struct ast_db_entry *ast_db_gettree(const char *family, const char *keytree)
{
	char prefix[256];
	DBT key, data;
	char *keys, *values;
	int values_len;
	int res;
	int pass;
	struct ast_db_entry *last = NULL;
	struct ast_db_entry *cur, *ret=NULL;

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
	}
	ast_mutex_lock(&dblock);
	if (dbinit()) {
		ast_mutex_unlock(&dblock);
		ast_log(LOG_WARNING, "Database unavailable\n");
		return NULL;	
	}
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	pass = 0;
	while (!(res = astdb->seq(astdb, &key, &data, pass++ ? R_NEXT : R_FIRST))) {
		if (key.size) {
			keys = key.data;
			keys[key.size - 1] = '\0';
		} else {
			keys = "<bad key>";
		}
		if (data.size) {
			values = data.data;
			values[data.size - 1] = '\0';
		} else {
			values = "<bad value>";
		}
		values_len = strlen(values) + 1;
		if (keymatch(keys, prefix) && (cur = ast_malloc(sizeof(*cur) + strlen(keys) + 1 + values_len))) {
			cur->next = NULL;
			cur->key = cur->data + values_len;
			strcpy(cur->data, values);
			strcpy(cur->key, keys);
			if (last) {
				last->next = cur;
			} else {
				ret = cur;
			}
			last = cur;
		}
	}
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

static struct ast_cli_entry cli_database[] = {
	AST_CLI_DEFINE(handle_cli_database_show,    "Shows database contents"),
	AST_CLI_DEFINE(handle_cli_database_showkey, "Shows database contents"),
	AST_CLI_DEFINE(handle_cli_database_get,     "Gets database value"),
	AST_CLI_DEFINE(handle_cli_database_put,     "Adds/updates database value"),
	AST_CLI_DEFINE(handle_cli_database_del,     "Removes database key/value"),
	AST_CLI_DEFINE(handle_cli_database_deltree, "Removes database keytree/values")
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
	char idText[256] = "";
	const char *family = astman_get_header(m, "Family");
	const char *key = astman_get_header(m, "Key");
	char tmp[256];
	int res;

	if (ast_strlen_zero(family)) {
		astman_send_error(s, m, "No family specified.");
		return 0;
	}
	if (ast_strlen_zero(key)) {
		astman_send_error(s, m, "No key specified.");
		return 0;
	}

	if (!ast_strlen_zero(id))
		snprintf(idText, sizeof(idText) ,"ActionID: %s\r\n", id);

	res = ast_db_get(family, key, tmp, sizeof(tmp));
	if (res) {
		astman_send_error(s, m, "Database entry not found");
	} else {
		astman_send_ack(s, m, "Result will follow");
		astman_append(s, "Event: DBGetResponse\r\n"
				"Family: %s\r\n"
				"Key: %s\r\n"
				"Val: %s\r\n"
				"%s"
				"\r\n",
				family, key, tmp, idText);
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
	int res;

	if (ast_strlen_zero(family)) {
		astman_send_error(s, m, "No family specified.");
		return 0;
	}

	if (!ast_strlen_zero(key))
		res = ast_db_deltree(family, key);
	else
		res = ast_db_deltree(family, NULL);

	if (res < 0)
		astman_send_error(s, m, "Database entry not found");
	else
		astman_send_ack(s, m, "Key tree deleted successfully");
	
	return 0;
}

int astdb_init(void)
{
	/* When this routine is run, the realtime modules are not loaded so we can't initialize realtime yet. */
	db_rt = 0;

	/* If you have multiple systems using the same database, set the systemname in asterisk.conf */
	db_rt_sysname = S_OR(ast_config_AST_SYSTEM_NAME, "asterisk");
	
	/* initialize astdb or realtime */
	dbinit();

	ast_cli_register_multiple(cli_database, ARRAY_LEN(cli_database));
	ast_manager_register_xml("DBGet", EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_dbget);
	ast_manager_register_xml("DBPut", EVENT_FLAG_SYSTEM, manager_dbput);
	ast_manager_register_xml("DBDel", EVENT_FLAG_SYSTEM, manager_dbdel);
	ast_manager_register_xml("DBDelTree", EVENT_FLAG_SYSTEM, manager_dbdeltree);
	return 0;
}
