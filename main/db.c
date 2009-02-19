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
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>

#include "asterisk/channel.h"
#include "asterisk/file.h"
#include "asterisk/app.h"
#include "asterisk/dsp.h"
#include "asterisk/logger.h"
#include "asterisk/options.h"
#include "asterisk/astdb.h"
#include "asterisk/cli.h"
#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/manager.h"
#include "asterisk/config.h"	/* For realtime support */
#include "db1-ast/include/db.h"

#ifdef __CYGWIN__
#define dbopen __dbopen
#endif
static int db_rt;			/*!< Flag for realtime system */
static const char *db_rt_rtfamily = "astdb";	/*!< Realtime name tag */
static const char *db_rt_value = "value";	/*!< Database field name for values */
static const char *db_rt_family = "family";   /*!< Database field name for family */
static const char *db_rt_key = "keyname";     /*!< Database field name for key */
static const char *db_rt_sysnamelabel = "systemname"; /*!< Database field name for system name */
static const char *db_rt_sysname;       /*!< From asterisk.conf or "asterisk" */


static DB *astdb;

AST_MUTEX_DEFINE_STATIC(dblock);


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

 	if (!astdb && !(astdb = dbopen((char *)ast_config_AST_DB, O_CREAT | O_RDWR, 0664, DB_BTREE, NULL))) {
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

	ast_log(LOG_DEBUG, ">>>>>> getall family: %s Key %s \n", S_OR(family,"-na-"), S_OR(key,"-na-"));

	if (ast_strlen_zero(family)) {
		/* Load all entries in the astdb */
		if (ast_strlen_zero(key)) {
			/* No variables given */
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, NULL);
		} else {
			/* Only key given */
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_key, key, NULL);
		}
	} else {
		if (ast_strlen_zero(key)) {
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, NULL);
		} else {
			variablelist = ast_load_realtime_multientry(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, key, NULL);
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
			ast_log(LOG_DEBUG, ">>>> Found name %s ...\n", cur->name);
			if (!strcmp(cur->name, db_rt_family)) {
				familyname = cur->value;
			} else if (!strcmp(cur->name, db_rt_key)) {
				keyname = cur->value;
			} else if (!strcmp(cur->name, db_rt_value)) {
				snprintf(buf, sizeof(buf), "/%s/%s", S_OR(familyname, ""), S_OR(keyname, ""));
				data = ast_variable_new(buf, S_OR(cur->value, "astdb-realtime"));
				familyname = keyname = NULL;
				ast_log(LOG_DEBUG, "#### Found Variable %s with value %s \n", buf, cur->value);
				/* Add this to the returnset */
				data->next = returnset;
				returnset = data;
			} else {
				if (ast_strlen_zero(cur->name)) {
					ast_log(LOG_DEBUG, "#### Skipping  strange record \n");
				} else {
					ast_log(LOG_DEBUG, "#### Skipping  %s with value %s \n", cur->name, cur->value);
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
	
	ast_mutex_lock(&dblock);
	if (dbinit()) {
		ast_mutex_unlock(&dblock);
		return -1;
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
		}
	}
	astdb->sync(astdb, 0);
	ast_mutex_unlock(&dblock);
	return 0;
}
int ast_db_put(const char *family, const char *keys, char *value)
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
		ast_log(LOG_DEBUG, ".... Trying ast_update_realtime\n");
		/* Update_realtime with mysql returns the number of rows affected */
		rowsaffected = ast_update2_realtime(db_rt_rtfamily, db_rt_family, family, db_rt_key, keys, db_rt_sysnamelabel, db_rt_sysname, NULL, db_rt_value, value, NULL);
		res = rowsaffected > 0 ? 0 : 1;
		if (res) {
			ast_log(LOG_DEBUG, ".... Trying ast_store_realtime\n");
			/* Update failed, let's try adding a new record */
			res = ast_store_realtime(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, keys, db_rt_value, value, NULL);
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

		res = var = ast_load_realtime(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, keys, NULL);
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
	
	ast_mutex_unlock(&dblock);

	/* Be sure to NULL terminate our data either way */
	if (res) {
		ast_log(LOG_DEBUG, "Unable to find key '%s' in family '%s'\n", keys, family);
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
		int rowcount = ast_destroy_realtime(db_rt_rtfamily, db_rt_sysnamelabel, db_rt_sysname, db_rt_family, family, db_rt_key, keys, NULL);
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
		ast_log(LOG_DEBUG, "Unable to find key '%s' in family '%s'\n", keys, family);
	}
	return res;
}



static int database_put(int fd, int argc, char *argv[])
{
	int res;
	if (argc != 5)
		return RESULT_SHOWUSAGE;
	res = ast_db_put(argv[2], argv[3], argv[4]);
	if (res)  {
		ast_cli(fd, "Failed to update entry\n");
	} else {
		ast_cli(fd, "Updated database successfully\n");
	}
	return RESULT_SUCCESS;
}

static int database_get(int fd, int argc, char *argv[])
{
	int res;
	char tmp[256];
	if (argc != 4)
		return RESULT_SHOWUSAGE;
	res = ast_db_get(argv[2], argv[3], tmp, sizeof(tmp));
	if (res) {
		ast_cli(fd, "Database entry not found.\n");
	} else {
		ast_cli(fd, "Value: %s\n", tmp);
	}
	return RESULT_SUCCESS;
}

static int database_del(int fd, int argc, char *argv[])
{
	int res;
	if (argc != 4)
		return RESULT_SHOWUSAGE;
	res = ast_db_del(argv[2], argv[3]);
	if (res) {
		ast_cli(fd, "Database entry does not exist.\n");
	} else {
		ast_cli(fd, "Database entry removed.\n");
	}
	return RESULT_SUCCESS;
}

static int database_deltree(int fd, int argc, char *argv[])
{
	int res;
	if ((argc < 3) || (argc > 4))
		return RESULT_SHOWUSAGE;
	if (argc == 4) {
		res = ast_db_deltree(argv[2], argv[3]);
	} else {
		res = ast_db_deltree(argv[2], NULL);
	}
	if (res) {
		ast_cli(fd, "Database entries do not exist.\n");
	} else {
		ast_cli(fd, "Database entries removed.\n");
	}
	return RESULT_SUCCESS;
}

static void handle_cli_database_show_realtime(int fd, const char *family, const char *key)
{
	struct ast_variable *resultset;
	struct ast_variable *cur;
	int counter = 0;

	dbinit();
	if (!db_rt) {
		ast_cli(fd, "Error: Can't connect to astdb/realtime\n");
		return;
	}

	cur = resultset = db_realtime_getall(family, key);
	while (cur) {
		ast_cli(fd, "%-40s: %-25s\n", cur->name, S_OR(cur->value, ""));
		cur = cur->next;
		counter++;
	}
	ast_cli(fd, "%d results found.\n", counter);
	ast_variables_destroy(resultset);
}

static int database_show(int fd, int argc, char *argv[])
{
	char prefix[256];
	DBT key, data;
	char *keys, *values;
	int res;
	int pass;

	if (argc == 4) {
		/* Family and key tree */
		snprintf(prefix, sizeof(prefix), "/%s/%s", argv[2], argv[3]);
	} else if (argc == 3) {
		/* Family only */
		snprintf(prefix, sizeof(prefix), "/%s", argv[2]);
	} else if (argc == 2) {
		/* Neither */
		prefix[0] = '\0';
	} else {
		return RESULT_SHOWUSAGE;
	}

	if (!db_rt) {
		ast_mutex_lock(&dblock);
		if (dbinit()) {
			ast_mutex_unlock(&dblock);
			ast_cli(fd, "Database unavailable\n");
			return RESULT_SUCCESS;	
		}
		if (db_rt)
			ast_mutex_unlock(&dblock);
	}
	if (db_rt) {
		handle_cli_database_show_realtime(fd, argc >= 3 ? argv[2] : "", argc == 4 ? argv[3] : "");
		return RESULT_SUCCESS;
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
				ast_cli(fd, "%-50s: %-25s\n", keys, values);
		}
	}
	ast_mutex_unlock(&dblock);
	return RESULT_SUCCESS;	
}

static int database_showkey(int fd, int argc, char *argv[])
{
	char suffix[256];
	DBT key, data;
	char *keys, *values;
	int res;
	int pass;

	if (argc == 3) {
		/* Key only */
		snprintf(suffix, sizeof(suffix), "/%s", argv[2]);
	} else {
		return RESULT_SHOWUSAGE;
	}
	if (!db_rt) {
		ast_mutex_lock(&dblock);
		if (dbinit()) {
			ast_mutex_unlock(&dblock);
			ast_cli(fd, "Database unavailable\n");
			return RESULT_SUCCESS;	
		}
		if (db_rt)
			ast_mutex_unlock(&dblock);
	}
	if (db_rt) {
		handle_cli_database_show_realtime(fd, "", argv[2]);
		return RESULT_SUCCESS;	
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
				ast_cli(fd, "%-50s: %-25s\n", keys, values);
		}
	}
	ast_mutex_unlock(&dblock);
	return RESULT_SUCCESS;	
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
	if (!db_rt && dbinit()) {
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
		free(last);
	}
}

static char database_show_usage[] =
"Usage: database show [family [keytree]]\n"
"       Shows Asterisk database contents, optionally restricted\n"
"to a given family, or family and keytree.\n";

static char database_showkey_usage[] =
"Usage: database showkey <keytree>\n"
"       Shows Asterisk database contents, restricted to a given key.\n";

static char database_put_usage[] =
"Usage: database put <family> <key> <value>\n"
"       Adds or updates an entry in the Asterisk database for\n"
"a given family, key, and value.\n";

static char database_get_usage[] =
"Usage: database get <family> <key>\n"
"       Retrieves an entry in the Asterisk database for a given\n"
"family and key.\n";

static char database_del_usage[] =
"Usage: database del <family> <key>\n"
"       Deletes an entry in the Asterisk database for a given\n"
"family and key.\n";

static char database_deltree_usage[] =
"Usage: database deltree <family> [keytree]\n"
"       Deletes a family or specific keytree within a family\n"
"in the Asterisk database.\n";

struct ast_cli_entry cli_database[] = {
	{ { "database", "show", NULL },
	database_show, "Shows database contents",
	database_show_usage },

	{ { "database", "showkey", NULL },
	database_showkey, "Shows database contents",
	database_showkey_usage },

	{ { "database", "get", NULL },
	database_get, "Gets database value",
	database_get_usage },

	{ { "database", "put", NULL },
	database_put, "Adds/updates database value",
	database_put_usage },

	{ { "database", "del", NULL },
	database_del, "Removes database key/value",
	database_del_usage },

	{ { "database", "deltree", NULL },
	database_deltree, "Removes database keytree/values",
	database_deltree_usage },
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

	res = ast_db_put(family, key, (char *) S_OR(val, ""));
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

int astdb_init(void)
{
	/* When this routine is run, the realtime modules are not loaded so we can't initialize realtime yet. */
        db_rt = 0;

        /* If you have multiple systems using the same database, set the systemname in asterisk.conf */
        db_rt_sysname = S_OR(ast_config_AST_SYSTEM_NAME, "asterisk");

        /* initialize astdb or realtime */
        dbinit();

	ast_cli_register_multiple(cli_database, sizeof(cli_database) / sizeof(struct ast_cli_entry));
	ast_manager_register("DBGet", EVENT_FLAG_SYSTEM, manager_dbget, "Get DB Entry");
	ast_manager_register("DBPut", EVENT_FLAG_SYSTEM, manager_dbput, "Put DB Entry");
	return 0;
}
