/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2009-2010, Edvina AB
 *
 * Olle E. Johansson <oej@edvina.net>
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
 * \brief Named Access Control Lists (nacl)
 *
 * \author Olle E. Johansson <oej@edvina.net>
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "asterisk/acl.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/cli.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/srv.h"
#include "asterisk/nacl.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define NACL_LOAD	1
#define NACL_RELOAD	2

/*! \brief Structure for named ACL */
struct named_acl {
	char name[MAXHOSTNAMELEN];		/*!< Name of this ACL */
	struct ast_ha *acl;			/*!< The actual ACL */
	int refcount;				/*!< Number of users of this ACL */
	int delete;				/*!< Delete this ACL when refcount is zero */
	int rules;				/*!< Number of ACL rules */
	char owner[20];				/*!< Owner (module) */
	AST_LIST_ENTRY(named_acl) list;		/*!< List mechanics */
};

static AST_LIST_HEAD_STATIC(nacl_list, named_acl);	/*!< The named acl list */

/*! \brief Add named ACL to list (done from configuration file or module) 
	Internal ACLs, created by Asterisk modules, should use a name that
	begins with "ast_". These are prevented from configuration in nacl.conf
 */
struct named_acl *ast_nacl_add(const char *name, const char *owner)
{
	struct named_acl *nacl;
	
	if (ast_strlen_zero(name)) {
		ast_log(LOG_WARNING, "Zero length name.\n");
		return NULL;
	}

	if (!(nacl = ast_calloc(1, sizeof(*nacl)))) {
		return NULL;
	}

	ast_copy_string(nacl->name, name, sizeof(nacl->name));
	ast_copy_string(nacl->owner, owner, sizeof(nacl->owner));

	AST_LIST_LOCK(&nacl_list);
	AST_LIST_INSERT_TAIL(&nacl_list, nacl, list);
	AST_LIST_UNLOCK(&nacl_list);

 	if (option_debug > 2) {
		ast_log(LOG_DEBUG, "Added named ACL '%s'\n", name);
	}

	return nacl;
}

/*! \brief Find a named ACL 
	if deleted is true, we will find deleted items too
	if owner is NULL, we'll find all otherwise owner is used for selection too
*/
struct named_acl *ast_nacl_find_all(const char *name, const int deleted, const char *owner)
{
	struct named_acl *nacl = NULL;

	AST_LIST_LOCK(&nacl_list);
	AST_LIST_TRAVERSE(&nacl_list, nacl, list) {
		if (!strcasecmp(nacl->name, name) && (owner == NULL || !strcasecmp(nacl->owner,owner))) {
			if (nacl->delete) {
				if (deleted) {
					continue;
				}
			} else {
				continue;
			}
		}
	}
	AST_LIST_UNLOCK(&nacl_list);

	return nacl;
}

/*! \brief Find a named ACL 
*/
struct named_acl *ast_nacl_find(const char *name)
{
	return ast_nacl_find_all(name, 0, NULL);
}

/*! \brief Clear all named ACLs that is not used
	Mark the others as deletion ready.
*/
void ast_nacl_clear_all_unused(const char *owner)
{
	struct named_acl *nacl = NULL;

	AST_LIST_LOCK(&nacl_list);
	AST_LIST_TRAVERSE_SAFE_BEGIN(&nacl_list, nacl, list) {
		if (owner == NULL || !strcasecmp(nacl->owner, owner)) {
			if(nacl->refcount == 0) {
				AST_LIST_REMOVE_CURRENT(&nacl_list, list);
			} else {
				nacl->delete = 1;
			}
		}
	}
	AST_LIST_TRAVERSE_SAFE_END;

	AST_LIST_UNLOCK(&nacl_list);
}


/*! \brief Clear the ACL list - all the time
*/
static void nacl_clear_all_force(void)
{
	struct named_acl *nacl = NULL;

	AST_LIST_LOCK(&nacl_list);

	while ((nacl = AST_LIST_REMOVE_HEAD(&nacl_list, list))) {
		free(nacl);
	}

	AST_LIST_UNLOCK(&nacl_list);
}


/*! \brief Attach to a named ACL. You need to detach later 
	This is to avoid Named ACLs to disappear from runtime. Even if they are deleted from the
	configuration, they will still be around
	\note Deleted NACLs won't be found any more with this function, to avoid adding to the use
		of these ACLs
 */
struct named_acl *ast_nacl_attach(const char *name)
{
	struct named_acl *nacl = ast_nacl_find(name);
	if (!nacl) {
		return NULL;
	}
	nacl->refcount++;
	return nacl;
}

/*! \brief Detach from a named ACL. 
	If it's marked for deletion and refcount is zero, then it's deleted
 */
void ast_nacl_detach(struct named_acl *nacl)
{
	if (!nacl) {
		return; /* What's up, doc? */
	}
	nacl->refcount--;
	if (nacl->refcount == 0 && nacl->delete) {
		AST_LIST_REMOVE(&nacl_list, nacl, list);
		free(nacl);
	}
}

static char show_nacls_usage[] = 
"Usage: nacl show\n"
"       Lists all configured named ACLs.\n"
"       Named ACLs can be used in many configuration files as well as internally\n"
"       by Asterisk.\n";

/*! \brief Print ha list to CLI */
static void ha_list(int fd, struct ast_ha *ha, const int rules)
{
	char iabuf[INET_ADDRSTRLEN];
	char iabuf2[INET_ADDRSTRLEN];
	int rulesfound = 0;

	while (ha) {
		rulesfound++;
		ast_copy_string(iabuf2, ast_inet_ntoa(ha->netaddr), sizeof(iabuf2));
		ast_copy_string(iabuf, ast_inet_ntoa(ha->netmask), sizeof(iabuf));
		ast_cli(fd,"     %s: %s mask %s\n", (ha->sense == AST_SENSE_ALLOW) ? "permit" : "deny  ", iabuf2, iabuf);
		ha = ha->next;
	}
	/* Rules is only used for configuration based nacls */
	if (rules != 0 && rulesfound != rules) {
		ast_cli(fd, "     NOTE: Number of rules doesn't match configuration. Please check.\n");
	}
}

/*! \brief CLI command to list named ACLs */
static int cli_show_nacls(int fd, int argc, char *argv[])
{
	struct named_acl *nacl;
#define FORMAT "%-40.40s %-20.20s %5d %5d %-3.3s\n"
#define FORMAT2 "%-40.40s %-20.20s %-5.5s %-5.5s %-3.3s\n"

	if (AST_LIST_EMPTY(&nacl_list)) {
		ast_cli(fd, "No named ACLs configured.\n\n");
		return RESULT_SUCCESS;
	} else {
		ast_cli(fd, FORMAT2, "ACL name:", "Set by", "#rules", "Usage", "Delete");
		AST_LIST_LOCK(&nacl_list);
		AST_LIST_TRAVERSE(&nacl_list, nacl, list) {
			ast_cli(fd, FORMAT, nacl->name, 
				S_OR(nacl->owner, "-"),
				nacl->rules,
				nacl->refcount,
				nacl->delete ? "Yes" : "No");
			ha_list(fd, nacl->acl, nacl->rules);
		}
		AST_LIST_UNLOCK(&nacl_list);
		ast_cli(fd, "\n");
		return RESULT_SUCCESS;
	}
}
#undef FORMAT
#undef FORMAT2

static struct ast_cli_entry cli_nacl = { 
	{ "nacl", "show", NULL },
	cli_show_nacls, "List configured named ACLs.",
	show_nacls_usage };

/* Initialize named ACLs 
	This function is used both at load and reload time.
 */
static int nacl_init(int reload_reason)
{
	struct ast_config *cfg;
	struct ast_variable *v;
	char *cat = NULL;
	struct named_acl *nacl = NULL;

	/* Clear all existing NACLs - or mark them for deletion */
	ast_nacl_clear_all_unused("config");

	cfg = ast_config_load("nacl.conf");
	if (cfg) {
		while ((cat = ast_category_browse(cfg, cat))) {
			if (!strncasecmp(cat, "ast_", 4)) {
				ast_log(LOG_ERROR, "NACL names prefixed with ast_ are reserved for internal use. NACL not actived:  %s\n", cat);
				continue;
			}
		
			nacl = ast_nacl_find_all(cat, 1, "config");	/* Find deleted items */
			if (nacl) {
				nacl->delete = 0;	/* Reset delete flag */
				ast_free_ha(nacl->acl);	/* Delete existing ACL (locking needed indeed) */
			} else {
				nacl = ast_nacl_add(cat, "config");
			}
			v = ast_variable_browse(cfg, cat);
			while(v) {
				if (!strcasecmp(v->name, "permit") || !strcasecmp(v->name, "deny")) {
					nacl->acl = ast_append_ha(v->name, v->value, nacl->acl);
					nacl->rules++;
				} else {
					ast_log(LOG_WARNING, "Unknown configuration option: %s\n", v->name);
				}
				v = v->next;
			}
		}
		ast_config_destroy(cfg);
	} 

	if (reload_reason == NACL_LOAD) {
		ast_cli_register(&cli_nacl);
	}
	return 0;
}

/*! \brief Initialize NACL subsystem */
int ast_nacl_load(void)
{
	return nacl_init(NACL_LOAD);
}

/*! \brief re-nitialize NACL subsystem */
int ast_nacl_reload(void)
{
	return nacl_init(NACL_RELOAD);
}
