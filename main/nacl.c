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
#include "asterisk/astobj.h"
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
	ASTOBJ_COMPONENTS(struct named_acl);
	char tag[MAXHOSTNAMELEN];		/*!< Name of this ACL */
	struct ast_ha *acl;			/*!< The actual ACL */
	int rules;				/*!< Number of ACL rules */
	char owner[20];				/*!< Owner (module) */
	char desc[80];				/*!< Description */
};

/*! \brief  The user list: Users and friends */
static struct nacl_list_def {
        ASTOBJ_CONTAINER_COMPONENTS(struct named_acl);
} nacl_list;

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

	ASTOBJ_INIT(nacl);

	ast_copy_string(nacl->name, name, sizeof(nacl->name));
	ast_copy_string(nacl->owner, owner, sizeof(nacl->owner));

	ASTOBJ_CONTAINER_LINK(&nacl_list,nacl);

 	if (option_debug > 2) {
		ast_log(LOG_DEBUG, "Added named ACL '%s'\n", name);
	}

	return nacl;
}

/*! \brief Find a named ACL 
	if deleted is true, we will find deleted items too
	if owner is NULL, we'll find all otherwise owner is used for selection too
	We raise the refcount on the result, which the calling function need to deref.
*/
struct named_acl *ast_nacl_find_all(const char *name, const int deleted, const char *owner)
{
	struct named_acl *nacl = NULL;

	ASTOBJ_CONTAINER_WRLOCK(&nacl_list);
	ASTOBJ_CONTAINER_TRAVERSE(&nacl_list, 1, do {
		ASTOBJ_WRLOCK(iterator);

		if (!strcasecmp(iterator->name, name) && (owner == NULL || !strcasecmp(iterator->owner,owner))) {
			if (iterator->objflags & ASTOBJ_FLAG_MARKED) {
				if (deleted) {
					nacl = iterator;
					ASTOBJ_REF(iterator);
					continue;
				}
			} else {
				nacl = iterator;
				ASTOBJ_REF(iterator);
				continue;
			}
		}
		ASTOBJ_UNLOCK(iterator);
	} while (0) );
	ASTOBJ_CONTAINER_UNLOCK(&nacl_list);

	return nacl;
}

/*! \brief destroy a NACL */
static void nacl_destroy(struct named_acl *nacl)
{
	if (option_debug > 2)
		ast_log(LOG_DEBUG, "--- Destruction of NACL %s is NOW. Please have a safe distance.\n", nacl->name);
	free(nacl);
}

/*! \brief Find a named ACL 
*/
struct named_acl *ast_nacl_find(const char *name)
{
	return ast_nacl_find_all(name, 0, NULL);
}

/*! \brief MarkClear all named ACLs owned by us 
	Mark the others as deletion ready.
*/
int ast_nacl_mark_all_owned(const char *owner)
{
	int pruned = 0;

	ASTOBJ_CONTAINER_WRLOCK(&nacl_list);
	ASTOBJ_CONTAINER_TRAVERSE(&nacl_list, 1, do {
		ASTOBJ_RDLOCK(iterator);
		if (owner == NULL || !strcasecmp(iterator->owner, owner)) {
			ASTOBJ_MARK(iterator);
			pruned++;
		}
		ASTOBJ_UNLOCK(iterator);
	} while (0) );
	ASTOBJ_CONTAINER_UNLOCK(&nacl_list);
	return pruned;
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
	ASTOBJ_UNREF(nacl, nacl_destroy);
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
#define FORMAT "%-40.40s %-20.20s %5d %5d \n"
#define FORMAT2 "%-40.40s %-20.20s %-5.5s %-5.5s\n"

	ast_cli(fd, FORMAT2, "ACL name:", "Set by", "#rules", "Usage");
	ASTOBJ_CONTAINER_TRAVERSE(&nacl_list, 1, {
                ASTOBJ_RDLOCK(iterator);
		ast_cli(fd, FORMAT, iterator->name, 
			S_OR(iterator->owner, "-"),
			iterator->rules,
			iterator->refcount);
		ha_list(fd, iterator->acl, iterator->rules);
                ASTOBJ_UNLOCK(iterator);
	} );
	ast_cli(fd, "\n");
	return RESULT_SUCCESS;
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
	int marked = 0;

	/* Clear all existing NACLs - or mark them for deletion */
	marked = ast_nacl_mark_all_owned("config");

	cfg = ast_config_load("nacl.conf");
	if (cfg) {
		while ((cat = ast_category_browse(cfg, cat))) {
			if (!strncasecmp(cat, "ast_", 4)) {
				ast_log(LOG_ERROR, "NACL names prefixed with ast_ are reserved for internal use. NACL not actived:  %s\n", cat);
				continue;
			}
		
			nacl = ast_nacl_find_all(cat, 1, "config");	/* Find deleted items */
			if (nacl) {
				ASTOBJ_UNMARK(nacl);
				ast_free_ha(nacl->acl);	/* Delete existing ACL (locking needed indeed) */
				ASTOBJ_UNREF(nacl, nacl_destroy);
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

	if (marked) {
		ASTOBJ_CONTAINER_WRLOCK(&nacl_list);
		ASTOBJ_CONTAINER_PRUNE_MARKED(&nacl_list, nacl_destroy);
		ASTOBJ_CONTAINER_UNLOCK(&nacl_list);
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

#ifdef ERROR
nacl.c: In function 'ast_nacl_add':
nacl.c:95: warning: assignment from incompatible pointer type
nacl.c: In function 'ast_nacl_find_all':
nacl.c:114: warning: assignment from incompatible pointer type
nacl.c:114: warning: implicit declaration of function 'ASTOBJ_RDUNLOCK'
nacl.c: At top level:
nacl.c:156: warning: no previous prototype for 'ast_nacl_mark_all_owned'
nacl.c: In function 'ast_nacl_mark_all_owned':
nacl.c:161: warning: assignment from incompatible pointer type
nacl.c:157: warning: unused variable 'nacl'
nacl.c:326:1: error: unterminated argument list invoking macro "ASTOBJ_CONTAINER_TRAVERSE"
nacl.c: In function 'cli_show_nacls':
nacl.c:239: error: 'ASTOBJ_CONTAINER_TRAVERSE' undeclared (first use in this function)
nacl.c:239: error: (Each undeclared identifier is reported only once
nacl.c:239: error: for each function it appears in.)
nacl.c:239: error: expected ';' at end of input
nacl.c:239: error: expected declaration or statement at end of input
nacl.c:229: warning: unused variable 'nacl'
nacl.c:239: warning: no return statement in function returning non-void
#endif

