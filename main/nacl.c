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
#include "asterisk/astobj2.h"
#include "asterisk/config.h"
#include "asterisk/manager.h"
#include "asterisk/logger.h"
#include "asterisk/cli.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/nacl.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define NACL_LOAD	1
#define NACL_RELOAD	2


enum nacl_ops {
	NACL_ADD,
	NACL_DEL,
	NACL_UNKNOWN = 0,
};

enum rule_ops {
	HA_PERMIT,
	HA_DENY,
	HA_UNKNOWN = 0,
};

static struct nacloptext_def {
	enum nacl_ops op;
	const char *text;
}  nops[] = {
	{ NACL_ADD, "add" },	
	{ NACL_DEL, "del" },	
};

static struct naclrule_def {
	enum rule_ops op;
	const char *text;
} rops[] = {
	{ HA_PERMIT, "permit" },
	{ HA_DENY, "deny" },
};




/*! \brief the list of NACLs */
struct ao2_container *nacl_list;

static enum nacl_ops find_naclop(const char *op)
{
	int i;

	for (i = 0; (i < (sizeof(nops) / sizeof(nops[0]))); i++) {
		if (!strcasecmp(nops[i].text, op)) {
			return nops[i].op;
		}
	}
	return NACL_UNKNOWN;
}

static enum rule_ops find_naclrule(const char *rule)
{
	int i;

	for (i = 0; (i < (sizeof(rops) / sizeof(rops[0]))); i++) {
		if (!strcasecmp(rops[i].text, rule)) {
			return rops[i].op;
		}
	}
	return HA_UNKNOWN;
}

static const char *find_naclruletext(enum rule_ops op)
{
	int i;

	for (i = 0; (i < (sizeof(rops) / sizeof(rops[0]))); i++) {
		if (op == rops[i].op) {
			return rops[i].text;
		}
	}
	return NULL;
}

/*! \brief destroy a NACL 
*/
static void nacl_destroy(void *obj)
{
	struct ast_nacl *nacl = obj;
	if (option_debug > 2)
		ast_log(LOG_DEBUG, "--- Destruction of NACL %s is NOW. Please have a safe distance.\n", nacl->name);
	if (nacl->acl)
		ast_free_ha(nacl->acl);
}


/*! \brief Add named ACL to list (done from configuration file or module) 
	Internal ACLs, created by Asterisk modules, should use a name that
	begins with "ast_". These are prevented from configuration in nacl.conf
 */
struct ast_nacl *ast_nacl_add(const char *name, const char *owner)
{
	struct ast_nacl *nacl;
	
	if (ast_strlen_zero(name)) {
		ast_log(LOG_WARNING, "Zero length name.\n");
		return NULL;
	}

	nacl = ao2_alloc(sizeof(struct ast_nacl), nacl_destroy);

	ast_copy_string(nacl->name, name, sizeof(nacl->name));
	ast_copy_string(nacl->owner, owner, sizeof(nacl->owner));

	ao2_link(nacl_list,nacl);

 	if (option_debug > 2) {
		ast_log(LOG_DEBUG, "Added named ACL '%s'\n", name);
	}

	return nacl;
}

/* Copied from app_queue.c */
static int compress_char(const char c)
{
	if (c < 32)
		return 0;
	else if (c > 96)
		return c - 64;
	else
		return c - 32;
}

/*! \brief ao2 function to create unique hash of object */
static int nacl_hash_fn(const void *obj, const int flags)
{
	const struct ast_nacl *nacl = obj;
	int ret = 0, i;

	for (i = 0; i < strlen(nacl->name) && nacl->name[i]; i++)
		ret += compress_char(nacl->name[i]) << (i * 6);
	return ret;
}

/*! \brief ao2 function to compare objects */
static int nacl_cmp_fn(void *obj1, void *obj2, int flags)
{
	struct ast_nacl *nacl1 = obj1, *nacl2 = obj2;
	return strcmp(nacl1->name, nacl2->name) ? 0 : CMP_MATCH | CMP_STOP;
}


/*! \brief Find a named ACL 
	if deleted is true, we will find deleted items too
	if owner is NULL, we'll find all otherwise owner is used for selection too
	We raise the refcount on the result, which the calling function need to deref.
*/
struct ast_nacl *ast_nacl_find_all(const char *name, const int deleted, const char *owner)
{
	struct ast_nacl *found = NULL;
	struct ao2_iterator i;
	struct ast_nacl *nacl = NULL;

	i = ao2_iterator_init(nacl_list, 0);

	ao2_lock(nacl_list);
	while ((nacl = ao2_iterator_next(&i))) {
		ao2_lock(nacl);

		if (!strcasecmp(nacl->name, name) && (owner == NULL || !strcasecmp(nacl->owner,owner))) {
			if(nacl->delete) {
				if (deleted) {
					found = nacl;
					ao2_unlock(nacl);
					continue;
				}
			} else {
				found = nacl;
				ao2_unlock(nacl);
				continue;
			}
		}
		ao2_unlock(nacl);
                ao2_ref(nacl, -1);
	};
	ao2_unlock(nacl_list);
	ao2_iterator_destroy(&i);

	return found;
}

/*! \brief Find a named ACL 
*/
struct ast_nacl *ast_nacl_find(const char *name)
{
	return ast_nacl_find_all(name, 0, NULL);
}

/*! \brief MarkClear all named ACLs owned by us 
	Mark the others as deletion ready.
*/
int ast_nacl_mark_all_owned(const char *owner)
{
	int pruned = 0;
	struct ao2_iterator i;
	struct ast_nacl *nacl = NULL;

	i = ao2_iterator_init(nacl_list, 0);

	ao2_lock(nacl_list);
	while ((nacl = ao2_iterator_next(&i))) {
		ao2_lock(nacl);
		if (owner == NULL || !strcasecmp(nacl->owner, owner)) {
			nacl->delete = TRUE;
			pruned++;
		}
		ao2_unlock(nacl);
	}; 
	ao2_unlock(nacl_list);
	return pruned;
}


/*! \brief Attach to a named ACL. You need to detach later 
	This is to avoid Named ACLs to disappear from runtime. Even if they are deleted from the
	configuration, they will still be around
	\note Deleted NACLs won't be found any more with this function, to avoid adding to the use
		of these ACLs
 */
struct ast_nacl *ast_nacl_attach(const char *name)
{
	struct ast_nacl *nacl;
	if (!name) {
		return NULL;
	}
	nacl = ast_nacl_find(name);
	if (!nacl) {
		return NULL;
	}
	return nacl;
}

/*! \brief Detach from a named ACL. 
	If it's marked for deletion and refcount is zero, then it's deleted
 */
void ast_nacl_detach(struct ast_nacl *nacl)
{
	if (!nacl) {
		return; /* What's up, doc? */
	}
	ao2_ref(nacl, -1);
}

/*! Unref all objects with delete=1 */
static int nacl_delete_marked(void)
{
	int pruned = 0;
	struct ao2_iterator i;
	struct ast_nacl *nacl = NULL;

	i = ao2_iterator_init(nacl_list, 0);

	ao2_lock(nacl_list);
	while ((nacl = ao2_iterator_next(&i))) {
		if (nacl->delete) {
			ao2_ref(nacl, -1);
			pruned++;
		}
	}; 
	ao2_unlock(nacl_list);
	return pruned;
}

/*! \brief Update a HA list by inserting or deleting a row at a specific position 
	if inser is false, it means delete
*/
static struct ast_ha *ha_update(struct ast_ha *ha, int line, int insert, struct ast_ha *new)
{
	struct ast_ha *next = ha;
	struct ast_ha *temp = NULL;
	int rule = 0;

	/* IF we have nothing to insert, just give up */
	if (insert && !new) {
		return ha;
	}

	ast_log(LOG_DEBUG, "--- Operation %s requested line %d\n", insert?"insert":"delete", line);

	/* If there's no existing ha we have nothing to delete */
	if (!ha) {
		if (!insert) {
			return NULL;
		} else {
			return new;
		}
	}

	/* Insert or delete at top */
	if (line <= 1) {
		if (insert) {
			if (next == NULL) {
				return new;
			}
			ast_log(LOG_DEBUG, "---  inserting at start\n");
			new->next = next;
			return new;
		} else {	/* Delete first rule */
			temp = next->next;
			ast_log(LOG_DEBUG, "---  deleting first line\n");
			free(next);
			return temp;
		}
	}

	for (rule=1; (rule <= line && next != NULL); rule++) {
		ast_log(LOG_DEBUG, "\n---  Rule %d ", rule);
		if (rule == line) {
			/* Ok, we are here */
			if (insert) {
				ast_log(LOG_DEBUG, "---  inserting\n");
				/* Insert */
				new->next = temp->next;
				temp->next = new;
			} else {
				ast_log(LOG_DEBUG, "---  deleting\n");
				/* Delete */
				temp->next = next->next;	/* The one to delete */
				free(next);
			}
			return ha;
		}
		temp = next;	/* The previous NACL */
		next = next->next;
	}
	/* If we are here, the line number was greater than the number of lines available */
	if (insert) {
		ast_log(LOG_DEBUG, "---  inserting\n");
		temp->next = new;
	}
	return ha;
	
}

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
		ast_cli(fd,"     %-3.3d: %s: %s mask %s\n", rulesfound, (ha->sense == AST_SENSE_ALLOW) ? "permit" : "deny  ", iabuf2, iabuf);
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
#define FORMAT "%-40.40s %-20.20s %5d %5d %7s\n"
#define FORMAT2 "%-40.40s %-20.20s %-5.5s %-5.5s %7s\n"

	struct ao2_iterator i;
	struct ast_nacl *nacl;

	i = ao2_iterator_init(nacl_list, 0);

	ast_cli(fd, FORMAT2, "ACL name:", "Set by", "#rules", "Usage", "Flags");
	while ((nacl = ao2_iterator_next(&i))) {
		ast_cli(fd, FORMAT, nacl->name, 
			S_OR(nacl->owner, "-"),
			nacl->rules,
			(ao2_ref(nacl, 0) -1),
			nacl->manipulated ? "M" : "");
		ha_list(fd, nacl->acl, nacl->rules);
                ao2_ref(nacl, -1);
	};
	ao2_iterator_destroy(&i);
	ast_cli(fd, "\nFlag M = Modified by AMI or CLI\n");
	return RESULT_SUCCESS;
}
#undef FORMAT
#undef FORMAT2

/*! \brief Add new IP address to ruleset */
int ast_nacl_add_ip(struct ast_nacl *nacl, struct sockaddr_in *ip, int permit)
{
	char ipbuf[128];

	if (!nacl || ip->sin_addr.s_addr) {
		return FALSE;
	}
	ao2_ref(nacl,1);
	ast_copy_string(ipbuf, ast_inet_ntoa(ip->sin_addr.s_addr), 128);
	/* In trunk, we need to create a function that uses IP directly */
	nacl->ha = ast_append_ha(permit ? "permit" : "deny", ipbuf, nacl->ha);
	nacl->rules++;
	ao2_ref(nacl,-1);
	return TRUE;
}

/*! \brief Update NACL (or create it if it doesn't exist) */
static int nacl_update(int fd, const char *command, const char *name, int rule, char *operation, const char *target, const char *owner)
{
	struct ast_nacl *nacl;
	struct ast_ha *newha = NULL;
	int insert = !strcasecmp(command, "add");

	nacl = ast_nacl_find(name);
	if (!nacl) {
		if (!insert) {
			ast_cli(fd, "No such NACL: %s\n", name);
			return RESULT_SUCCESS;
		}
		nacl = ast_nacl_add(name, owner);
		/* Add a ref so that both existing and new NACLs has an extra ref after nacl_find or nacl_add */
		if (fd) {
			ast_cli(fd, "Successfully added new NACL %s\n", name);
		}
		ao2_ref(nacl, +1);
	}
	if (!insert && !nacl->acl) {
		if (fd) {
			ast_cli(fd, "No rules to delete for NACL: %s\n", name);
		}
		ao2_ref(nacl, -1);
		return RESULT_SUCCESS;
	}
	ao2_lock(nacl);
	if (insert) {
		newha = ast_append_ha(operation, target, NULL);
		if (!newha) {
			if (fd) {
				ast_cli(fd, "Syntax error in new rule forNACL: %s\n", name);
			}
			ao2_ref(nacl, -1);
			ao2_unlock(nacl);
			return RESULT_SUCCESS;
		}
	}
	nacl->acl = ha_update(nacl->acl, rule, insert, newha);
	if (insert) {
		nacl->rules++;
	} else if (nacl->rules) {
		nacl->rules--;
	}
	nacl->manipulated = TRUE;
	ao2_ref(nacl, -1);
	ao2_unlock(nacl);
	return RESULT_SUCCESS;
}

static char show_nacls_usage[] = 
"Usage: nacl show\n"
"       Lists all configured named ACLs.\n"
"       Named ACLs can be used in many configuration files as well as internally\n"
"       by Asterisk.\n";

static struct ast_cli_entry cli_nacl = { 
	{ "nacl", "show", NULL },
	cli_show_nacls, "List configured named ACLs.",
	show_nacls_usage };

/*! \brief CLI command to add named ACLs */
static int cli_nacl_add(int fd, int argc, char *argv[])
{

	if (argc != 6) {
		return RESULT_SHOWUSAGE;
	}
	if (option_debug >= 2) {
		ast_cli(fd, "--- Command: %s %s\n", argv[0], argv[1]);
		ast_cli(fd, "--- NACL Name: %s Operation %s\n", argv[2], argv[4]);
		ast_cli(fd, "--- NACL line: %s Address %s\n", argv[3], argv[5]);
	}
	if (strcasecmp(argv[4], "permit") && strcasecmp(argv[4], "deny")) {
		ast_cli(fd, "Error: Illegal operand %s\n", argv[4]);
		return RESULT_SHOWUSAGE;
	}
	return nacl_update(fd, argv[1], argv[2], atoi(argv[3]), argv[4], argv[5], "cli");
}

/*! \brief CLI command to delete rules in named ACLs */
static int cli_nacl_delete(int fd, int argc, char *argv[])
{
	if (argc != 4) {
		return RESULT_SHOWUSAGE;
	}
	ast_cli(fd, "--- Command: %s %s\n", argv[0], argv[1]);
	ast_cli(fd, "--- NACL Name: %s Line %s\n", argv[2], argv[3]);
	return nacl_update(fd, argv[1], argv[2], atoi(argv[3]), NULL, NULL, "cli");
}

static char nacl_delete_usage[] = 
"Usage: nacl delete <name> <number>\n"
"       Delete a rule from a NACL.\n"
"	The NACL will still remain in memory, even if there are no active rules\n"
"	Please note that changes to ACLs are not stored in configuration, thuse are not\n"
"	persistant between Asterisk restarts.\n"
"\n";

static char nacl_add_usage[] = 
"Usage: nacl add <name> <number> [permit|deny] <address>\n"
"       Add a rule to a specific NACL.\n"
"	If the NACL doesn't exist, it's created. If there is an existing rule with the given\n"
"       number, the new rule is inserted before.\n"
"       Address is given as <ipaddress>/<netmask> or <ipaddress>/<maskbytes> (CIDR notation)\n"
"	Please note that changes to ACLs are not stored in configuration, thuse are not\n"
"	persistant between Asterisk restarts.\n"
"\n";

static struct ast_cli_entry clidef_nacl_add = { 
	{ "nacl", "add", NULL },
	cli_nacl_add, "Add a new rule to a NACL.",
	nacl_add_usage };

static struct ast_cli_entry clidef_nacl_delete = { 
	{ "nacl", "delete", NULL },
	cli_nacl_delete, "Delete a rule from an NACL.",
	nacl_delete_usage };

static char mandescr_naclupdate[] =
"Description: A 'NaclUpdate' action will modify or create\n"
"named ACLs for dynamic IP based filters.\n"
"Variables:\n"
"   NaclName:   Name of the NACL. If it doesn't exist, it's created on an add operation\n"
"   NaclOp:     Operation - Add or Delete\n"
"   RuleId:     Line number of rule to add or delete. If there is an existing rule on this\n"
"               position on an add operation, the line is inserted at that position, before\n"
"               the existing line. If the line number is higher than the number of lines,\n"
"               the new line is added at the end.\n"
"For 'add' operations, the RuleOp and RuleTarget variables are required:\n"
"   RuleOp:     Permit or Deny\n"
"   RuleTarget: IP address and netmask for filter, separated by slash.\n"
"   ActionId:   Optional ID for this transaction\n"
"\n";

static int manager_naclupdate(struct mansession *s, const struct message *m)
{
        const char *naclname = astman_get_header(m, "NaclName");
        const char *naclop = astman_get_header(m, "NaclOp");
        const char *ruleid = astman_get_header(m, "RuleId");
        const char *ruleop = astman_get_header(m, "RuleOp");
        const char *ruletarget = astman_get_header(m, "RuleTarget");
        const char *id = astman_get_header(m,"ActionID");
	enum nacl_ops n_op;
	enum rule_ops r_op = HA_UNKNOWN;
	struct ast_nacl *nacl;
	struct ast_ha *newha = NULL;

        char idText[256] = "";

	if (ast_strlen_zero(naclname)) {
		astman_send_error(s, m, "NaclName not specified");
		return 0;
	}
	if (ast_strlen_zero(naclop)) {
		astman_send_error(s, m, "NaclOp not specified");
		return 0;
	}
	if (ast_strlen_zero(ruleid)) {
		astman_send_error(s, m, "RuleID not specified");
		return 0;
	}
	if ((n_op = find_naclop(naclop)) == NACL_UNKNOWN) {
		astman_send_error(s, m, "Unknown NaclOP - 'add' or 'del' implemented");
		return 0;
	}
	if (n_op == NACL_ADD) {
		r_op = find_naclrule(ruleop);
		if  (r_op  == HA_UNKNOWN) {
			astman_send_error(s, m, "Unknown RuleOp");
			return 0;
		}
		if (ast_strlen_zero(ruletarget)) {
			astman_send_error(s, m, "RuleTarget not specified");
			return 0;
		}
	}

        if (!ast_strlen_zero(id)) {
                snprintf(idText, sizeof(idText), "ActionID: %s\r\n", id);
        }
	nacl = ast_nacl_find(naclname);
	if (!nacl) {
		if (n_op == NACL_DEL) {
			astman_send_error(s, m, "Unknown NACL name");
			return 0;
		}
		/* Assume ADD */
		nacl = ast_nacl_add(naclname, "AMI");
		/* Add a ref so that both existing and new NACLs has an extra ref after nacl_find or nacl_add */
		ao2_ref(nacl, +1);
	}
	if (n_op == NACL_DEL && !nacl->acl) {
		ao2_ref(nacl, -1);
		astman_send_error(s, m, "No rules to delete in given NACL");
		return 0;
	}
	if (n_op == NACL_ADD) {
		newha = ast_append_ha(ruleop, ruletarget, NULL);
		if (!newha) {
			astman_send_error(s,m, "Syntax error in rule.");
			ao2_ref(nacl, -1);
			return RESULT_SUCCESS;
		}
	}
	ao2_lock(nacl);
	nacl->acl = ha_update(nacl->acl, atoi(ruleid), (n_op == NACL_ADD), newha);
	if (n_op == NACL_ADD) {
		nacl->rules++;
	} else if (nacl->rules) {
		nacl->rules--;
	}
	nacl->manipulated = TRUE;
	ao2_ref(nacl, -1);
	ao2_unlock(nacl);
	return 0;
}
 


/* Initialize named ACLs 
	This function is used both at load and reload time.
 */
static int nacl_init(int reload_reason)
{
	struct ast_config *cfg;
	struct ast_variable *v;
	char *cat = NULL;
	struct ast_nacl *nacl = NULL;
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
				nacl->delete = FALSE;
				ast_free_ha(nacl->acl);	/* Delete existing ACL (locking needed indeed) */
				nacl->acl = NULL;
				ao2_ref(nacl, -1);	/* The find operation adds a ref */
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
		ao2_lock(nacl_list);
		nacl_delete_marked();
		ao2_unlock(nacl_list);
	}

	if (reload_reason == NACL_LOAD) {
		ast_cli_register(&cli_nacl);
		ast_cli_register(&clidef_nacl_add);
		ast_cli_register(&clidef_nacl_delete);
		ast_manager_register2("NaclUpdate", EVENT_FLAG_CONFIG, manager_naclupdate, "Update Named ACL", mandescr_naclupdate);
	}
	return 0;
}

/*! \brief Initialize NACL subsystem */
int ast_nacl_load(void)
{
	nacl_list = ao2_container_alloc(42, nacl_hash_fn, nacl_cmp_fn);
	return nacl_init(NACL_LOAD);
}

/*! \brief re-nitialize NACL subsystem */
int ast_nacl_reload(void)
{
	return nacl_init(NACL_RELOAD);
}
