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
#ifndef ASTERISK_NACL_H
#define ASTERISK_NACL_H


/*! \file
 *
 * \brief Named Access Control Lists (nacl)
 *
 * \author Olle E. Johansson <oej@edvina.net>
 */

/*! \brief Structure for named ACL */
/*! \brief Structure for named ACL */
struct ast_nacl {
	char name[MAXHOSTNAMELEN];		/*!< Name of this ACL */
	struct ast_ha *acl;			/*!< The actual ACL */
	int rules;				/*!< Number of ACL rules */
	int delete;				/*!< Mark this object for deletion */
	int manipulated;			/*!< Manipulated by CLI or manager */
	char owner[20];				/*!< Owner (module) */
	char desc[80];				/*!< Description */
};

/*! \brief Add named ACL to list (done from configuration file or module) */
struct ast_nacl *ast_nacl_add(const char *name, const char *owner);

/*! \brief Find a named ACL 
	if deleted is true, we will find deleted items too
	if owner is NULL, we'll find all otherwise owner is used for selection too
*/
struct ast_nacl *ast_nacl_find_all(const char *name, const int deleted, const char *owner);

/*! \brief Find a named ACL (that is not marked with the delete flag) 
 */
struct ast_nacl *ast_nacl_find(const char *name);

/*! \brief Mark all the owned NACLs
*/
int ast_nacl_mark_all_owned(const char *owner);

/*! \brief Attach to a named ACL. You need to detach later 
	This is to avoid Named ACLs to disappear from runtime. Even if they are deleted from the
	configuration, they will still be around thanks to ASTOBJs
 */
struct ast_nacl *ast_nacl_attach(const char *name);

/*! \brief Detach from a named ACL. 
	If it's marked for deletion and refcount is zero, then it's deleted
 */
void ast_nacl_detach(struct ast_nacl *nacl);

/*! \brief Add new IP address to ruleset */
int ast_nacl_add_ip(struct ast_nacl *nacl, struct sockaddr_in *ip, int permit)

/*! \brief Initialize NACL subsystem */
int ast_nacl_load(void);

/*! \brief re-nitialize NACL subsystem */
int ast_nacl_reload(void);

#endif /* ASTERISK_NACL_H */
