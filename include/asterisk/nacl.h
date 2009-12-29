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
struct named_acl; 

/*! \brief Add named ACL to list (done from configuration file or module) */
struct named_acl *ast_nacl_add(const char *name, const char *owner);

/*! \brief Find a named ACL 
	if deleted is true, we will find deleted items too
	if owner is NULL, we'll find all otherwise owner is used for selection too
*/
struct named_acl *ast_nacl_find_all(const char *name, const int deleted, const char *owner);

/*! \brief Find a named ACL (that is not marked with the delete flag) 
 */
struct named_acl *ast_nacl_find(const char *name);

/*! \brief Clear all named ACLs that is not used
	Mark the others as deletion ready.
	If owner is NULL, clear ALL, otherwise only nacls with the same owner
*/
void ast_nacl_clear_all_unused(const char *owner);

/*! \brief Attach to a named ACL. You need to detach later 
	This is to avoid Named ACLs to disappear from runtime. Even if they are deleted from the
	configuration, they will still be around
 */
struct named_acl *ast_nacl_attach(const char *name);

/*! \brief Detach from a named ACL. 
	If it's marked for deletion and refcount is zero, then it's deleted
 */
void ast_nacl_detach(struct named_acl *nacl);

/*! \brief Initialize NACL subsystem */
int ast_nacl_load(void);

/*! \brief re-nitialize NACL subsystem */
int ast_nacl_reload(void);

#endif /* ASTERISK_NACL_H */
