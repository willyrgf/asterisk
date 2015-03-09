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

/*!
 * \file
 * \brief Persistant data storage (akin to *doze registry)
 */

#ifndef _ASTERISK_ASTDB_H
#define _ASTERISK_ASTDB_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#include "asterisk/utils.h"

enum ast_db_shared_type {
	/* Items in the shared family are common across all Asterisk instances */
	SHARED_DB_TYPE_GLOBAL = 0,
	/*! Items in the shared family are made unique across all Asterisk instances */
	SHARED_DB_TYPE_UNIQUE,
};

struct ast_db_entry {
	struct ast_db_entry *next;
	char *key;
	char data[0];
};

struct stasis_topic;
struct stasis_message_type;

struct ast_db_shared_family {
	/*! How the family is shared */
	enum ast_db_shared_type share_type;
	/*! Entries in the family, if appropriate */
	struct ast_db_entry *entries;
	/*! The name of the shared family */
	char name[0];
};

struct ast_db_entry *ast_db_entry_create(const char *key, const char *value);

struct ast_db_shared_family *ast_db_shared_family_alloc(const char *family, enum ast_db_shared_type share_type);

int ast_db_publish_shared_message(struct stasis_message_type *type, struct ast_db_shared_family *shared_family, struct ast_eid *eid);

void ast_db_refresh_shared(void);

/*! \addtogroup StasisTopicsAndMessages
 * @{
 */

struct stasis_topic *ast_db_cluster_topic(void);

/*!
 * \since 14
 * \brief Message type for an RTCP message sent from this Asterisk instance
 *
 * \retval A stasis message type
 */
struct stasis_message_type *ast_db_put_shared_type(void);

/*!
 * \since 14
 * \brief Message type for an RTCP message received from some external source
 *
 * \retval A stasis message type
 */
struct stasis_message_type *ast_db_del_shared_type(void);

/* }@ */

/*!
 * \brief @@@@
 */
int ast_db_put_shared(const char *family, enum ast_db_shared_type);

int ast_db_del_shared(const char *family);

int ast_db_is_shared(const char *family);

/*! \brief Get key value specified by family/key */
int ast_db_get(const char *family, const char *key, char *value, int valuelen);

/*!
 * \brief Get key value specified by family/key as a heap allocated string.
 *
 * \details
 * Given a \a family and \a key, sets \a out to a pointer to a heap
 * allocated string.  In the event of an error, \a out will be set to
 * NULL.  The string must be freed by calling ast_free().
 *
 * \retval -1 An error occurred
 * \retval 0 Success
 */
int ast_db_get_allocated(const char *family, const char *key, char **out);

/*! \brief Store value addressed by family/key */
int ast_db_put(const char *family, const char *key, const char *value);

/*! \brief Delete entry in astdb */
int ast_db_del(const char *family, const char *key);

/*!
 * \brief Delete one or more entries in astdb
 *
 * \details
 * If both parameters are NULL, the entire database will be purged.  If
 * only keytree is NULL, all entries within the family will be purged.
 * It is an error for keytree to have a value when family is NULL.
 *
 * \retval -1 An error occurred
 * \retval >= 0 Number of records deleted
 */
int ast_db_deltree(const char *family, const char *keytree);

/*!
 * \brief Get a list of values within the astdb tree
 *
 * \details
 * If family is specified, only those keys will be returned.  If keytree
 * is specified, subkeys are expected to exist (separated from the key with
 * a slash).  If subkeys do not exist and keytree is specified, the tree will
 * consist of either a single entry or NULL will be returned.
 *
 * Resulting tree should be freed by passing the return value to ast_db_freetree()
 * when usage is concluded.
 */
struct ast_db_entry *ast_db_gettree(const char *family, const char *keytree);

/*! \brief Free structure created by ast_db_gettree() */
void ast_db_freetree(struct ast_db_entry *entry);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _ASTERISK_ASTDB_H */
