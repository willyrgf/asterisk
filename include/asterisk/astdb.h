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

struct stasis_topic;
struct stasis_message_type;

enum ast_db_shared_type {
	/*! Items in the shared family are common across all Asterisk instances */
	DB_SHARE_TYPE_GLOBAL = 0,
	/*! Items in the shared family are made unique across all Asterisk instances */
	DB_SHARE_TYPE_UNIQUE,
};

/*! \brief An actual entry in the AstDB */
struct ast_db_entry {
	/*! The next entry, if there are multiple entries */
	struct ast_db_entry *next;
	/*! The key of the entry */
	char *key;
	/*! The data associated with the key */
	char data[0];
};

/*! \brief A shared family of keys in the AstDB */
struct ast_db_shared_family {
	/*! How the family is shared */
	enum ast_db_shared_type share_type;
	/*! Entries in the family, if appropriate */
	struct ast_db_entry *entries;
	/*! The name of the shared family */
	char name[0];
};

/*!
 * \since 14.0.0
 * \brief Create a new database entry
 *
 * \param key The key of the entry in the database
 * \param value The value of the entry
 *
 * \note The entry returned is allocated on the heap, and should be
 * disposed of using \ref ast_db_freetree
 *
 * \retval NULL on error
 * \retval \c ast_db_entry on success
 */
struct ast_db_entry *ast_db_entry_create(const char *key, const char *value);

/*!
 * \since 14.0.0
 * \brief Create a shared database family
 *
 * \param family The family to share
 * \param share_type The way in which the family should be shared
 *
 * \note The \c ast_db_shared_family structure is an \c ao2 ref counted
 * object.
 *
 * \retval NULL on error
 * \retval an \c ao2 ref counted \c ast_db_shared_family object
 */
struct ast_db_shared_family *ast_db_shared_family_alloc(const char *family,
	enum ast_db_shared_type share_type);

/*! \addtogroup StasisTopicsAndMessages
 * @{
 */

/*!
 * \since 14.0.0
 * \brief Topic for families that should be passed to clustered Asterisk
 *        instances
 *
 * \retval A stasis topic
 */
struct stasis_topic *ast_db_cluster_topic(void);

/*!
 * \since 14.0.0
 * \brief Message type for an update to a shared family
 *
 * \retval A stasis message type
 */
struct stasis_message_type *ast_db_put_shared_type(void);

/*!
 * \since 14.0.0
 * \brief Message type for deletion of a shared family
 *
 * \retval A stasis message type
 */
struct stasis_message_type *ast_db_del_shared_type(void);

/* }@ */

/*!
 * \since 14.0.0
 * \brief Publish a message for a shared family
 *
 * \param type The \c stasis_message_type indicating what happened to
               the shared family
 * \param shared_family The shared family that was updated
 * \param eid The server that conveyed the update
 *
 * \retval 0 success
 * \retval -1 error
 */
int ast_db_publish_shared_message(struct stasis_message_type *type,
	struct ast_db_shared_family *shared_family, struct ast_eid *eid);

/*!
 * \since 14.0.0
 * \brief Refresh the state of all shared families
 *
 * \details
 * This will cause Stasis messages to be generated that contain the current
 * key/value pairs of all shared families. This can be used to send the state
 * of all shared families to other Asterisk instances.
 */
void ast_db_refresh_shared(void);

/*!
 * \since 14.0.0
 * \brief Add a new shared family
 *
 * \param family The family to share
 * \param share_type The way in which the family should be shared
 *
 * \retval 0 success
 * \retval -1 failure
 */
int ast_db_put_shared(const char *family, enum ast_db_shared_type share_type);

/*!
 * \since 14.0.0
 * \brief Delete a shared family
 *
 * \param family The family whose shared status should be removed
 *
 * \retval 0 success
 * \retval -1 failure
 */
int ast_db_del_shared(const char *family);

/*!
 * \since 14.0.0
 * \brief Check if a family is shared
 *
 * \param family The family to verify
 *
 * \retval 0 The family is not shared
 * \retval 1 The family is shared
 */
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
