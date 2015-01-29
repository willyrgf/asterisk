/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2014, Digium, Inc.
 *
 * Matt Jordan <mjordan@digium.com>
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
 * \brief AGI Extension interfaces - Asterisk Gateway Interface
 */

#ifndef _ASTERISK_MEDIA_CACHE_H
#define _ASTERISK_MEDIA_CACHE_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

struct ast_variable;

/*!
 * \brief
 *
 * \param uri
 *
 * \retval 0 uri does not exist in cache
 * \retval 1 uri does exist in cache
 */
int ast_media_cache_exists(const char *uri);

int ast_media_cache_retrieve(const char *uri, const char *preferred_file_name,
	char *file_path, size_t len);

int ast_media_cache_retrieve_metadata(const char *uri, const char *key,
	char *value, size_t len);

int ast_media_cache_create_or_update(const char *uri, const char *file_path,
	struct ast_variable *metadata);

int ast_media_cache_delete(const char *uri);

int ast_media_cache_init(void);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _ASTERISK_MEDIA_CACHE_H */
