/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, malleable, LLC.
 *
 * Sean Bright <sean@malleable.com>
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
 * \brief Generic Text-To-Speech API
 */

#ifndef _ASTERISK_TTS_H
#define _ASTERISK_TTS_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

struct ast_tts_engine {
	/*! Name of TTS engine */
	char *name;
	AST_LIST_ENTRY(ast_tts_engine) list;
};

/*! \brief Register a TTS engine */
int ast_tts_register(struct ast_tts_engine *engine);
/*! \brief Unregister a TTS engine */
int ast_tts_unregister(const char *engine_name);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _ASTERISK_TTS_H */
