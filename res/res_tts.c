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
 *
 * \brief Generic Text-To-Speech API
 *
 * \author Sean Bright <sean@malleable.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$");

#include "asterisk/channel.h"
#include "asterisk/module.h"
#include "asterisk/lock.h"
#include "asterisk/linkedlists.h"
#include "asterisk/cli.h"
#include "asterisk/term.h"
#include "asterisk/tts.h"
#include "asterisk/format_cache.h"

static AST_RWLIST_HEAD_STATIC(engines, ast_tts_engine);
static struct ast_tts_engine *default_engine = NULL;

/*! \brief Find a TTS engine of specified name, if NULL then use the default one */
static struct ast_tts_engine *find_engine(const char *engine_name)
{
	struct ast_tts_engine *engine = NULL;

	/* If no name is specified -- use the default engine */
	if (ast_strlen_zero(engine_name)) {
		return default_engine;
	}

	AST_RWLIST_RDLOCK(&engines);
	AST_RWLIST_TRAVERSE(&engines, engine, list) {
		if (!strcasecmp(engine->name, engine_name)) {
			break;
		}
	}
	AST_RWLIST_UNLOCK(&engines);

	return engine;
}

/*! \brief Register a TTS engine */
int ast_tts_register(struct ast_tts_engine *engine)
{
	int res = 0;

	if (!engine->speak) {
		ast_log(LOG_WARNING, "TTS engine '%s' did not meet minimum API requirements.\n", engine->name);
		return -1;
	}

	/* If an engine is already loaded with this name, error out */
	if (find_engine(engine->name)) {
		ast_log(LOG_WARNING, "TTS engine '%s' already exists.\n", engine->name);
		return -1;
	}

	ast_verb(2, "Registered TTS engine '%s'\n", engine->name);

	/* Add to the engine linked list and make default if needed */
	AST_RWLIST_WRLOCK(&engines);
	AST_RWLIST_INSERT_HEAD(&engines, engine, list);
	if (!default_engine) {
		default_engine = engine;
		ast_verb(2, "Made '%s' the default TTS engine\n", engine->name);
	}
	AST_RWLIST_UNLOCK(&engines);

	return res;
}

/*! \brief Unregister a TTS engine */
int ast_tts_unregister(const char *engine_name)
{
	struct ast_tts_engine *engine = NULL;
	int res = -1;

	if (ast_strlen_zero(engine_name))
		return -1;

	AST_RWLIST_WRLOCK(&engines);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&engines, engine, list) {
		if (!strcasecmp(engine->name, engine_name)) {
			/* We have our engine... removed it */
			AST_RWLIST_REMOVE_CURRENT(list);
			/* If this was the default engine, we need to pick a new one */
			if (engine == default_engine) {
				default_engine = AST_RWLIST_FIRST(&engines);
			}
			ast_verb(2, "Unregistered TTS  engine '%s'\n", engine_name);
			/* All went well */
			res = 0;
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	AST_RWLIST_UNLOCK(&engines);

	return res;
}

static int unload_module(void)
{
	/* We can not be unloaded */
	return -1;
}

static int load_module(void)
{
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Generic Text-To-Speech API",
		.support_level = AST_MODULE_SUPPORT_CORE,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_APP_DEPEND,
		);
