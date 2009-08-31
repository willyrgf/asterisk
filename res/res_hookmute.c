/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
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
 * \brief MUTE audiohooks
 *
 * \author Olle E. Johansson <oej@edvina.net>
 *
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 89545 $")

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>

#include "asterisk/callerid.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/module.h"
#include "asterisk/config.h"
#include "asterisk/file.h"
#include "asterisk/pbx.h"
#include "asterisk/frame.h"
#include "asterisk/utils.h"
#include "asterisk/audiohook.h"



/* Our own datastore */
struct mute_information {
	struct ast_audiohook audiohook;
	int mute_write;
	int mute_read;
};


#define TRUE 1
#define FALSE 0

/*! Datastore destroy audiohook callback */
static void destroy_callback(void *data)
{
	struct mute_information *mute = data;
	ast_log(LOG_DEBUG, "***** About to destroy mute audiohook for this channel\n");

	/* Destroy the audiohook, and destroy ourselves */
	ast_audiohook_destroy(&mute->audiohook);
	free(mute);
	ast_log(LOG_DEBUG, "***** Destroying mute audiohook for this channel\n");

	return;
}

/*! \brief Static structure for datastore information */
static const struct ast_datastore_info mute_datastore = {
	.type = "mute",
	.destroy = destroy_callback
};

/*! \brief Wipe out all audio samples from an ast_frame. Clean it. */
static void ast_frame_clear(struct ast_frame *frame)
{
	struct ast_frame *next;

	for (next = AST_LIST_NEXT(frame, frame_list);
		frame;
		frame = next, next = frame ? AST_LIST_NEXT(frame, frame_list) : NULL) {

		ast_log(LOG_DEBUG, "     ---- CLEANING FRAME ---- Datalen %d\n", frame->datalen);
 		memset(frame->data, frame->datalen, 0);
        }
}


static int mute_callback(struct ast_audiohook *audiohook, struct ast_channel *chan, struct ast_frame *frame, enum ast_audiohook_direction direction)
{
	struct ast_datastore *datastore = NULL;
	struct mute_information *mute = NULL;

	ast_log(LOG_DEBUG, "''' Mute callback on %s \n", chan ? chan->name : "No channel");

	/* If the audiohook is stopping it means the channel is shutting down.... but we let the datastore destroy take care of it */
	if (audiohook->status == AST_AUDIOHOOK_STATUS_DONE) {
		ast_log(LOG_DEBUG, " *** We're done here. Good bye.\n");
		return 0;
	}

	ast_channel_lock(chan);
	/* Grab datastore which contains our mute information */
	if (!(datastore = ast_channel_datastore_find(chan, &mute_datastore, NULL))) {
		ast_log(LOG_DEBUG, " *** Can't find any datastore to use. Bad. \n");
		return 0;
	}

	mute = datastore->data;


	/* If this is audio then allow them to increase/decrease the gains */
	if (frame->frametype == AST_FRAME_VOICE) {
		ast_log(LOG_DEBUG, "''' Audio frame - direction %s  mute READ %s WRITE %s\n", direction == AST_AUDIOHOOK_DIRECTION_READ ? "read" : "write", mute->mute_read ? "on" : "off", mute->mute_write ? "on" : "off");
		
		/* Based on direction of frame grab the gain, and confirm it is applicable */
		if ((direction == AST_AUDIOHOOK_DIRECTION_READ && mute->mute_read) || (direction == AST_AUDIOHOOK_DIRECTION_WRITE && mute->mute_write)) {
			/* Ok, we just want to reset all audio in this frame. Keep NOTHING, thanks. */
 			ast_frame_clear(frame);
		}
	/* DTMF Just for debugging - kind of stupid */
	} else if (frame->frametype == AST_FRAME_DTMF) {
		ast_log(LOG_DEBUG, "*** Frame is a DTMF frame\n");
		if (frame->subclass == '1') {
			mute->mute_read = TRUE;
			mute->mute_write = TRUE;
		} else if (frame->subclass == '0') {
			mute->mute_read = FALSE;
			mute->mute_write = FALSE;
			ast_log(LOG_DEBUG, "*** Turning off mute \n");
		}
	} else {
		ast_log(LOG_DEBUG, "*** Frame is not a  voice or DTMF frame. What is it? -- %d\n", frame->frametype);
	}
	ast_channel_unlock(chan);

	return 0;
}

static struct ast_datastore *initialize_mutehook(struct ast_channel *chan)
{
	struct ast_datastore *datastore = NULL;
	struct mute_information *mute = NULL;

	ast_log(LOG_DEBUG, "**** Initializing new Mute Audiohook \n");
	/* Allocate a new datastore to hold the reference to this mute_datastore and audiohook information */
	if (!(datastore = ast_channel_datastore_alloc(&mute_datastore, NULL))) {
		return NULL;
	}

	if (!(mute = ast_calloc(1, sizeof(*mute)))) {
		ast_channel_datastore_free(datastore);
		return NULL;
	}
	ast_audiohook_init(&mute->audiohook, AST_AUDIOHOOK_TYPE_MANIPULATE, "Mute");
	mute->audiohook.manipulate_callback = mute_callback;
	/* For debugging control, listen to DTMF */
	ast_set_flag(&mute->audiohook, AST_AUDIOHOOK_WANTS_DTMF);
	datastore->data = mute;
	return datastore;
}

static int func_mute_write(struct ast_channel *chan, char *cmd, char *data, const char *value)
{
	struct ast_datastore *datastore = NULL;
	struct mute_information *mute = NULL;
	int is_new = 0;

	ast_log(LOG_DEBUG, "**** Mute write - data %s value %s \n", data, value);

	if (!(datastore = ast_channel_datastore_find(chan, &mute_datastore, NULL))) {
		if (!(datastore = initialize_mutehook(chan))) {
			return 0;
		}
		is_new = 1;
	} 

	mute = datastore->data;

	if (!strcasecmp(data, "out")) {
		mute->mute_write = ast_true(value);
		if (ast_true(value))
			ast_log(LOG_DEBUG, "*** Muting channel - outbound *** \n");
		else
			ast_log(LOG_DEBUG, "*** UN-Muting channel - outbound *** \n");
	}

	else if (!strcasecmp(data, "in")){
		mute->mute_read = ast_true(value);
		if (ast_true(value))
			ast_log(LOG_DEBUG, "*** Muting channel - inbound *** \n");
		else
			ast_log(LOG_DEBUG, "*** UN-Muting channel - inbound *** \n");
	}
	/* DEBUG */
	mute->mute_read = TRUE;
	mute->mute_write = TRUE;

	if (is_new) {
		/* Activate the settings */
		ast_channel_datastore_add(chan, datastore);
		if(ast_audiohook_attach(chan, &mute->audiohook))
			ast_log(LOG_DEBUG, "*** Failed to attach audiohook for muting!\n");
		ast_log(LOG_DEBUG, "*** Initialized audiohook on channel %s\n", chan->name);
	}

	return 0;
}

/* Function for debugging - might be useful */
static struct ast_custom_function mute_function = {
        .name = "MUTE",
        .write = func_mute_write,
	.synopsis = "Muting the channel, totally and utterly",
	.syntax = "MUTE(in|out) = true|false",
	.desc = "Use this function instead of shouting SHUT UP.",
};



static int reload(void)
{
	return 0;
}

static int load_module(void)
{
	ast_custom_function_register(&mute_function);
	return 0;
}

static int unload_module(void)
{
	ast_custom_function_unregister(&mute_function);
	/* Can't unload this once we're loaded */
	return -1;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS, "MUTE resource",
		.load = load_module,
		.unload = unload_module,
		.reload = reload,
	       );
