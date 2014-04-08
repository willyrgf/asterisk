/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, Olle E. Johansson
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
 * \brief Silence Detection and suppression audiohooks
 *
 * \author Olle E. Johansson <oej@edvina.net>
 *
 *
 * This is an internal API and have no functions, applications or other cool stuff to expose to the admin.
 * 
 * If this audiohook is applied, we listen for silence and when silence has been detected for a certain 
 * number of frames in a row, we replace the frame with a CNG frame and then (want to) drop frames until
 * we have audio again. Right now the code just clears the frame.
 *
 * \note This code only handles audio streams 
 * 	For silence in video, check Ingmar Bergman movies on Wikipedia. We have
 *	no current way to detect video "silence" so we can't optimize that type of movies.
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/options.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/file.h"
#include "asterisk/pbx.h"
#include "asterisk/frame.h"
#include "asterisk/utils.h"
#include "asterisk/audiohook.h"
#include "asterisk/dsp.h"
#include "asterisk/silencedetection.h"


/*! Our own datastore */
struct silence_detection_info {
	struct ast_audiohook audiohook;
	struct ast_dsp *dsp;			/*!< DSP used for silence detection */
	unsigned int silencelevel;		/*!< Silence treshold */
        unsigned int silenceframes;		/*!< How many frames to wait for silence before activating silence
							support and sending CNG */
        unsigned int silencecounter;		/*!< Frame Counter used for silence detection. */
	int detect;				/*!< Silence detected */
	int active;
};


#define TRUE 1
#define FALSE 0

/*! Datastore destroy audiohook callback */
static void destroy_callback(void *data)
{
	struct silence_detection_info *sildet = data;

	ast_dsp_free(sildet->dsp);
	sildet->dsp = NULL;

	/* Destroy the audiohook, and destroy ourselves */
	ast_audiohook_destroy(&sildet->audiohook);
	ast_free(sildet);

	return;
}

/*! \brief Static structure for datastore information */
static const struct ast_datastore_info sildet_datastore = {
	.type = "sildet",
	.destroy = destroy_callback
};

/*! \brief The callback from the audiohook subsystem. We basically get a frame to have fun with 
	Return TRUE to keep original packet
	Return FALSE to use our packet
*/
static int silence_detection_callback(struct ast_audiohook *audiohook, struct ast_channel *chan, struct ast_frame *frame, enum ast_audiohook_direction direction)
{
	struct ast_datastore *datastore = NULL;
	struct silence_detection_info *sildet = NULL;

	if (direction != AST_AUDIOHOOK_DIRECTION_WRITE) {
		return 1;
	}

	/* If the audiohook is stopping it means the channel is shutting down.... but we let the datastore destroy take care of it */
	if (audiohook->status == AST_AUDIOHOOK_STATUS_DONE) {
		ast_debug(7, "Audiohook giving up - STATUS_DONE \n");
		return 1;
	}

	ast_channel_lock(chan);
	/* Grab datastore which contains our mute information */
	if (!(datastore = ast_channel_datastore_find(chan, &sildet_datastore, NULL))) {
		ast_channel_unlock(chan);
		ast_debug(2, "Can't find any datastore to use. Bad. \n");
		return 1;
	}

	sildet = datastore->data;
	if (!sildet || !sildet->dsp) {
		ast_channel_unlock(chan);
		ast_debug(2, "Can't find any DSP to use. Bad. \n");
		return 1;
	}

	/* If this is audio then allow them to increase/decrease the gains */
	if (frame->frametype == AST_FRAME_VOICE) {
		int dsptime = 0;

		/* Based on direction of frame grab the gain, and confirm it is applicable */
		if (direction == AST_AUDIOHOOK_DIRECTION_WRITE) {
			ast_dsp_silence(sildet->dsp, frame, &dsptime);	/* Checking for silence */
			if (!dsptime) {
				if (option_debug && sildet->silencecounter > 0) {
					ast_debug(8, " ++++ Silence stopped ++++ on chan %s\n", chan->name);
				}
				if (sildet->silencecounter > 0) {
					sildet->silencecounter = 0;		/* No more silence */
					sildet->detect = 0;		/* No more silence */
				}
				ast_debug(9, " ++++ We are not silent on write to %s (dsptime %d)\n", chan->name, dsptime);
			} else {
				if (option_debug && sildet->silencecounter == 0) {
					ast_debug(9, "          ++++ Silence starts here %d ++++ on chan %s dsptime %d\n", sildet->silencecounter, chan->name, dsptime);
				}
				if (option_debug && sildet->silencecounter > 0) {
					ast_debug(9, "          ++++ Silence continues %d ++++ on chan %s dsptime %d\n", sildet->silencecounter, chan->name, dsptime);
				}
				sildet->silencecounter++;
				if (sildet->detect == 1 && sildet->silencecounter > sildet->silenceframes) {
					ast_frame_clear(frame);		/* Should really be dropped. */
        				frame->samples = 0;
					frame->datalen = 0;
					
					frame->frametype = AST_FRAME_DROP;
					ast_channel_unlock(chan);
					return 0;	/* Return TRUE since we manipulated the frame */
				}
			}
			if (sildet->detect == 0 && sildet->silencecounter > sildet->silenceframes) {
				ast_debug(8, "++++ Silence suppression should start now ++++ on chan %s\n", chan->name);
				sildet->detect = 1;
				ast_frame_clear(frame);
				frame->frametype = AST_FRAME_CNG;
        			frame->subclass.integer =  0x7f;
        			frame->samples = 0;
				ast_channel_unlock(chan);
				return 0;	/* Return TRUE since we manipulated the frame */
			}
			/* Do not touch the frame yet */
		}
	}
	ast_channel_unlock(chan);

	return 1;
}

/*! \brief Initialize mute hook on channel, but don't activate it
	\pre Assumes that the channel is locked
*/
static struct ast_datastore *initialize_sildethook(struct ast_channel *chan)
{
	struct ast_datastore *datastore = NULL;
	struct silence_detection_info *sildet = NULL;

	ast_debug(2, "Initializing new Silence Detection Audiohook \n");

	/* Allocate a new datastore to hold the reference to this sildet_datastore and audiohook information */
	if (!(datastore = ast_datastore_alloc(&sildet_datastore, NULL))) {
		return NULL;
	}

	if (!(sildet = ast_calloc(1, sizeof(*sildet)))) {
		ast_datastore_free(datastore);
		return NULL;
	}
	if (!(sildet->dsp = ast_dsp_new())) {
		/* We failed to create a DSP */
		ast_log(LOG_WARNING, "Unable to create silence detector :(\n");
		ast_free(sildet);
		ast_datastore_free(datastore);
		return NULL;
	}
	ast_audiohook_init(&sildet->audiohook, AST_AUDIOHOOK_TYPE_MANIPULATE, "Sildet");
	sildet->audiohook.manipulate_callback = silence_detection_callback;
	sildet->active = 1;
	sildet->silencecounter = 0;
	sildet->detect = 0;
	datastore->data = sildet;
	return datastore;
}

/*! \brief Add or activate mute audiohook on channel
	Assumes channel is locked
*/
static int sildet_add_audiohook(struct ast_channel *chan, struct silence_detection_info *sildet, struct ast_datastore *datastore)
{
	/* Activate the settings */
	ast_channel_datastore_add(chan, datastore);
	if (ast_audiohook_attach(chan, &sildet->audiohook)) {
		ast_log(LOG_ERROR, "Failed to attach audiohook for silence detection on channel %s\n", chan->name);
		return -1;
	}
	ast_debug(2, "Initialized audiohook for silence detection on channel %s\n", chan->name);
	return 0;
}

/*! \brief Activation of silence detection */
int ast_sildet_activate(struct ast_channel *chan, unsigned int silencelevel, unsigned int silenceframes)
{
	struct ast_datastore *datastore = NULL;
	struct silence_detection_info *sildet = NULL;

	int is_new = 0;

	if (!chan) {
		ast_log(LOG_WARNING, "No channel was provided.\n" );
		return -1;
	}
	if (silenceframes < 3) {
		ast_log(LOG_WARNING, "Silenceframes is set very low. Are you sure? Value=%d\n", silenceframes);
	}
	ast_debug(4, "----> Setting up silence detection/suppression with silence level %d and silence frames %d for chan %s\n", silencelevel, silenceframes, chan->name);

	ast_channel_lock(chan);
	ast_debug(4, "----> Looking for silence detection datastore for %s\n", chan->name);
	if (!(datastore = ast_channel_datastore_find(chan, &sildet_datastore, NULL))) {
		if (!(datastore = initialize_sildethook(chan))) {
			ast_debug(4, "----> Failed to initialize hook for silence detection for %s\n", chan->name);
			ast_channel_unlock(chan);
			return 0;
		}
		is_new = 1;
	}

	/* Configure the silence detection */
	sildet = datastore->data;
	if (!sildet) {
		ast_debug(4, "----> No datastore data for silence detection for %s\n", chan->name);
		ast_channel_unlock(chan);
		return 0;
	}
	if (!sildet->dsp) {
		ast_debug(4, "----> No datastore dsp for silence detection for %s\n", chan->name);
		ast_channel_unlock(chan);
		return 0;
	}
	ast_debug(4, "----> Looking for silence detection datastore for %s\n", chan->name);
	ast_dsp_set_threshold(sildet->dsp, silencelevel);
	sildet->silencelevel = silencelevel;
	sildet->silenceframes = silenceframes;
	sildet->active = 1;
	sildet->silencecounter = 0;
	sildet->detect = 0;

	if (is_new) {
		if (sildet_add_audiohook(chan, sildet, datastore)) {
			/* Can't add audiohook - already printed error message */
			ast_datastore_free(datastore);
			ast_free(sildet);
		}
	}
	ast_channel_unlock(chan);

	return 1;
}

int ast_sildet_deactivate(struct ast_channel *chan)
{
	struct ast_datastore *datastore = NULL;
	struct silence_detection_info *sildet = NULL;
	if (!chan) {
		ast_log(LOG_WARNING, "No channel was provided.\n" );
		return -1;
	}
	ast_channel_lock(chan);
	if (!(datastore = ast_channel_datastore_find(chan, &sildet_datastore, NULL))) {
		ast_debug(4, "----> No silence detection datastore  for %s\n", chan->name);
		ast_channel_unlock(chan);
		return 0;
	}
	sildet = datastore->data;
	if (!sildet) {
		ast_debug(4, "----> No datastore data for silence detection for %s\n", chan->name);
		ast_channel_unlock(chan);
		return 0;
	}
	sildet->active = 0;
	ast_audiohook_detach(&sildet->audiohook);
	ast_channel_unlock(chan);
	return 1;
}
