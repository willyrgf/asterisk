/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2009, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
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
 * \brief Built in bridging features
 *
 * \author Joshua Colp <jcolp@digium.com>
 *
 * \ingroup bridges
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/bridging.h"
#include "asterisk/bridging_technology.h"
#include "asterisk/frame.h"
#include "asterisk/file.h"
#include "asterisk/app.h"
#include "asterisk/astobj2.h"
#include "asterisk/pbx.h"

/*!
 * \brief Helper function that presents dialtone and grabs extension
 *
 * \retval 0 on success
 * \retval -1 on failure
 */
static int grab_transfer(struct ast_channel *chan, char *exten, size_t exten_len, const char *context)
{
	int res;

	/* Play the simple "transfer" prompt out and wait */
	res = ast_stream_and_wait(chan, "pbx-transfer", AST_DIGIT_ANY);
	ast_stopstream(chan);
	if (res < 0) {
		/* Hangup or error */
		return -1;
	}
	if (res) {
		/* Store the DTMF digit that interrupted playback of the file. */
		exten[0] = res;
	}

	/* Drop to dialtone so they can enter the extension they want to transfer to */
/* BUGBUG the timeout needs to be configurable from features.conf. */
	res = ast_app_dtget(chan, context, exten, exten_len, exten_len - 1, 3000);
	if (res < 0) {
		/* Hangup or error */
		res = -1;
	} else if (!res) {
		/* 0 for invalid extension dialed. */
		if (ast_strlen_zero(exten)) {
			ast_debug(1, "%s dialed no digits.\n", ast_channel_name(chan));
		} else {
			ast_debug(1, "%s dialed '%s@%s' does not exist.\n",
				ast_channel_name(chan), exten, context);
		}
		ast_stream_and_wait(chan, "pbx-invalid", AST_DIGIT_NONE);
		res = -1;
	} else {
		/* Dialed extension is valid. */
		res = 0;
	}
	return res;
}

/*! \brief Helper function that creates an outgoing channel and returns it immediately */
static struct ast_channel *dial_transfer(struct ast_channel *caller, const char *exten, const char *context)
{
	char destination[AST_MAX_EXTENSION + AST_MAX_CONTEXT + 1];
	struct ast_channel *chan;
	int cause;

	/* Fill the variable with the extension and context we want to call */
/* BUGBUG if local channel optimization is using masquerades then this needs /n so the destination keeps its DTMF features.
 * Or use /n to keep the peer channel stable until after the atxfer completes and remove the /n from the channel.
 *
 * Local channel optimization currently is disabled because I don't set the chan->bridge pointers.
 */
	snprintf(destination, sizeof(destination), "%s@%s", exten, context);

	/* Now we request that chan_local prepare to call the destination */
	chan = ast_request("Local", ast_channel_nativeformats(caller), caller, destination,
		&cause);
	if (!chan) {
		return NULL;
	}

	/* Before we actually dial out let's inherit appropriate information. */
	ast_channel_lock_both(caller, chan);
	ast_connected_line_copy_from_caller(ast_channel_connected(chan), ast_channel_caller(caller));
	ast_channel_inherit_variables(caller, chan);
	ast_channel_datastore_inherit(caller, chan);
	ast_channel_unlock(chan);
	ast_channel_unlock(caller);

	/* Since the above worked fine now we actually call it and return the channel */
	if (ast_call(chan, destination, 0)) {
		ast_hangup(chan);
		return NULL;
	}

	return chan;
}

/*!
 * \internal
 * \brief Determine the transfer context to use.
 * \since 12.0.0
 *
 * \param transferer Channel initiating the transfer.
 * \param context User supplied context if available.  May be NULL.
 *
 * \return The context to use for the transfer.
 */
static const char *get_transfer_context(struct ast_channel *transferer, const char *context)
{
	if (!ast_strlen_zero(context)) {
		return context;
	}
	context = pbx_builtin_getvar_helper(transferer, "TRANSFER_CONTEXT");
	if (!ast_strlen_zero(context)) {
		return context;
	}
	context = ast_channel_macrocontext(transferer);
	if (!ast_strlen_zero(context)) {
		return context;
	}
	context = ast_channel_context(transferer);
	if (!ast_strlen_zero(context)) {
		return context;
	}
	return "default";
}

/*! \brief Internal built in feature for blind transfers */
static int feature_blind_transfer(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel, void *hook_pvt)
{
	char exten[AST_MAX_EXTENSION] = "";
	struct ast_channel *chan = NULL;
	struct ast_bridge_features_blind_transfer *blind_transfer = hook_pvt;
	const char *context;

/* BUGBUG the peer needs to be put on hold for the transfer. */
	ast_channel_lock(bridge_channel->chan);
	context = ast_strdupa(get_transfer_context(bridge_channel->chan,
		blind_transfer ? blind_transfer->context : NULL));
	ast_channel_unlock(bridge_channel->chan);

	/* Grab the extension to transfer to */
	if (grab_transfer(bridge_channel->chan, exten, sizeof(exten), context)) {
		return 0;
	}

/* BUGBUG just need to ast_async_goto the peer so this bridge will go away and not accumulate local channels and bridges if the destination is to an application. */
/* ast_async_goto actually is a blind transfer. */
/* BUGBUG Use the bridge count to determine if can do DTMF transfer features.  If count is not 2 then don't allow it. */

	/* Get a channel that is the destination we wish to call */
	chan = dial_transfer(bridge_channel->chan, exten, context);
	if (!chan) {
		return 0;
	}

	/* Impart the new channel onto the bridge, and have it take our place. */
	if (ast_bridge_impart(bridge, chan, bridge_channel->chan, NULL, 1)) {
		ast_hangup(chan);
		return 0;
	}

	return 0;
}

/*! \brief Attended transfer feature to turn it into a threeway call */
static int attended_threeway_transfer(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel, void *hook_pvt)
{
	/*
	 * This is sort of abusing the depart state but in this instance
	 * it is only going to be handled by feature_attended_transfer()
	 * so it is okay.
	 */
	ast_bridge_change_state(bridge_channel, AST_BRIDGE_CHANNEL_STATE_DEPART);
	return 0;
}

/*! \brief Internal built in feature for attended transfers */
static int feature_attended_transfer(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel, void *hook_pvt)
{
	char exten[AST_MAX_EXTENSION] = "";
	struct ast_channel *peer;
	struct ast_bridge *attended_bridge;
	struct ast_bridge_features caller_features;
	enum ast_bridge_channel_state attended_bridge_result;
	int xfer_failed;
	struct ast_bridge_features_attended_transfer *attended_transfer = hook_pvt;
	const char *context;

/* BUGBUG the peer needs to be put on hold for the transfer. */
	ast_channel_lock(bridge_channel->chan);
	context = ast_strdupa(get_transfer_context(bridge_channel->chan,
		attended_transfer ? attended_transfer->context : NULL));
	ast_channel_unlock(bridge_channel->chan);

	/* Grab the extension to transfer to */
	if (grab_transfer(bridge_channel->chan, exten, sizeof(exten), context)) {
		return 0;
	}

	/* Get a channel that is the destination we wish to call */
	peer = dial_transfer(bridge_channel->chan, exten, context);
	if (!peer) {
		ast_stream_and_wait(bridge_channel->chan, "beeperr", AST_DIGIT_NONE);
		return 0;
	}

/* BUGBUG we need to wait for Party C (peer) to answer before dumping into the transient B-C bridge. */

	/* Create a bridge to use to talk to the person we are calling */
	attended_bridge = ast_bridge_new(AST_BRIDGE_CAPABILITY_NATIVE | AST_BRIDGE_CAPABILITY_1TO1MIX,
		AST_BRIDGE_FLAG_DISSOLVE_HANGUP);
	if (!attended_bridge) {
		ast_hangup(peer);
/* BUGBUG beeperr needs to be configurable from features.conf */
		ast_stream_and_wait(bridge_channel->chan, "beeperr", AST_DIGIT_NONE);
		return 0;
	}

	/* This is how this is going down, we are imparting the channel we called above into this bridge first */
/* BUGBUG we should impart the peer as an independent and move it to the original bridge. */
	if (ast_bridge_impart(attended_bridge, peer, NULL, NULL, 0)) {
		ast_bridge_destroy(attended_bridge);
		ast_hangup(peer);
		ast_stream_and_wait(bridge_channel->chan, "beeperr", AST_DIGIT_NONE);
		return 0;
	}

	/* Before we join setup a features structure with the hangup option, just in case they want to use DTMF */
	ast_bridge_features_init(&caller_features);
/* BUGBUG bridging API features does not support features.conf featuremap */
/* BUGBUG bridging API features does not support the features.conf atxfer bounce between C & B channels */
/* BUGBUG The atxfer feature hooks need to be passed a pointer to where to mark which hook happened.  Rather than relying on the bridge join return value. */
	ast_bridge_features_enable(&caller_features, AST_BRIDGE_BUILTIN_HANGUP,
		attended_transfer && !ast_strlen_zero(attended_transfer->complete)
			? attended_transfer->complete : "*1",
		NULL);
	ast_bridge_features_hook(&caller_features,
		attended_transfer && !ast_strlen_zero(attended_transfer->threeway)
			? attended_transfer->threeway : "*2",
		attended_threeway_transfer, NULL, NULL);

	/* But for the caller we want to join the bridge in a blocking fashion so we don't spin around in this function doing nothing while waiting */
	attended_bridge_result = ast_bridge_join(attended_bridge, bridge_channel->chan, NULL, &caller_features, NULL, 0);

	/* Wait for peer thread to exit bridge and die. */
	if (!ast_autoservice_start(bridge_channel->chan)) {
		ast_bridge_depart(attended_bridge, peer);
		ast_autoservice_stop(bridge_channel->chan);
	} else {
		ast_bridge_depart(attended_bridge, peer);
	}

	/* Now that all channels are out of it we can destroy the bridge and the feature structures */
	ast_bridge_features_cleanup(&caller_features);
	ast_bridge_destroy(attended_bridge);

	xfer_failed = -1;
	switch (attended_bridge_result) {
	case AST_BRIDGE_CHANNEL_STATE_END:
		if (!ast_check_hangup_locked(bridge_channel->chan)) {
			/* Transferer aborted the transfer. */
			break;
		}

		/* The peer takes our place in the bridge. */
		ast_bridge_change_state(bridge_channel, AST_BRIDGE_CHANNEL_STATE_HANGUP);
		xfer_failed = ast_bridge_impart(bridge, peer, bridge_channel->chan, NULL, 1);
		break;
	case AST_BRIDGE_CHANNEL_STATE_HANGUP:
		/* Peer hungup */
		break;
	case AST_BRIDGE_CHANNEL_STATE_DEPART:
		/*
		 * Transferer wants to convert to a threeway call.
		 *
		 * Just impart the peer onto the bridge and have us return to it
		 * as normal.
		 */
		xfer_failed = ast_bridge_impart(bridge, peer, NULL, NULL, 1);
		break;
	default:
		break;
	}
	if (xfer_failed) {
		ast_hangup(peer);
		if (!ast_check_hangup_locked(bridge_channel->chan)) {
			ast_stream_and_wait(bridge_channel->chan, "beeperr", AST_DIGIT_NONE);
		}
	}

	return 0;
}

/*! \brief Internal built in feature for hangup */
static int feature_hangup(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel, void *hook_pvt)
{
	/*
	 * This is very simple, we simply change the state on the
	 * bridge_channel to force the channel out of the bridge and the
	 * core takes care of the rest.
	 */
	ast_bridge_change_state(bridge_channel, AST_BRIDGE_CHANNEL_STATE_END);
	return 0;
}

static int unload_module(void)
{
	return 0;
}

static int load_module(void)
{
	ast_bridge_features_register(AST_BRIDGE_BUILTIN_BLINDTRANSFER, feature_blind_transfer, NULL);
	ast_bridge_features_register(AST_BRIDGE_BUILTIN_ATTENDEDTRANSFER, feature_attended_transfer, NULL);
	ast_bridge_features_register(AST_BRIDGE_BUILTIN_HANGUP, feature_hangup, NULL);

	/* Bump up our reference count so we can't be unloaded */
	ast_module_ref(ast_module_info->self);

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Built in bridging features");
