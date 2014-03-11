/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, Digium, Inc.
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
 * \brief Unreal channel bridging optimization module
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
#include "asterisk/bridge.h"
#include "asterisk/bridge_technology.h"
#include "asterisk/frame.h"
#include "asterisk/core_unreal.h"
#include "asterisk/taskprocessor.h"

/*!
 * \page bridge-unreal-impl Unreal Bridge Implementation Notes
 *
 * \par Requirements
 *
 * The bridge_unreal bridge technology requires at least one Local
 * channel to be present within a bridge using it. The second channel
 * MAY or MAY NOT be a second Local channel.
 *
 * \par Candidate Collection
 *
 * The bridge_unreal bridge technology collects candidates for optimization
 * when Local channels join the bridge. The bridge itself and the respective
 * peer channel are stored within the shared private structure of each Local
 * channel within the bridge.
 *
 * \par Candidate Usage
 *
 * If after storing candidate information candidates are available from both
 * the master and outbound Local channel a task is queued with all candidate
 * information to optimize the channels if possible. This task is queued in
 * a serialized fashion for execution on a thread outside of the bridging
 * framework and will be queued only once per set of candidates.
 *
 * \par Optimization Task
 *
 * The optimization task takes all candidates and performs a bridge move in a
 * direction permitted by the configuration of each bridge. If the bridge move
 * fails no retry is attempted.
 *
 * \par Resolving Chains
 *
 * Chains are automatically resolved by the implementation queueing multiple
 * optimization tasks as each hop in the chain is resolved. Since a task
 * preceeding another in the queue may result in the optimization candidates
 * becoming stale it is possible for the move attempt to fail. This will resolve
 * itself automatically as the action causing it to become stale will have
 * already queued a task with updated candidates. Once all tasks have been
 * attempted the chain will have been resolved as best as possible.
 */

/*! \brief Taskprocessor which optimizes things */
static struct ast_taskprocessor *taskprocessor;

/*! \brief Integer which is incremented to produce a unique id for optimization attempts */
static unsigned int optimization_id;

/*! \brief Task structure which contains information for optimizing unreal bridges */
struct optimize_task_data {
	/*! \brief Owner channel */
	struct ast_channel *owner;
	/*! \brief Bridge that the owner channel is in */
	struct ast_bridge *bridge_owner;
	/*! \brief Outbound channel */
	struct ast_channel *chan;
	/*! \brief Bridge that the outbound channel is in */
	struct ast_bridge *bridge_chan;
	/*! \brief Peer in the owner channel bridge */
	struct ast_channel *peer_owner;
	/*! \brief Peer in the outbound channel bridge */
	struct ast_channel *peer_chan;
	/*! \brief Optional callback functions */
	struct ast_unreal_pvt_callbacks *callbacks;
};

/*! \brief Destructor for optimize task data */
static void optimize_task_data_destroy(void *obj)
{
	struct optimize_task_data *task_data = obj;

	ast_channel_cleanup(task_data->owner);
	ao2_cleanup(task_data->bridge_owner);
	ast_channel_cleanup(task_data->chan);
	ao2_cleanup(task_data->bridge_chan);
	ast_channel_cleanup(task_data->peer_owner);
	ast_channel_cleanup(task_data->peer_chan);
}

/*! \brief Allocator for optimize task data */
static struct optimize_task_data *optimize_task_data_alloc(
	struct ast_channel *owner, struct ast_channel *chan,
	struct ast_bridge *bridge_owner, struct ast_bridge *bridge_chan,
	struct ast_channel *peer_owner, struct ast_channel *peer_chan,
	struct ast_unreal_pvt_callbacks *callbacks)
{
	struct optimize_task_data *task_data = ao2_alloc(sizeof(*task_data),
		optimize_task_data_destroy);

	if (!task_data) {
		return NULL;
	}

	task_data->owner = ast_channel_ref(owner);
	task_data->chan = ast_channel_ref(chan);
	task_data->bridge_owner = ao2_bump(bridge_owner);
	task_data->bridge_chan = ao2_bump(bridge_chan);
	task_data->peer_owner = ast_channel_ref(peer_owner);
	task_data->peer_chan = ast_channel_ref(peer_chan);
	task_data->callbacks = callbacks;

	return task_data;
}

/*! \brief Task callback for performing unreal channel optimization */
static int unreal_bridge_optimize_task(void *data)
{
	struct optimize_task_data *task_data = data;
	enum ast_bridge_optimization optimization = ast_bridges_allow_optimization(task_data->bridge_chan,
		task_data->bridge_owner);
	unsigned int id = ast_atomic_fetchadd_int((int *) &optimization_id, +1);
	struct ast_bridge *dst_bridge = NULL, *src_bridge = NULL;
	struct ast_channel *chan = NULL, *swap = NULL;
	int res = 0;

	switch (optimization) {
	case AST_BRIDGE_OPTIMIZE_SWAP_TO_CHAN_BRIDGE:
		dst_bridge = task_data->bridge_chan;
		src_bridge = task_data->bridge_owner;
		chan = task_data->peer_owner;
		swap = task_data->chan;
		break;
	case AST_BRIDGE_OPTIMIZE_SWAP_TO_PEER_BRIDGE:
		dst_bridge = task_data->bridge_owner;
		src_bridge = task_data->bridge_chan;
		chan = task_data->peer_chan;
		swap = task_data->owner;
		break;
	default:
		break;
	}

	/* If all required information is not present abort early */
	if (!dst_bridge || !src_bridge || !chan || !swap) {
		ao2_ref(task_data, -1);
		return 0;
	}

	if (task_data->callbacks && task_data->callbacks->optimization_started) {
		task_data->callbacks->optimization_started(task_data->owner, task_data->chan,
			chan, (swap == task_data->owner) ? AST_UNREAL_OWNER : AST_UNREAL_CHAN, id);
	}

	res = ast_bridge_move(dst_bridge, src_bridge, chan, swap, 1);

	if (task_data->callbacks && task_data->callbacks->optimization_finished) {
		task_data->callbacks->optimization_finished(task_data->owner, task_data->chan,
			!res ? 1 : 0, id);
	}

	ao2_ref(task_data, -1);
	return 0;
}

static int native_bridge_is_capable(struct ast_bridge_channel *bridge_channel, int *unreal)
{
	struct ast_unreal_pvt *pvt = ast_channel_tech_pvt(bridge_channel->chan);
	struct ast_channel *chan = bridge_channel->chan;

	ast_channel_lock(chan);

	if (ast_channel_has_audio_frame_or_monitor(chan)) {
		ast_debug(2, "Channel '%s' has an active monitor, audiohook, or framehook.\n",
			ast_channel_name(chan));
		ast_channel_unlock(chan);
		return 0;
	}

	if (ast_channel_tech(chan)->write != ast_unreal_write) {
		ast_debug(2, "Channel '%s' is not unreal.\n", ast_channel_name(chan));
		ast_channel_unlock(chan);
		/* Despite this being a non-unreal channel it is still compatible */
		return 1;
	}

	*unreal = 1;

	if (ast_test_flag(pvt, AST_UNREAL_NO_OPTIMIZATION)) {
		ast_debug(2, "Channel '%s' has explicitly disabled optimization.\n",
			ast_channel_name(chan));
		ast_channel_unlock(chan);
		return 0;
	}

	ast_channel_unlock(chan);

	return 1;
}

static int unreal_bridge_compatible(struct ast_bridge *bridge)
{
	struct ast_bridge_channel *c0 = AST_LIST_FIRST(&bridge->channels);
	struct ast_bridge_channel *c1 = AST_LIST_LAST(&bridge->channels);
	int c0_local = 0, c1_local = 0;

	/* We require two channels before even considering native bridging. */
	if (bridge->num_channels != 2) {
		ast_debug(1, "Bridge %s: Cannot use native unreal.  Must have two channels.\n",
			bridge->uniqueid);
		return 0;
	}

	if (!native_bridge_is_capable(c0, &c0_local)) {
		ast_debug(1, "Bridge %s: Cannot use native unreal. Channel '%s' not compatible.\n",
			bridge->uniqueid, ast_channel_name(c0->chan));
		return 0;
	}

	if (!native_bridge_is_capable(c1, &c1_local)) {
		ast_debug(1, "Bridge %s: Cannot use native unreal. Channel '%s' not compatible.\n",
			bridge->uniqueid, ast_channel_name(c1->chan));
		return 0;
	}

	if (!c0_local && !c1_local) {
		ast_debug(1, "Bridge %s: Cannot use native unreal. One channel must be of type unreal.\n",
			bridge->uniqueid);
		return 0;
	}

	return 1;
}

/*! \brief Helper function which updates the bridge on an unreal channel */
static void unreal_bridge_set(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel,
	struct ast_bridge_channel *other)
{
	struct ast_channel *chan = bridge_channel->chan;
	struct ast_unreal_pvt *pvt = ast_channel_tech_pvt(chan);
	int changed = 0;

	ast_channel_lock(chan);
	if (ast_channel_tech(chan)->write != ast_unreal_write) {
		ast_channel_unlock(chan);
		return;
	}
	ao2_lock(pvt);

	if (AST_UNREAL_IS_OUTBOUND(chan, pvt)) {
		if (pvt->bridge_chan != bridge) {
			changed = 1;
		}
		ao2_cleanup(pvt->bridge_chan);
		pvt->bridge_chan = ao2_bump(bridge);
		ast_channel_cleanup(pvt->bridged_chan);
		if (other) {
			if (pvt->bridged_chan != other->chan) {
				changed = 1;
			}
			pvt->bridged_chan = ast_channel_ref(other->chan);
		} else {
			pvt->bridged_chan = NULL;
		}
	} else {
		if (pvt->bridge_owner != bridge) {
			changed = 1;
		}
		ao2_cleanup(pvt->bridge_owner);
		pvt->bridge_owner = ao2_bump(bridge);
		ast_channel_cleanup(pvt->bridged_owner);
		if (other) {
			if (pvt->bridged_owner != other->chan) {
				changed = 1;
			}
			pvt->bridged_owner = ast_channel_ref(other->chan);
		} else {
			pvt->bridged_owner = NULL;
		}
	}

	/* If we have a bridge on both sides we can optimize */
	if (changed && pvt->bridge_owner && pvt->bridge_chan) {
		struct optimize_task_data *task_data = optimize_task_data_alloc(pvt->owner,
			pvt->chan, pvt->bridge_owner, pvt->bridge_chan, pvt->bridged_owner,
			pvt->bridged_chan, pvt->callbacks);

		ast_debug(1, "Queueing task to remove unreal channels between bridge '%s' and '%s'\n",
			pvt->bridge_owner->uniqueid, pvt->bridge_chan->uniqueid);

		if (ast_taskprocessor_push(taskprocessor, unreal_bridge_optimize_task, task_data)) {
			ast_log(LOG_WARNING, "Could not perform unreal channel optimization between '%s' and '%s'\n",
				pvt->bridge_owner->uniqueid, pvt->bridge_chan->uniqueid);
			ao2_ref(task_data, -1);
		}
	}

	ao2_unlock(pvt);
	ast_channel_unlock(chan);
}

static int unreal_bridge_join(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	struct ast_bridge_channel *c0 = AST_LIST_FIRST(&bridge->channels);
	struct ast_bridge_channel *c1 = AST_LIST_LAST(&bridge->channels);

	/* We can only do things once we have two channels */
	if (c0 == c1) {
		return 0;
	}

	/* Update the bridge on each unreal channel involved */
	unreal_bridge_set(bridge, c0, c1);
	unreal_bridge_set(bridge, c1, c0);

	return 0;
}

static void unreal_bridge_leave(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	unreal_bridge_set(NULL, bridge_channel, NULL);
}

static int unreal_bridge_write(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel, struct ast_frame *frame)
{
	return ast_bridge_queue_everyone_else(bridge, bridge_channel, frame);
}

static struct ast_bridge_technology unreal_bridge = {
	.name = "unreal_bridge",
	.capabilities = AST_BRIDGE_CAPABILITY_NATIVE,
	.preference = AST_BRIDGE_PREFERENCE_BASE_NATIVE,
	.compatible = unreal_bridge_compatible,
	.join = unreal_bridge_join,
	.leave = unreal_bridge_leave,
	.write = unreal_bridge_write,
};

static int unload_module(void)
{
	ast_taskprocessor_unreference(taskprocessor);
	ast_format_cap_destroy(unreal_bridge.format_capabilities);
	return ast_bridge_technology_unregister(&unreal_bridge);
}

static int load_module(void)
{
	char uuid[AST_UUID_STR_LEN];

	if (!(unreal_bridge.format_capabilities = ast_format_cap_alloc(0))) {
		return AST_MODULE_LOAD_DECLINE;
	}
	ast_format_cap_add_all_by_type(unreal_bridge.format_capabilities, AST_FORMAT_TYPE_AUDIO);
	ast_format_cap_add_all_by_type(unreal_bridge.format_capabilities, AST_FORMAT_TYPE_VIDEO);
	ast_format_cap_add_all_by_type(unreal_bridge.format_capabilities, AST_FORMAT_TYPE_TEXT);

	ast_uuid_generate_str(uuid, sizeof(uuid));
	if (!(taskprocessor = ast_taskprocessor_get(uuid, TPS_REF_DEFAULT))) {
		ast_format_cap_destroy(unreal_bridge.format_capabilities);
		return AST_MODULE_LOAD_DECLINE;
	}

	return ast_bridge_technology_register(&unreal_bridge);
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Unreal channel bridging module");
