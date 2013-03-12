/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2007 - 2009, Digium, Inc.
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
 * \brief Channel Bridging API
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <signal.h>

#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/linkedlists.h"
#include "asterisk/bridging.h"
#include "asterisk/bridging_technology.h"
#include "asterisk/app.h"
#include "asterisk/file.h"
#include "asterisk/module.h"
#include "asterisk/astobj2.h"
#include "asterisk/pbx.h"
#include "asterisk/test.h"

#include "asterisk/heap.h"
#include "asterisk/say.h"
#include "asterisk/timing.h"
#include "asterisk/stringfields.h"
#include "asterisk/musiconhold.h"
#include "asterisk/features.h"

static AST_RWLIST_HEAD_STATIC(bridge_technologies, ast_bridge_technology);

/* Initial starting point for the bridge array of channels */
#define BRIDGE_ARRAY_START 128

/* Grow rate of bridge array of channels */
#define BRIDGE_ARRAY_GROW 32

static void cleanup_video_mode(struct ast_bridge *bridge);
static int bridge_make_compatible(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel);
static int smart_bridge_operation(struct ast_bridge *bridge);

/*! Default DTMF keys for built in features */
static char builtin_features_dtmf[AST_BRIDGE_BUILTIN_END][MAXIMUM_DTMF_FEATURE_STRING];

/*! Function handlers for the built in features */
static void *builtin_features_handlers[AST_BRIDGE_BUILTIN_END];

/*! Function handlers for built in interval features */
static void *builtin_interval_handlers[AST_BRIDGE_BUILTIN_INTERVAL_END];

/*! Bridge manager service request */
struct bridge_manager_request {
	/*! List of bridge service requests. */
	AST_LIST_ENTRY(bridge_manager_request) node;
	/*! Refed bridge requesting service. */
	struct ast_bridge *bridge;
};

struct bridge_manager_controller {
	/*! Condition, used to wake up the bridge manager thread. */
	ast_cond_t cond;
	/*! Queue of bridge service requests. */
	AST_LIST_HEAD_NOLOCK(, bridge_manager_request) service_requests;
	/*! Manager thread */
	pthread_t thread;
	/*! TRUE if the manager needs to stop. */
	unsigned int stop:1;
};

/*! Bridge manager controller. */
static struct bridge_manager_controller *bridge_manager;

/*!
 * \brief Request service for a bridge from the bridge manager.
 * \since 12.0.0
 *
 * \param bridge Requesting service.
 *
 * \return Nothing
 */
void ast_bridge_manager_service_req(struct ast_bridge *bridge);//BUGBUG not used yet
void ast_bridge_manager_service_req(struct ast_bridge *bridge)
{
	struct bridge_manager_request *request;

	ao2_lock(bridge_manager);
	if (bridge_manager->stop) {
		ao2_unlock(bridge_manager);
		return;
	}

	/* Create the service request. */
	request = ast_calloc(1, sizeof(*request));
	if (!request) {
		/* Well. This isn't good. */
		ao2_unlock(bridge_manager);
		return;
	}
	ao2_ref(bridge, +1);
	request->bridge = bridge;

	/* Put request into the queue and wake the bridge manager. */
	AST_LIST_INSERT_TAIL(&bridge_manager->service_requests, request, node);
	ast_cond_signal(&bridge_manager->cond);
	ao2_unlock(bridge_manager);
}

int __ast_bridge_technology_register(struct ast_bridge_technology *technology, struct ast_module *module)
{
	struct ast_bridge_technology *current;

	/* Perform a sanity check to make sure the bridge technology conforms to our needed requirements */
	if (ast_strlen_zero(technology->name)
		|| !technology->capabilities
		|| !technology->write) {
		ast_log(LOG_WARNING, "Bridge technology %s failed registration sanity check.\n",
			technology->name);
		return -1;
	}

	AST_RWLIST_WRLOCK(&bridge_technologies);

	/* Look for duplicate bridge technology already using this name, or already registered */
	AST_RWLIST_TRAVERSE(&bridge_technologies, current, entry) {
		if ((!strcasecmp(current->name, technology->name)) || (current == technology)) {
			ast_log(LOG_WARNING, "A bridge technology of %s already claims to exist in our world.\n",
				technology->name);
			AST_RWLIST_UNLOCK(&bridge_technologies);
			return -1;
		}
	}

	/* Copy module pointer so reference counting can keep the module from unloading */
	technology->mod = module;

	/* Insert our new bridge technology into the list and print out a pretty message */
	AST_RWLIST_INSERT_TAIL(&bridge_technologies, technology, entry);

	AST_RWLIST_UNLOCK(&bridge_technologies);

	ast_verb(2, "Registered bridge technology %s\n", technology->name);

	return 0;
}

int ast_bridge_technology_unregister(struct ast_bridge_technology *technology)
{
	struct ast_bridge_technology *current;

	AST_RWLIST_WRLOCK(&bridge_technologies);

	/* Ensure the bridge technology is registered before removing it */
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&bridge_technologies, current, entry) {
		if (current == technology) {
			AST_RWLIST_REMOVE_CURRENT(entry);
			ast_verb(2, "Unregistered bridge technology %s\n", technology->name);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	AST_RWLIST_UNLOCK(&bridge_technologies);

	return current ? 0 : -1;
}

void ast_bridge_channel_poke(struct ast_bridge_channel *bridge_channel)
{
	if (!pthread_equal(pthread_self(), bridge_channel->thread)) {
		bridge_channel->poked = 1;
		pthread_kill(bridge_channel->thread, SIGURG);
		ast_cond_signal(&bridge_channel->cond);
	}
}

static void bridge_channel_poke_locked(struct ast_bridge_channel *bridge_channel)
{
	ao2_lock(bridge_channel);
	ast_bridge_channel_poke(bridge_channel);
	ao2_unlock(bridge_channel);
}

void ast_bridge_change_state_nolock(struct ast_bridge_channel *bridge_channel, enum ast_bridge_channel_state new_state)
{
/* BUGBUG need cause code for the bridge_channel leaving the bridge. */
	if (bridge_channel->state != AST_BRIDGE_CHANNEL_STATE_WAIT) {
		return;
	}

	ast_debug(1, "Setting bridge channel %p(%s) state from:%d to:%d\n",
		bridge_channel, ast_channel_name(bridge_channel->chan), bridge_channel->state,
		new_state);

	/* Change the state on the bridge channel */
	bridge_channel->state = new_state;

	ast_bridge_channel_poke(bridge_channel);
}

void ast_bridge_change_state(struct ast_bridge_channel *bridge_channel, enum ast_bridge_channel_state new_state)
{
	ao2_lock(bridge_channel);
	ast_bridge_change_state_nolock(bridge_channel, new_state);
	ao2_unlock(bridge_channel);
}

int ast_bridge_queue_action(struct ast_bridge *bridge, struct ast_frame *action)
{
	struct ast_frame *dup;

	dup = ast_frdup(action);
	if (!dup) {
		return -1;
	}

	ast_debug(1, "Queueing action type:%d sub:%d on bridge %p\n",
		action->frametype, action->subclass.integer, bridge);

	ao2_lock(bridge);
	AST_LIST_INSERT_TAIL(&bridge->action_queue, dup, frame_list);
	bridge->interrupt = 1;
	ast_bridge_poke(bridge);
	ao2_unlock(bridge);
	return 0;
}

int ast_bridge_channel_queue_action(struct ast_bridge_channel *bridge_channel, struct ast_frame *action)
{
	struct ast_frame *dup;

	dup = ast_frdup(action);
	if (!dup) {
		return -1;
	}

	ast_debug(1, "Queueing action type:%d sub:%d on bridge channel %p(%s)\n",
		action->frametype, action->subclass.integer, bridge_channel,
		ast_channel_name(bridge_channel->chan));

	ao2_lock(bridge_channel);
	AST_LIST_INSERT_TAIL(&bridge_channel->action_queue, dup, frame_list);
	ast_bridge_channel_poke(bridge_channel);
	ao2_unlock(bridge_channel);
	return 0;
}

void ast_bridge_channel_restore_formats(struct ast_bridge_channel *bridge_channel)
{
	/* Restore original formats of the channel as they came in */
	if (ast_format_cmp(ast_channel_readformat(bridge_channel->chan), &bridge_channel->read_format) == AST_FORMAT_CMP_NOT_EQUAL) {
		ast_debug(1, "Bridge is returning bridge channel %p(%s) to read format %s\n",
			bridge_channel, ast_channel_name(bridge_channel->chan),
			ast_getformatname(&bridge_channel->read_format));
		if (ast_set_read_format(bridge_channel->chan, &bridge_channel->read_format)) {
			ast_debug(1, "Bridge failed to return bridge channel %p(%s) to read format %s\n",
				bridge_channel, ast_channel_name(bridge_channel->chan),
				ast_getformatname(&bridge_channel->read_format));
		}
	}
	if (ast_format_cmp(ast_channel_writeformat(bridge_channel->chan), &bridge_channel->write_format) == AST_FORMAT_CMP_NOT_EQUAL) {
		ast_debug(1, "Bridge is returning bridge channel %p(%s) to write format %s\n",
			bridge_channel, ast_channel_name(bridge_channel->chan),
			ast_getformatname(&bridge_channel->write_format));
		if (ast_set_write_format(bridge_channel->chan, &bridge_channel->write_format)) {
			ast_debug(1, "Bridge failed to return bridge channel %p(%s) to write format %s\n",
				bridge_channel, ast_channel_name(bridge_channel->chan),
				ast_getformatname(&bridge_channel->write_format));
		}
	}
}

void ast_bridge_poke(struct ast_bridge *bridge)
{
	/* Poke the thread just in case */
	if (bridge->thread != AST_PTHREADT_NULL) {
		pthread_kill(bridge->thread, SIGURG);
		ast_cond_signal(&bridge->cond);
	}
}

/*!
 * \internal
 * \brief Stop the bridge.
 * \since 12.0.0
 *
 * \note This function assumes the bridge is locked.
 *
 * \return Nothing
 */
static void bridge_stop(struct ast_bridge *bridge)
{
	pthread_t thread;

	bridge->stop = 1;
	bridge->interrupt = 1;
	ast_bridge_poke(bridge);
	thread = bridge->thread;
	bridge->thread = AST_PTHREADT_NULL;
	ao2_unlock(bridge);
	pthread_join(thread, NULL);
	ao2_lock(bridge);
	bridge->stop = 0;
}

/*!
 * \internal
 * \brief Grow the bridge array size.
 * \since 12.0.0
 *
 * \param bridge Grow the array on this bridge.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int bridge_array_grow(struct ast_bridge *bridge)
{
	struct ast_channel **new_array;

	ast_debug(1, "Growing bridge array on %p from %u to %u\n",
		bridge, bridge->array_size, bridge->array_size + BRIDGE_ARRAY_GROW);
	new_array = ast_realloc(bridge->array,
		(bridge->array_size + BRIDGE_ARRAY_GROW) * sizeof(*bridge->array));
	if (!new_array) {
		return -1;
	}
	bridge->array = new_array;
	bridge->array_size += BRIDGE_ARRAY_GROW;
	return 0;
}

/*!
 * \brief Helper function to add a channel to the bridge array
 *
 * \note This function assumes the bridge is locked.
 */
static void bridge_array_add(struct ast_bridge *bridge, struct ast_channel *chan)
{
	/* We have to make sure the bridge thread is not using the bridge array before messing with it */
	while (bridge->waiting) {
		ast_bridge_poke(bridge);
		sched_yield();
	}

	/* If this addition cannot be held by the array, grow it or quit. */
	if (bridge->array_num == bridge->array_size
		&& bridge_array_grow(bridge)) {
		return;
	}

	bridge->array[bridge->array_num++] = chan;

	ast_debug(1, "Added channel %s to bridge array on %p, new count is %u\n",
		ast_channel_name(chan), bridge, bridge->array_num);

	/* If the next addition of a channel will exceed our array size grow it out */
	if (bridge->array_num == bridge->array_size) {
		bridge_array_grow(bridge);
	}
}

/*!
 * \brief Helper function to remove a channel from the bridge array
 *
 * \note This function assumes the bridge is locked.
 */
static void bridge_array_remove(struct ast_bridge *bridge, struct ast_channel *chan)
{
	unsigned int idx;

	/* We have to make sure the bridge thread is not using the bridge array before messing with it */
	while (bridge->waiting) {
		ast_bridge_poke(bridge);
		sched_yield();
	}

	for (idx = 0; idx < bridge->array_num; ++idx) {
		if (bridge->array[idx] == chan) {
			--bridge->array_num;
			bridge->array[idx] = bridge->array[bridge->array_num];
			ast_debug(1, "Removed channel %s from bridge array on %p, new count is %u\n",
				ast_channel_name(chan), bridge, bridge->array_num);
			break;
		}
	}
}

/*! \brief Helper function to find a bridge channel given a channel */
static struct ast_bridge_channel *find_bridge_channel(struct ast_bridge *bridge, struct ast_channel *chan)
{
	struct ast_bridge_channel *bridge_channel;

	AST_LIST_TRAVERSE(&bridge->channels, bridge_channel, entry) {
		if (bridge_channel->chan == chan) {
			break;
		}
	}

	return bridge_channel;
}

/*!
 * \internal
 * \brief Pull the bridge channel out of its current bridge.
 * \since 12.0.0
 *
 * \param bridge_channel Channel to pull.
 *
 * \note On entry, the bridge is already locked.
 *
 * \return Nothing
 */
static void ast_bridge_channel_pull(struct ast_bridge_channel *bridge_channel)
{
	struct ast_bridge *bridge = bridge_channel->bridge;

	ao2_lock(bridge_channel);
	if (!bridge_channel->in_bridge) {
		ao2_unlock(bridge_channel);
		return;
	}
	bridge_channel->in_bridge = 0;
	ao2_unlock(bridge_channel);

	ast_debug(1, "Pulling bridge channel %p(%s) from bridge %p\n",
		bridge_channel, ast_channel_name(bridge_channel->chan), bridge);

	if (!bridge_channel->just_joined) {
		/* Tell the bridge technology we are leaving so they tear us down */
		ast_debug(1, "Giving bridge technology %s notification that %p(%s) is leaving bridge %p\n",
			bridge->technology->name, bridge_channel,
			ast_channel_name(bridge_channel->chan), bridge);
		if (bridge->technology->leave) {
			bridge->technology->leave(bridge, bridge_channel);
		}
	}

	/* Remove channel from the bridge */
	if (!bridge_channel->suspended) {
		bridge_array_remove(bridge, bridge_channel->chan);
	}
	--bridge->num_channels;
	AST_LIST_REMOVE(&bridge->channels, bridge_channel, entry);

	/* Wake up the bridge to recognize the reconfiguration. */
	bridge->reconfigured = 1;
	bridge->interrupt = 1;
	ast_bridge_poke(bridge);
}

/*!
 * \internal
 * \brief Push the bridge channel into its specified bridge.
 * \since 12.0.0
 *
 * \param bridge_channel Channel to push.
 *
 * \note On entry, the bridge is already locked.
 *
 * \return Nothing
 */
static void ast_bridge_channel_push(struct ast_bridge_channel *bridge_channel)
{
	struct ast_bridge *bridge = bridge_channel->bridge;
	struct ast_channel *swap;

	ao2_lock(bridge_channel);
	ast_assert(!bridge_channel->in_bridge);

	if (bridge->dissolved) {
		/* Force out channel being pushed into a dissolved bridge. */
		ast_bridge_change_state_nolock(bridge_channel, AST_BRIDGE_CHANNEL_STATE_HANGUP);
	}
	if (bridge_channel->state != AST_BRIDGE_CHANNEL_STATE_WAIT) {
		/* Don't push a channel in the process of leaving. */
		ao2_unlock(bridge_channel);
		return;
	}

	bridge_channel->in_bridge = 1;
	bridge_channel->just_joined = 1;
	swap = bridge_channel->swap;
	bridge_channel->swap = NULL;
	ao2_unlock(bridge_channel);

	if (swap) {
		struct ast_bridge_channel *bridge_channel2;

		bridge_channel2 = find_bridge_channel(bridge, swap);
		if (bridge_channel2) {
			ast_debug(1, "Swapping bridge channel %p(%s) out from bridge %p so bridge channel %p(%s) can slip in\n",
				bridge_channel2, ast_channel_name(bridge_channel2->chan), bridge,
				bridge_channel, ast_channel_name(bridge_channel->chan));
			ast_bridge_change_state(bridge_channel2, AST_BRIDGE_CHANNEL_STATE_HANGUP);

			ast_bridge_channel_pull(bridge_channel2);
		}
	}

	ast_debug(1, "Pushing bridge channel %p(%s) into bridge %p\n",
		bridge_channel, ast_channel_name(bridge_channel->chan), bridge);

	/* Add channel to the bridge */
	AST_LIST_INSERT_TAIL(&bridge->channels, bridge_channel, entry);
	++bridge->num_channels;
	if (!bridge_channel->suspended) {
		bridge_array_add(bridge, bridge_channel->chan);
	}

	/* Wake up the bridge to complete joining the bridge. */
	bridge->reconfigured = 1;
	bridge->interrupt = 1;
	ast_bridge_poke(bridge);
}

/*!
 * \internal
 * \brief Force out all channels that are not already going out of the bridge.
 * \since 12.0.0
 *
 * \param bridge Bridge to eject all channels
 *
 * \note On entry, bridge is already locked.
 *
 * \return Nothing
 */
static void bridge_force_out_all(struct ast_bridge *bridge)
{
	struct ast_bridge_channel *bridge_channel;

	bridge->dissolved = 1;

/* BUGBUG need a cause code on the bridge for the later ejected channels. */
	AST_LIST_TRAVERSE(&bridge->channels, bridge_channel, entry) {
		ast_bridge_change_state(bridge_channel, AST_BRIDGE_CHANNEL_STATE_HANGUP);
	}
}

/*!
 * \internal
 * \brief Check if a bridge should dissolve and then do it.
 * \since 12.0.0
 *
 * \param bridge Bridge to check.
 * \param bridge_channel Channel causing the check.
 *
 * \note On entry, bridge is already locked.
 *
 * \return Nothing
 */
static void bridge_check_dissolve(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	if (!ast_test_flag(&bridge->feature_flags, AST_BRIDGE_FLAG_DISSOLVE_HANGUP)
		&& (!bridge_channel->features
			|| !bridge_channel->features->usable
			|| !ast_test_flag(&bridge_channel->features->feature_flags, AST_BRIDGE_FLAG_DISSOLVE_HANGUP))) {
		return;
	}

	ast_debug(1, "Dissolving bridge %p\n", bridge);
	bridge_force_out_all(bridge);
}

/*! \brief Internal function to handle DTMF from a channel */
static struct ast_frame *bridge_handle_dtmf(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel, struct ast_frame *frame)
{
	struct ast_bridge_features *features;
	struct ast_bridge_hook *hook;

	features = bridge_channel->features;
	if (!features) {
		features = &bridge->features;
	}

	/* If the features structure we grabbed is not usable, immediately return the frame */
	if (!features->usable) {
		return frame;
	}

/* BUGBUG the feature hook matching needs to be done here.  Any matching feature hook needs to be queued onto the bridge_channel.  Also the feature hook digit timeout needs to be handled. */
	/* See if this DTMF matches the beginnings of any feature hooks, if so we switch to the feature state to either execute the feature or collect more DTMF */
	AST_LIST_TRAVERSE(&features->dtmf_hooks, hook, entry) {
		if (hook->parms.dtmf.code[0] == frame->subclass.integer) {
			struct ast_frame action = {
				.frametype = AST_FRAME_BRIDGE_ACTION,
				.subclass.integer = AST_BRIDGE_ACTION_FEATURE,
			};

			ast_frfree(frame);
			frame = NULL;
			ast_bridge_channel_queue_action(bridge_channel, &action);
			break;
		}
	}

	return frame;
}

/*!
 * \internal
 * \brief Handle bridge hangup event.
 * \since 12.0.0
 *
 * \param bridge Bridge involved in a hangup.
 * \param bridge_channel Which channel is hanging up.
 *
 * \return Nothing
 */
static void bridge_handle_hangup(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	struct ast_bridge_features *features;

	features = bridge_channel->features;
	if (!features) {
		features = &bridge->features;
	}

	if (features->usable) {
		struct ast_bridge_hook *hook;

		/* Run any hangup hooks. */
		AST_LIST_TRAVERSE_SAFE_BEGIN(&features->hangup_hooks, hook, entry) {
			int failed;

			failed = hook->callback(bridge, bridge_channel, hook->hook_pvt);
			if (failed) {
				ast_debug(1, "Hangup hook %p is being removed from bridge channel %p(%s)\n",
					hook, bridge_channel, ast_channel_name(bridge_channel->chan));
				AST_LIST_REMOVE_CURRENT(entry);
				if (hook->destructor) {
					hook->destructor(hook->hook_pvt);
				}
				ast_free(hook);
			}
		}
		AST_LIST_TRAVERSE_SAFE_END;
	}

	/* Default hangup action. */
	ast_bridge_change_state(bridge_channel, AST_BRIDGE_CHANNEL_STATE_END);
}

static int bridge_channel_interval_ready(struct ast_bridge_channel *bridge_channel)
{
	struct ast_bridge_hook *hook;

	if (!bridge_channel->features || !bridge_channel->features->usable
		|| !bridge_channel->features->interval_hooks) {
		return 0;
	}

	hook = ast_heap_peek(bridge_channel->features->interval_hooks, 1);
	if (!hook || ast_tvdiff_ms(hook->parms.timer.trip_time, ast_tvnow()) > 0) {
		return 0;
	}

	return 1;
}

/*! \brief Internal function used to determine whether a control frame should be dropped or not */
static int bridge_drop_control_frame(int subclass)
{
/* BUGBUG I think this code should be removed. Let the bridging tech determine what to do with control frames. */
#if 1
	/* Block all control frames. */
	return 1;
#else
	switch (subclass) {
	case AST_CONTROL_READ_ACTION:
	case AST_CONTROL_CC:
	case AST_CONTROL_MCID:
	case AST_CONTROL_AOC:
	case AST_CONTROL_CONNECTED_LINE:
	case AST_CONTROL_REDIRECTING:
		return 1;

	case AST_CONTROL_ANSWER:
	case -1:
		return 1;
	default:
		return 0;
	}
#endif
}

void ast_bridge_notify_talking(struct ast_bridge_channel *bridge_channel, int started_talking)
{
	struct ast_frame action = {
		.frametype = AST_FRAME_BRIDGE_ACTION,
		.subclass.integer = started_talking
			? AST_BRIDGE_ACTION_TALKING_START : AST_BRIDGE_ACTION_TALKING_STOP,
	};

	ast_bridge_channel_queue_action(bridge_channel, &action);
}

void ast_bridge_handle_trip(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel, struct ast_channel *chan)
{
	struct ast_timer *interval_timer;

	/* If no bridge channel has been provided and the actual channel has been provided find it */
	if (chan && !bridge_channel) {
		bridge_channel = find_bridge_channel(bridge, chan);
	}

	if (bridge_channel && bridge_channel->features
		&& (interval_timer = bridge_channel->features->interval_timer)) {
		if (ast_wait_for_input(ast_timer_fd(interval_timer), 0) == 1) {
			ast_timer_ack(interval_timer, 1);
			if (bridge_channel_interval_ready(bridge_channel)) {
				struct ast_frame interval_action = {
					.frametype = AST_FRAME_BRIDGE_ACTION,
					.subclass.integer = AST_BRIDGE_ACTION_INTERVAL,
				};

				ast_bridge_channel_queue_action(bridge_channel, &interval_action);
			}
		}
	}

	/* If a bridge channel with actual channel is present read a frame and handle it */
	if (chan && bridge_channel) {
		struct ast_frame *frame;

		if (bridge->features.mute
			|| (bridge_channel->features && bridge_channel->features->mute)) {
			frame = ast_read_noaudio(chan);
		} else {
			frame = ast_read(chan);
		}
		/* This is pretty simple... see if they hung up */
		if (!frame || (frame->frametype == AST_FRAME_CONTROL && frame->subclass.integer == AST_CONTROL_HANGUP)) {
			bridge_handle_hangup(bridge, bridge_channel);
		} else if (frame->frametype == AST_FRAME_CONTROL && bridge_drop_control_frame(frame->subclass.integer)) {
			ast_debug(1, "Dropping control frame %d from bridge channel %p(%s)\n",
				frame->subclass.integer, bridge_channel,
				ast_channel_name(bridge_channel->chan));
		} else if (frame->frametype == AST_FRAME_DTMF_BEGIN || frame->frametype == AST_FRAME_DTMF_END) {
			int dtmf_passthrough = bridge_channel->features ?
				bridge_channel->features->dtmf_passthrough :
				bridge->features.dtmf_passthrough;

			if (frame->frametype == AST_FRAME_DTMF_BEGIN) {
				frame = bridge_handle_dtmf(bridge, bridge_channel, frame);
			}

			if (frame && dtmf_passthrough) {
				bridge->technology->write(bridge, bridge_channel, frame);
			}
		} else {
/* BUGBUG looks like the place to handle the control frame exchange between 1-1 bridge participants is the bridge tech write callback. */
/* BUGBUG make a 1-1 bridge write handler for control frames. */
/* BUGBUG make bridge_channel thread run the CONNECTED_LINE and REDIRECTING interception macros. */
/* BUGBUG should we assume that all parties need to be already answered when bridged? */
/* BUGBUG should make AST_CONTROL_ANSWER do an ast_indicate(-1) to the bridge peer if it is not UP as well as a connected line update. */
/* BUGBUG bridge join or impart needs to do CONNECTED_LINE updates if the channels are being swapped and it is a 1-1 bridge. */
/* BUGBUG could make a queue of things the bridge_channel thread needs to handle in case it gets behind on processing because of the interception macros. */
			/* Simply write the frame out to the bridge technology if it still exists */
			bridge->technology->write(bridge, bridge_channel, frame);
		}

		if (frame) {
			ast_frfree(frame);
		}
		return;
	}

	/* If all else fails just poke the bridge channel */
	if (bridge->technology->poke_channel && bridge_channel) {
		bridge->technology->poke_channel(bridge, bridge_channel);
		return;
	}
}

int ast_bridge_thread_generic(struct ast_bridge *bridge)
{
	if (bridge->interrupt || !bridge->array_num) {
		return 0;
	}
	for (;;) {
		struct ast_channel *winner;
		int to = -1;

		/* Move channels around for priority reasons if we have more than one channel in our array */
		if (bridge->array_num > 1) {
			struct ast_channel *first = bridge->array[0];
			memmove(bridge->array, bridge->array + 1, sizeof(struct ast_channel *) * (bridge->array_num - 1));
			bridge->array[(bridge->array_num - 1)] = first;
		}

		/* Wait on the channels */
		bridge->waiting = 1;
		ao2_unlock(bridge);
		winner = ast_waitfor_n(bridge->array, bridge->array_num, &to);
		bridge->waiting = 0;
		ao2_lock(bridge);

		if (bridge->interrupt || !bridge->array_num) {
			return 0;
		}

		/* Process whatever they did */
		ast_bridge_handle_trip(bridge, NULL, winner);
	}
}

/*!
 * \internal
 * \brief Complete joining new channels to the bridge.
 * \since 12.0.0
 *
 * \param bridge Check for new channels on this bridge.
 *
 * \note On entry, bridge is already locked.
 *
 * \return Nothing
 */
static void bridge_complete_join(struct ast_bridge *bridge)
{
	struct ast_bridge_channel *bridge_channel;

	if (bridge->dissolved) {
		/*
		 * No sense in completing the join on channels for a dissolved
		 * bridge.  They are just going to be removed soon anyway.
		 * However, we do have reason to abort here because the bridge
		 * technology may not be able to handle the number of channels
		 * still in the bridge.
		 */
		return;
	}

	AST_LIST_TRAVERSE(&bridge->channels, bridge_channel, entry) {
		if (!bridge_channel->just_joined) {
			continue;
		}

		/* Make the channel compatible with the bridge */
		bridge_make_compatible(bridge, bridge_channel);

		/* Tell the bridge technology we are joining so they set us up */
		ast_debug(1, "Giving bridge technology %s notification that %p(%s) is joining bridge %p\n",
			bridge->technology->name, bridge_channel,
			ast_channel_name(bridge_channel->chan), bridge);
		if (bridge->technology->join
			&& bridge->technology->join(bridge, bridge_channel)) {
			ast_debug(1, "Bridge technology %s failed to join %p(%s) to bridge %p\n",
				bridge->technology->name, bridge_channel,
				ast_channel_name(bridge_channel->chan), bridge);
		}

		/*
		 * Poke the bridge channel, this will cause it to wake up and
		 * execute the proper threading model for the bridge.
		 */
		ao2_lock(bridge_channel);
		bridge_channel->just_joined = 0;
		ast_bridge_channel_poke(bridge_channel);
		ao2_unlock(bridge_channel);
	}
}

/*!
 * \internal
 * \brief Handle bridge action frame.
 * \since 12.0.0
 *
 * \param bridge What to execute the action on.
 * \param action What to do.
 *
 * \note This function assumes the bridge is locked.
 *
 * \return Nothing
 */
static void bridge_action_bridge(struct ast_bridge *bridge, struct ast_frame *action)
{
	/*! \todo BUGBUG bridge_action() not written */
}

/*!
 * \brief Bridge thread function
 *
 * \note The thread does not have its own reference to the
 * bridge.  The bridge ao2 object destructor will stop the
 * thread if it is running.
 */
void *bridge_thread(void *data);//BUGBUG not used
void *bridge_thread(void *data)
{
	struct ast_bridge *bridge = data;
	struct ast_frame *action;
	int res = 0;

	if (bridge->callid) {
		ast_callid_threadassoc_add(bridge->callid);
	}

	ast_debug(1, "Started bridge thread for %p\n", bridge);

	ao2_lock(bridge);

	/* Loop around until we are told to stop */
	while (!bridge->stop) {
		bridge->interrupt = 0;

		if (bridge->reconfigured) {
			bridge->reconfigured = 0;
			if (ast_test_flag(&bridge->feature_flags, AST_BRIDGE_FLAG_SMART)
				&& smart_bridge_operation(bridge)) {
				/* Smart bridge failed.  Dissolve the bridge. */
				bridge_force_out_all(bridge);
				break;
			}
			bridge_complete_join(bridge);
		}

		/* Run a pending bridge action. */
		action = AST_LIST_REMOVE_HEAD(&bridge->action_queue, frame_list);
		if (action) {
			switch (action->frametype) {
			case AST_FRAME_BRIDGE_ACTION:
				bridge_action_bridge(bridge, action);
				break;
			default:
				/* Unexpected deferred frame type.  Should never happen. */
				ast_assert(0);
				break;
			}
			ast_frfree(action);
			continue;
		}

		if (!bridge->array_num || !bridge->technology->thread_loop) {
			/* Wait for something to happen to the bridge. */
			ast_cond_wait(&bridge->cond, ao2_object_get_lockaddr(bridge));
			continue;
		}

		res = bridge->technology->thread_loop(bridge);
		if (res) {
			/*
			 * A bridge error occurred.  Sleep and try again later so we
			 * won't flood the logs.
			 */
			ao2_unlock(bridge);
			sleep(1);
			ao2_lock(bridge);
		}
	}

	ao2_unlock(bridge);

	ast_debug(1, "Ending bridge thread for %p\n", bridge);

	return NULL;
}

/*! \brief Helper function used to find the "best" bridge technology given a specified capabilities */
static struct ast_bridge_technology *find_best_technology(uint32_t capabilities)
{
	struct ast_bridge_technology *current;
	struct ast_bridge_technology *best = NULL;

	AST_RWLIST_RDLOCK(&bridge_technologies);
	AST_RWLIST_TRAVERSE(&bridge_technologies, current, entry) {
		if (current->suspended) {
			ast_debug(1, "Bridge technology %s is suspended. Skipping.\n",
				current->name);
			continue;
		}
		if (!(current->capabilities & capabilities)) {
			ast_debug(1, "Bridge technology %s does not have the capabilities we need.\n",
				current->name);
			continue;
		}
		if (best && best->preference < current->preference) {
			ast_debug(1, "Bridge technology %s has preference %d while %s has preference %d. Skipping.\n",
				current->name, current->preference, best->name, best->preference);
			continue;
		}
		best = current;
	}

	if (best) {
		/* Increment it's module reference count if present so it does not get unloaded while in use */
		ast_module_ref(best->mod);
		ast_debug(1, "Chose bridge technology %s\n", best->name);
	}

	AST_RWLIST_UNLOCK(&bridge_technologies);

	return best;
}

static void destroy_bridge(void *obj)
{
	struct ast_bridge *bridge = obj;
	struct ast_frame *action;

	ast_debug(1, "Actually destroying bridge %p, nobody wants it anymore\n", bridge);

	/* There should not be any channels left in the bridge. */
	ast_assert(AST_LIST_EMPTY(&bridge->channels));

	ao2_lock(bridge);
	if (bridge->thread != AST_PTHREADT_NULL) {
		bridge_stop(bridge);
	}
	ao2_unlock(bridge);

	if (bridge->callid) {
		bridge->callid = ast_callid_unref(bridge->callid);
	}

	/* Flush any unhandled actions. */
	while ((action = AST_LIST_REMOVE_HEAD(&bridge->action_queue, frame_list))) {
		ast_frfree(action);
	}

	cleanup_video_mode(bridge);

	/* Clean up the features configuration */
	ast_bridge_features_cleanup(&bridge->features);

	/* Pass off the bridge to the technology to destroy if needed */
	ast_debug(1, "Giving bridge technology %s the bridge structure %p to destroy\n",
		bridge->technology->name, bridge);
	if (bridge->technology->destroy) {
		bridge->technology->destroy(bridge);
	}
	ast_module_unref(bridge->technology->mod);

	/* Drop the array of channels */
	ast_free(bridge->array);
	ast_cond_destroy(&bridge->cond);
}

struct ast_bridge *ast_bridge_new(uint32_t capabilities, int flags)
{
	struct ast_bridge *bridge;
	struct ast_bridge_technology *bridge_technology;

	/* If we need to be a smart bridge see if we can move between 1to1 and multimix bridges */
	if (flags & AST_BRIDGE_FLAG_SMART) {
		if (!ast_bridge_check((capabilities & AST_BRIDGE_CAPABILITY_1TO1MIX)
			? AST_BRIDGE_CAPABILITY_MULTIMIX : AST_BRIDGE_CAPABILITY_1TO1MIX)) {
			return NULL;
		}
	}

	/*
	 * If capabilities were provided use our helper function to find
	 * the "best" bridge technology, otherwise we can just look for
	 * the most basic capability needed, single 1to1 mixing.
	 */
	bridge_technology = capabilities
		? find_best_technology(capabilities)
		: find_best_technology(AST_BRIDGE_CAPABILITY_1TO1MIX);

	/* If no bridge technology was found we can't possibly do bridging so fail creation of the bridge */
	if (!bridge_technology) {
		return NULL;
	}

	/* We have everything we need to create this bridge... so allocate the memory, link things together, and fire her up! */
	bridge = ao2_alloc(sizeof(*bridge), destroy_bridge);
	if (!bridge) {
		ast_module_unref(bridge_technology->mod);
		return NULL;
	}

	ast_cond_init(&bridge->cond, NULL);
	bridge->technology = bridge_technology;
	bridge->thread = AST_PTHREADT_NULL;

	/* Create an array of pointers for the channels that will be joining us */
	bridge->array = ast_malloc(BRIDGE_ARRAY_START * sizeof(*bridge->array));
	if (!bridge->array) {
		ao2_ref(bridge, -1);
		return NULL;
	}
	bridge->array_size = BRIDGE_ARRAY_START;

	ast_set_flag(&bridge->feature_flags, flags);

	/* Pass off the bridge to the technology to manipulate if needed */
	ast_debug(1, "Giving bridge technology %s the bridge structure %p to setup\n",
		bridge->technology->name, bridge);
	if (bridge->technology->create && bridge->technology->create(bridge)) {
		ast_debug(1, "Bridge technology %s failed to setup bridge structure %p\n",
			bridge->technology->name, bridge);
		ao2_ref(bridge, -1);
		return NULL;
	}

	return bridge;
}

int ast_bridge_check(uint32_t capabilities)
{
	struct ast_bridge_technology *bridge_technology;

	if (!(bridge_technology = find_best_technology(capabilities))) {
		return 0;
	}

	ast_module_unref(bridge_technology->mod);

	return 1;
}

int ast_bridge_destroy(struct ast_bridge *bridge)
{
	ast_debug(1, "Telling all channels in bridge %p to leave the party\n", bridge);
	ao2_lock(bridge);
	bridge_force_out_all(bridge);
	ao2_unlock(bridge);

	ao2_ref(bridge, -1);

	return 0;
}

static int bridge_make_compatible(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	struct ast_format formats[2];

	ast_format_copy(&formats[0], ast_channel_readformat(bridge_channel->chan));
	ast_format_copy(&formats[1], ast_channel_writeformat(bridge_channel->chan));

	/* Are the formats currently in use something this bridge can handle? */
	if (!ast_format_cap_iscompatible(bridge->technology->format_capabilities, ast_channel_readformat(bridge_channel->chan))) {
		struct ast_format best_format;

		ast_best_codec(bridge->technology->format_capabilities, &best_format);

		/* Read format is a no go... */
		if (option_debug) {
			char codec_buf[512];
			ast_debug(1, "Bridge technology %s wants to read any of formats %s but channel has %s\n",
				bridge->technology->name,
				ast_getformatname_multiple(codec_buf, sizeof(codec_buf), bridge->technology->format_capabilities),
				ast_getformatname(&formats[0]));
		}
		/* Switch read format to the best one chosen */
		if (ast_set_read_format(bridge_channel->chan, &best_format)) {
			ast_log(LOG_WARNING, "Failed to set channel %s to read format %s\n",
				ast_channel_name(bridge_channel->chan), ast_getformatname(&best_format));
			return -1;
		}
		ast_debug(1, "Bridge %p put channel %s into read format %s\n",
			bridge, ast_channel_name(bridge_channel->chan), ast_getformatname(&best_format));
	} else {
		ast_debug(1, "Bridge %p is happy that channel %s already has read format %s\n",
			bridge, ast_channel_name(bridge_channel->chan), ast_getformatname(&formats[0]));
	}

	if (!ast_format_cap_iscompatible(bridge->technology->format_capabilities, &formats[1])) {
		struct ast_format best_format;

		ast_best_codec(bridge->technology->format_capabilities, &best_format);

		/* Write format is a no go... */
		if (option_debug) {
			char codec_buf[512];
			ast_debug(1, "Bridge technology %s wants to write any of formats %s but channel has %s\n",
				bridge->technology->name,
				ast_getformatname_multiple(codec_buf, sizeof(codec_buf), bridge->technology->format_capabilities),
				ast_getformatname(&formats[1]));
		}
		/* Switch write format to the best one chosen */
		if (ast_set_write_format(bridge_channel->chan, &best_format)) {
			ast_log(LOG_WARNING, "Failed to set channel %s to write format %s\n",
				ast_channel_name(bridge_channel->chan), ast_getformatname(&best_format));
			return -1;
		}
		ast_debug(1, "Bridge %p put channel %s into write format %s\n",
			bridge, ast_channel_name(bridge_channel->chan), ast_getformatname(&best_format));
	} else {
		ast_debug(1, "Bridge %p is happy that channel %s already has write format %s\n",
			bridge, ast_channel_name(bridge_channel->chan), ast_getformatname(&formats[1]));
	}

	return 0;
}

/*!
 * \internal
 * \brief Perform the smart bridge operation.
 * \since 12.0.0
 *
 * \param bridge Work on this bridge.
 *
 * \details
 * Basically see if a new bridge technology should be used instead
 * of the current one.
 *
 * \note On entry, bridge is already locked.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int smart_bridge_operation(struct ast_bridge *bridge)
{
	uint32_t new_capabilities = 0;
	struct ast_bridge_technology *new_technology;
	struct ast_bridge_technology *old_technology = bridge->technology;
	struct ast_bridge temp_bridge = {
		.technology = bridge->technology,
		.bridge_pvt = bridge->bridge_pvt,
	};
	struct ast_bridge_channel *bridge_channel;

	if (bridge->dissolved) {
		ast_debug(1, "Bridge %p is dissolved, not performing smart bridge operation.\n",
			bridge);
		return 0;
	}

/* BUGBUG the bridge tech compatible callback should be asking if the specified bridge is compatible with the tech. */
	/*
	 * Based on current capabilities determine whether we want to
	 * change bridge technologies.
	 */
	if (bridge->technology->capabilities & AST_BRIDGE_CAPABILITY_1TO1MIX) {
		if (bridge->num_channels <= 2) {
			ast_debug(1, "Bridge %p channel count (%d) is within limits for bridge technology %s, not performing smart bridge operation.\n",
				bridge, bridge->num_channels, bridge->technology->name);
			return 0;
		}
		new_capabilities = AST_BRIDGE_CAPABILITY_MULTIMIX;
	} else if (bridge->technology->capabilities & AST_BRIDGE_CAPABILITY_MULTIMIX) {
		if (2 < bridge->num_channels) {
			ast_debug(1, "Bridge %p channel count (%d) is within limits for bridge technology %s, not performing smart bridge operation.\n",
				bridge, bridge->num_channels, bridge->technology->name);
			return 0;
		}
		new_capabilities = AST_BRIDGE_CAPABILITY_1TO1MIX;
	}

	if (!new_capabilities) {
		ast_debug(1, "Bridge %p has no new capabilities, not performing smart bridge operation.\n",
			bridge);
		return 0;
	}

	/* Attempt to find a new bridge technology to satisfy the capabilities */
	new_technology = find_best_technology(new_capabilities);
	if (!new_technology) {
/* BUGBUG need to output the bridge id for tracking why. */
		ast_log(LOG_WARNING, "No bridge technology available to support bridge %p\n",
			bridge);
		return -1;
	}

	/*
	 * We are now committed to changing the bridge technology.  We
	 * must not release the bridge lock until we have installed the
	 * new bridge technology.
	 */
	ast_debug(1, "Performing smart bridge operation on bridge %p, moving from bridge technology %s to %s\n",
		bridge, old_technology->name, new_technology->name);

	/*
	 * Since we are soon going to pass this bridge to a new
	 * technology we need to NULL out the bridge_pvt pointer but
	 * don't worry as it still exists in temp_bridge, ditto for the
	 * old technology.
	 */
	bridge->bridge_pvt = NULL;
	bridge->technology = new_technology;

	/* Setup the new bridge technology. */
	ast_debug(1, "Giving bridge technology %s the bridge structure %p to setup\n",
		new_technology->name, bridge);
	if (new_technology->create && new_technology->create(bridge)) {
/* BUGBUG need to output the bridge id for tracking why. */
		ast_log(LOG_WARNING, "Bridge technology %s for bridge %p failed to get setup\n",
			new_technology->name, bridge);
		bridge->bridge_pvt = temp_bridge.bridge_pvt;
		bridge->technology = temp_bridge.technology;
		ast_module_unref(new_technology->mod);
		return -1;
	}

	/* Move existing channels over to the new technology. */
	AST_LIST_TRAVERSE(&bridge->channels, bridge_channel, entry) {
		if (bridge_channel->just_joined) {
			/*
			 * This channel has not completed joining the bridge so it is
			 * not in the old bridge technology.
			 */
			continue;
		}

		/* First we part them from the old technology */
		ast_debug(1, "Giving bridge technology %s notification that %p(%s) is leaving bridge %p (really %p)\n",
			old_technology->name, bridge_channel, ast_channel_name(bridge_channel->chan),
			&temp_bridge, bridge);
		if (old_technology->leave) {
			old_technology->leave(&temp_bridge, bridge_channel);
		}

		/* Second we make them compatible again with the bridge */
		bridge_make_compatible(bridge, bridge_channel);

		/* Third we join them to the new technology */
		ast_debug(1, "Giving bridge technology %s notification that %p(%s) is joining bridge %p\n",
			new_technology->name, bridge_channel, ast_channel_name(bridge_channel->chan),
			bridge);
		if (new_technology->join && new_technology->join(bridge, bridge_channel)) {
			ast_debug(1, "Bridge technology %s failed to join %p(%s) to bridge %p\n",
				new_technology->name, bridge_channel,
				ast_channel_name(bridge_channel->chan), bridge);
		}

		/* Fourth we tell them to wake up so they become aware that the above has happened */
		bridge_channel_poke_locked(bridge_channel);
	}

	/*
	 * Now that all the channels have been moved over we need to get
	 * rid of all the information the old technology may have left
	 * around.
	 */
	ast_debug(1, "Giving bridge technology %s the bridge structure %p (really %p) to destroy\n",
		old_technology->name, &temp_bridge, bridge);
	if (old_technology->destroy) {
		old_technology->destroy(&temp_bridge);
	}
	ast_module_unref(old_technology->mod);

	return 0;
}

/*!
 * \internal
 * \brief Notify the bridge that it has been reconfigured.
 * \since 12.0.0
 *
 * \param bridge Reconfigured bridge.
 *
 * \details
 * After a series of ast_bridge_channel_push and
 * ast_bridge_channel_pull calls, you need to call this function
 * to cause the bridge to complete restruturing for the change
 * in the channel makeup of the bridge.
 *
 * \note On entry, the bridge is already locked.
 *
 * \return Nothing
 */
static void ast_bridge_reconfigured(struct ast_bridge *bridge)
{
	if (!bridge->reconfigured) {
		return;
	}
	bridge->reconfigured = 0;
	if (ast_test_flag(&bridge->feature_flags, AST_BRIDGE_FLAG_SMART)
		&& smart_bridge_operation(bridge)) {
		/* Smart bridge failed.  Dissolve the bridge. */
		bridge_force_out_all(bridge);
		return;
	}
	bridge_complete_join(bridge);
}

/*! \brief Run in a multithreaded model. Each joined channel does writing/reading in their own thread. TODO: Improve */
static void bridge_channel_join_multithreaded(struct ast_bridge_channel *bridge_channel)
{
	int ms = -1;
	struct ast_channel *chan;

	ao2_unlock(bridge_channel->bridge);

	/* Wait for data to either come from the channel or us to be signaled */
	ao2_lock(bridge_channel);
	if (bridge_channel->poked
		|| bridge_channel->state != AST_BRIDGE_CHANNEL_STATE_WAIT) {
	} else if (bridge_channel->suspended) {
		ast_debug(1, "Going into a multithreaded signal wait for bridge channel %p(%s) of bridge %p\n",
			bridge_channel, ast_channel_name(bridge_channel->chan),
			bridge_channel->bridge);
		ast_cond_wait(&bridge_channel->cond, ao2_object_get_lockaddr(bridge_channel));
	} else {
		ast_debug(10, "Going into a multithreaded waitfor for bridge channel %p(%s) of bridge %p\n",
			bridge_channel, ast_channel_name(bridge_channel->chan),
			bridge_channel->bridge);
		ao2_unlock(bridge_channel);
		chan = ast_waitfor_n(&bridge_channel->chan, 1, &ms);
		ao2_lock(bridge_channel->bridge);
		if (!bridge_channel->suspended) {
			ast_bridge_handle_trip(bridge_channel->bridge, bridge_channel, chan);
		}
		ao2_lock(bridge_channel);
		bridge_channel->poked = 0;
		ao2_unlock(bridge_channel);
		return;
	}
	bridge_channel->poked = 0;
	ao2_unlock(bridge_channel);
	ao2_lock(bridge_channel->bridge);
}

/*! \brief Run in a singlethreaded model. Each joined channel yields itself to the main bridge thread. TODO: Improve */
static void bridge_channel_join_singlethreaded(struct ast_bridge_channel *bridge_channel)
{
	ao2_unlock(bridge_channel->bridge);
	ao2_lock(bridge_channel);
	if (!bridge_channel->poked
		&& bridge_channel->state == AST_BRIDGE_CHANNEL_STATE_WAIT) {
		ast_debug(1, "Going into a single threaded signal wait for bridge channel %p(%s) of bridge %p\n",
			bridge_channel, ast_channel_name(bridge_channel->chan),
			bridge_channel->bridge);
		ast_cond_wait(&bridge_channel->cond, ao2_object_get_lockaddr(bridge_channel));
	}
	bridge_channel->poked = 0;
	ao2_unlock(bridge_channel);
	ao2_lock(bridge_channel->bridge);
}

/*!
 * \internal
 * \brief Suspend a channel from a bridge.
 *
 * \param bridge Bridge channel in.
 * \param bridge_channel Channel to suspend.
 *
 * \note This function assumes the bridge is locked.
 *
 * \return Nothing
 */
static void bridge_channel_suspend(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	ao2_lock(bridge_channel);
	bridge_channel->suspended = 1;
	bridge_array_remove(bridge, bridge_channel->chan);
	ao2_unlock(bridge_channel);

	/* Get technology bridge threads off of the channel. */
	if (bridge->technology->suspend) {
		bridge->technology->suspend(bridge, bridge_channel);
	}
}

/*!
 * \internal
 * \brief Unsuspend a channel from a bridge.
 *
 * \param bridge Bridge channel in.
 * \param bridge_channel Channel to unsuspend.
 *
 * \note This function assumes the bridge is locked.
 *
 * \return Nothing
 */
static void bridge_channel_unsuspend(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	ao2_lock(bridge_channel);
	bridge_channel->suspended = 0;
	bridge_array_add(bridge, bridge_channel->chan);

	/* Wake suspended channel on multithreaded type bridges. */
	ast_cond_signal(&bridge_channel->cond);
	ao2_unlock(bridge_channel);

	/* Wake technology bridge threads to take care of channel again. */
	if (bridge->technology->unsuspend) {
		bridge->technology->unsuspend(bridge, bridge_channel);
	}
	ast_bridge_poke(bridge);
}

/*! \brief Internal function that activates interval hooks on a bridge channel */
static void bridge_channel_interval(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	struct ast_bridge_hook *hook;

	while ((hook = ast_heap_peek(bridge_channel->features->interval_hooks, 1))) {
		int res;
		struct timeval start = ast_tvnow();
		int execution_time = 0;

		if (ast_tvdiff_ms(hook->parms.timer.trip_time, start) > 0) {
			ast_debug(1, "Hook %p on bridge channel %p(%s) wants to happen in the future, stopping our traversal\n",
				hook, bridge_channel, ast_channel_name(bridge_channel->chan));
			break;
		}

		ast_debug(1, "Executing hook %p on bridge channel %p(%s)\n",
			hook, bridge_channel, ast_channel_name(bridge_channel->chan));
		res = hook->callback(bridge, bridge_channel, hook->hook_pvt);

		/*
		 * Must be popped after the callback.  The callback could call
		 * ast_bridge_interval_hook_update().
		 */
		ast_heap_pop(bridge_channel->features->interval_hooks);

		if (res || !hook->parms.timer.interval) {
			ast_debug(1, "Interval hook %p is being removed from bridge channel %p(%s)\n",
				hook, bridge_channel, ast_channel_name(bridge_channel->chan));
			if (hook->destructor) {
				hook->destructor(hook->hook_pvt);
			}
			ast_free(hook);
			continue;
		}

		ast_debug(1, "Updating interval hook %p with interval %u on bridge channel %p(%s)\n",
			hook, hook->parms.timer.interval, bridge_channel,
			ast_channel_name(bridge_channel->chan));

		execution_time = ast_tvdiff_ms(ast_tvnow(), start);

		/* resetting start */
		start = ast_tvnow();

		hook->parms.timer.trip_time = ast_tvadd(start, ast_samp2tv(hook->parms.timer.interval - execution_time, 1000));

		hook->parms.timer.seqno = ast_atomic_fetchadd_int((int *) &bridge_channel->features->interval_sequence, +1);
		ast_heap_push(bridge_channel->features->interval_hooks, hook);
	}
}

/*!
 * \brief Internal function that executes a feature on a bridge channel
 * \note Neither the bridge nor the bridge_channel locks should be held when entering
 * this function.
 */
static void bridge_channel_feature(struct ast_bridge *bridge, struct ast_bridge_channel *bridge_channel)
{
	struct ast_bridge_features *features = (bridge_channel->features ? bridge_channel->features : &bridge->features);
	struct ast_bridge_hook *hook = NULL;
	char dtmf[MAXIMUM_DTMF_FEATURE_STRING] = "";
	int look_for_dtmf = 1, dtmf_len = 0;

	/* The channel is now under our control and we don't really want any begin frames to do our DTMF matching so disable 'em at the core level */
	ast_set_flag(ast_channel_flags(bridge_channel->chan), AST_FLAG_END_DTMF_ONLY);

	/* Wait for DTMF on the channel and put it into a buffer. If the buffer matches any feature hook execute the hook. */
	while (look_for_dtmf) {
		int res = ast_waitfordigit(bridge_channel->chan, 3000);

		/* If the above timed out simply exit */
		if (!res) {
			ast_debug(1, "DTMF feature string collection on bridge channel %p(%s) timed out\n",
				bridge_channel, ast_channel_name(bridge_channel->chan));
			break;
		} else if (res < 0) {
			ast_debug(1, "DTMF feature string collection failed on bridge channel %p(%s) for some reason\n",
				bridge_channel, ast_channel_name(bridge_channel->chan));
			break;
		}

/* BUGBUG need to record the duration of DTMF digits so when the string is played back, they are reproduced. */
		/* Add the above DTMF into the DTMF string so we can do our matching */
		dtmf[dtmf_len++] = res;

		ast_debug(1, "DTMF feature string on bridge channel %p(%s) is now '%s'\n",
			bridge_channel, ast_channel_name(bridge_channel->chan), dtmf);

		/* Assume that we do not want to look for DTMF any longer */
		look_for_dtmf = 0;

		/* See if a DTMF feature hook matches or can match */
		AST_LIST_TRAVERSE(&features->dtmf_hooks, hook, entry) {
			/* If this hook matches just break out now */
			if (!strcmp(hook->parms.dtmf.code, dtmf)) {
				ast_debug(1, "DTMF feature hook %p matched DTMF string '%s' on bridge channel %p(%s)\n",
					hook, dtmf, bridge_channel, ast_channel_name(bridge_channel->chan));
				look_for_dtmf = 0;
				break;
			} else if (!strncmp(hook->parms.dtmf.code, dtmf, dtmf_len)) {
				ast_debug(1, "DTMF feature hook %p can match DTMF string '%s', it wants '%s', on bridge channel %p(%s)\n",
					hook, dtmf, hook->parms.dtmf.code, bridge_channel,
					ast_channel_name(bridge_channel->chan));
				look_for_dtmf = 1;
			} else {
				ast_debug(1, "DTMF feature hook %p does not match DTMF string '%s', it wants '%s', on bridge channel %p(%s)\n",
					hook, dtmf, hook->parms.dtmf.code, bridge_channel,
					ast_channel_name(bridge_channel->chan));
			}
		}

		/* If we have reached the maximum length of a DTMF feature string bail out */
		if (dtmf_len == MAXIMUM_DTMF_FEATURE_STRING) {
			break;
		}
	}

	/* Since we are done bringing DTMF in return to using both begin and end frames */
	ast_clear_flag(ast_channel_flags(bridge_channel->chan), AST_FLAG_END_DTMF_ONLY);

	/* If a hook was actually matched execute it on this channel, otherwise stream up the DTMF to the other channels */
	if (hook) {
		int failed;

		failed = hook->callback(bridge, bridge_channel, hook->hook_pvt);
		if (failed) {
			struct ast_bridge_hook *cur;

			AST_LIST_TRAVERSE_SAFE_BEGIN(&features->dtmf_hooks, cur, entry) {
				if (cur == hook) {
					ast_debug(1, "DTMF hook %p is being removed from bridge channel %p(%s)\n",
						hook, bridge_channel, ast_channel_name(bridge_channel->chan));
					AST_LIST_REMOVE_CURRENT(entry);
					if (hook->destructor) {
						hook->destructor(hook->hook_pvt);
					}
					ast_free(hook);
					break;
				}
			}
			AST_LIST_TRAVERSE_SAFE_END;
		}

		/*
		 * If we are handing the channel off to an external hook for
		 * ownership, we are not guaranteed what kind of state it will
		 * come back in.  If the channel hungup, we need to detect that
		 * here if the hook did not already change the state.
		 */
		if (bridge_channel->chan && ast_check_hangup_locked(bridge_channel->chan)) {
			bridge_handle_hangup(bridge, bridge_channel);
		}
	} else {
/* BUGBUG Check the features.dtmf_passthrough flag just like ast_bridge_handle_trip() before passing on the collected digits. */
		ast_bridge_dtmf_stream(bridge, dtmf, bridge_channel->chan);
	}
}

static void bridge_channel_talking(struct ast_bridge_channel *bridge_channel, int talking)
{
	struct ast_bridge_features *features;

	features = bridge_channel->features;
	if (!features) {
		features = &bridge_channel->bridge->features;
	}
	if (features->talker_cb) {
		features->talker_cb(bridge_channel, features->talker_pvt_data, talking);
	}
}

/*! \brief Internal function that plays back DTMF on a bridge channel */
static void bridge_channel_dtmf_stream(struct ast_bridge_channel *bridge_channel, const char *dtmf)
{
	ast_debug(1, "Playing DTMF stream '%s' out to bridge channel %p(%s)\n",
		dtmf, bridge_channel, ast_channel_name(bridge_channel->chan));
	ast_dtmf_stream(bridge_channel->chan, NULL, dtmf, 0, 0);
}

/*!
 * \internal
 * \brief Handle bridge channel bridge action frame.
 * \since 12.0.0
 *
 * \param bridge_channel Channel to execute the action on.
 * \param action What to do.
 *
 * \return Nothing
 *
 * \note This function assumes the bridge is locked.
 */
static void bridge_channel_action_bridge(struct ast_bridge_channel *bridge_channel, struct ast_frame *action)
{
	switch (action->subclass.integer) {
	case AST_BRIDGE_ACTION_INTERVAL:
		bridge_channel_suspend(bridge_channel->bridge, bridge_channel);
		ao2_unlock(bridge_channel->bridge);
		bridge_channel_interval(bridge_channel->bridge, bridge_channel);
		ao2_lock(bridge_channel->bridge);
		bridge_channel_unsuspend(bridge_channel->bridge, bridge_channel);
		break;
	case AST_BRIDGE_ACTION_FEATURE:
		bridge_channel_suspend(bridge_channel->bridge, bridge_channel);
		ao2_unlock(bridge_channel->bridge);
		bridge_channel_feature(bridge_channel->bridge, bridge_channel);
		ao2_lock(bridge_channel->bridge);
		bridge_channel_unsuspend(bridge_channel->bridge, bridge_channel);
		break;
	case AST_BRIDGE_ACTION_DTMF_STREAM:
		bridge_channel_suspend(bridge_channel->bridge, bridge_channel);
		ao2_unlock(bridge_channel->bridge);
		bridge_channel_dtmf_stream(bridge_channel, action->data.ptr);
		ao2_lock(bridge_channel->bridge);
		bridge_channel_unsuspend(bridge_channel->bridge, bridge_channel);
		break;
	case AST_BRIDGE_ACTION_TALKING_START:
	case AST_BRIDGE_ACTION_TALKING_STOP:
		ao2_unlock(bridge_channel->bridge);
		bridge_channel_talking(bridge_channel,
			action->subclass.integer == AST_BRIDGE_ACTION_TALKING_START);
		ao2_lock(bridge_channel->bridge);
		break;
	default:
		break;
	}
}

/*!
 * \internal
 * \brief Handle bridge channel control frame action.
 * \since 12.0.0
 *
 * \param bridge_channel Channel to execute the control frame action on.
 * \param action What to do.
 *
 * \return Nothing
 *
 * \note This function assumes the bridge is locked.
 */
static void bridge_channel_action_control(struct ast_bridge_channel *bridge_channel, struct ast_frame *action)
{
	switch (action->subclass.integer) {
	case AST_CONTROL_CONNECTED_LINE:
		break;
	default:
		break;
	}
	/*! \todo BUGBUG bridge_channel_action_control() not written */
}

/*! \brief Join a channel to a bridge and handle anything the bridge may want us to do */
static void bridge_channel_join(struct ast_bridge_channel *bridge_channel)
{
	struct ast_frame *action;

	ast_format_copy(&bridge_channel->read_format, ast_channel_readformat(bridge_channel->chan));
	ast_format_copy(&bridge_channel->write_format, ast_channel_writeformat(bridge_channel->chan));

	ast_debug(1, "Joining bridge channel %p(%s) to bridge %p\n",
		bridge_channel, ast_channel_name(bridge_channel->chan), bridge_channel->bridge);

	ao2_lock(bridge_channel->bridge);

	if (!bridge_channel->bridge->callid) {
		bridge_channel->bridge->callid = ast_read_threadstorage_callid();
	}

	ast_bridge_channel_push(bridge_channel);
	ast_bridge_reconfigured(bridge_channel->bridge);

	/* Actually execute the respective threading model, and keep our bridge thread alive */
	while (bridge_channel->state == AST_BRIDGE_CHANNEL_STATE_WAIT) {
		/* Update bridge pointer on channel */
		ast_channel_internal_bridge_set(bridge_channel->chan, bridge_channel->bridge);

		/* Execute the threading model */
		if (bridge_channel->bridge->technology->capabilities & AST_BRIDGE_CAPABILITY_MULTITHREADED) {
			bridge_channel_join_multithreaded(bridge_channel);
		} else {
			bridge_channel_join_singlethreaded(bridge_channel);
		}

/* BUGBUG the code is assuming that bridge_channel->bridge does not change which is just wrong.  The bridge pointer can change with merges and moves.  The locking protocol must be implemented. */
		/* Run any queued actions on the channel. */
		ao2_lock(bridge_channel);
		while (bridge_channel->state == AST_BRIDGE_CHANNEL_STATE_WAIT
			&& !bridge_channel->suspended) {
			action = AST_LIST_REMOVE_HEAD(&bridge_channel->action_queue, frame_list);
			if (!action) {
				break;
			}
			ao2_unlock(bridge_channel);
			switch (action->frametype) {
			case AST_FRAME_BRIDGE_ACTION:
				bridge_channel_action_bridge(bridge_channel, action);
				break;
			case AST_FRAME_CONTROL:
				bridge_channel_action_control(bridge_channel, action);
				break;
			case AST_FRAME_TEXT:
			case AST_FRAME_IMAGE:
			case AST_FRAME_HTML:
				/* Write the deferred frame to the channel. */
				ao2_unlock(bridge_channel->bridge);
				ast_write(bridge_channel->chan, action);
				ao2_lock(bridge_channel->bridge);
				break;
			default:
				/* Unexpected deferred frame type.  Should never happen. */
				ast_assert(0);
				break;
			}
			ast_frfree(action);
			ao2_lock(bridge_channel);
		}
		ao2_unlock(bridge_channel);
	}

	ast_bridge_channel_pull(bridge_channel);
	ast_bridge_reconfigured(bridge_channel->bridge);

	/* See if we need to dissolve the bridge itself if they hung up */
	switch (bridge_channel->state) {
	case AST_BRIDGE_CHANNEL_STATE_END:
		bridge_check_dissolve(bridge_channel->bridge, bridge_channel);
		break;
	default:
		break;
	}

	ao2_unlock(bridge_channel->bridge);

	/* Flush any unhandled actions. */
	ao2_lock(bridge_channel);
	while ((action = AST_LIST_REMOVE_HEAD(&bridge_channel->action_queue, frame_list))) {
		ast_frfree(action);
	}
	ao2_unlock(bridge_channel);

/* BUGBUG Revisit in regards to moving channels between bridges and local channel optimization. */
	/* Complete any partial DTMF digit before exiting the bridge. */
	if (ast_channel_sending_dtmf_digit(bridge_channel->chan)) {
		ast_bridge_end_dtmf(bridge_channel->chan,
			ast_channel_sending_dtmf_digit(bridge_channel->chan),
			ast_channel_sending_dtmf_tv(bridge_channel->chan), "bridge end");
	}

	/*
	 * Wait for any dual redirect to complete.
	 *
	 * Must be done while "still in the bridge" for ast_async_goto()
	 * to work right.
	 */
	while (ast_test_flag(ast_channel_flags(bridge_channel->chan), AST_FLAG_BRIDGE_DUAL_REDIRECT_WAIT)) {
		sched_yield();
	}
	ast_channel_internal_bridge_set(bridge_channel->chan, NULL);

	ast_bridge_channel_restore_formats(bridge_channel);
}

static void bridge_channel_destroy(void *obj)
{
	struct ast_bridge_channel *bridge_channel = obj;

	ast_bridge_channel_clear_roles(bridge_channel);

	if (bridge_channel->callid) {
		bridge_channel->callid = ast_callid_unref(bridge_channel->callid);
	}

	if (bridge_channel->bridge) {
		ao2_ref(bridge_channel->bridge, -1);
		bridge_channel->bridge = NULL;
	}

	/* Destroy elements of the bridge channel structure and the bridge channel structure itself */
	ast_cond_destroy(&bridge_channel->cond);
}

static struct ast_bridge_channel *bridge_channel_alloc(struct ast_bridge *bridge)
{
	struct ast_bridge_channel *bridge_channel;

	bridge_channel = ao2_alloc(sizeof(struct ast_bridge_channel), bridge_channel_destroy);
	if (!bridge_channel) {
		return NULL;
	}
	ast_cond_init(&bridge_channel->cond, NULL);
	if (bridge) {
		bridge_channel->bridge = bridge;
		ao2_ref(bridge_channel->bridge, +1);
	}
	return bridge_channel;
}

struct after_bridge_goto_ds {
	/*! Goto string that can be parsed by ast_parseable_goto(). */
	const char *parseable_goto;
	/*! Specific goto context or default context for parseable_goto. */
	const char *context;
	/*! Specific goto exten or default exten for parseable_goto. */
	const char *exten;
	/*! Specific goto priority or default priority for parseable_goto. */
	int priority;
	/*! TRUE if the peer should run the h exten. */
	unsigned int run_h_exten:1;
	/*! Specific goto location */
	unsigned int specific:1;
};

/*!
 * \internal
 * \brief Destroy the after bridge goto datastore.
 * \since 12.0.0
 *
 * \param data After bridge goto data to destroy.
 *
 * \return Nothing
 */
static void after_bridge_goto_destroy(void *data)
{
	struct after_bridge_goto_ds *after_bridge = data;

	ast_free((char *) after_bridge->parseable_goto);
	ast_free((char *) after_bridge->context);
	ast_free((char *) after_bridge->exten);
}

/*!
 * \internal
 * \brief Fixup the after bridge goto datastore.
 * \since 12.0.0
 *
 * \param data After bridge goto data to fixup.
 * \param old_chan The datastore is moving from this channel.
 * \param new_chan The datastore is moving to this channel.
 *
 * \return Nothing
 */
static void after_bridge_goto_fixup(void *data, struct ast_channel *old_chan, struct ast_channel *new_chan)
{
	/* There can be only one.  Discard any already on the new channel. */
	ast_after_bridge_goto_discard(new_chan);
}

static const struct ast_datastore_info after_bridge_goto_info = {
	.type = "after-bridge-goto",
	.destroy = after_bridge_goto_destroy,
	.chan_fixup = after_bridge_goto_fixup,
};

/*!
 * \internal
 * \brief Remove channel goto location after the bridge and return it.
 * \since 12.0.0
 *
 * \param chan Channel to remove after bridge goto location.
 *
 * \retval datastore on success.
 * \retval NULL on error or not found.
 */
static struct ast_datastore *after_bridge_goto_remove(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	ast_channel_lock(chan);
	datastore = ast_channel_datastore_find(chan, &after_bridge_goto_info, NULL);
	if (datastore && ast_channel_datastore_remove(chan, datastore)) {
		datastore = NULL;
	}
	ast_channel_unlock(chan);

	return datastore;
}

void ast_after_bridge_goto_discard(struct ast_channel *chan)
{
	struct ast_datastore *datastore;

	datastore = after_bridge_goto_remove(chan);
	if (datastore) {
		ast_datastore_free(datastore);
	}
}

int ast_after_bridge_goto_setup(struct ast_channel *chan)
{
	struct ast_datastore *datastore;
	struct after_bridge_goto_ds *after_bridge;
	int goto_failed = -1;

	/* Determine if we are going to setup a dialplan location and where. */
	if (ast_channel_softhangup_internal_flag(chan) & AST_SOFTHANGUP_ASYNCGOTO) {
		/* An async goto has already setup a location. */
		ast_channel_clear_softhangup(chan, AST_SOFTHANGUP_ASYNCGOTO);
		if (!ast_check_hangup(chan)) {
			goto_failed = 0;
		}
		return goto_failed;
	}

	/* Get after bridge goto datastore. */
	datastore = after_bridge_goto_remove(chan);
	if (!datastore) {
		return goto_failed;
	}

	after_bridge = datastore->data;
	if (after_bridge->run_h_exten) {
		if (ast_exists_extension(chan, after_bridge->context, "h", 1,
			S_COR(ast_channel_caller(chan)->id.number.valid,
				ast_channel_caller(chan)->id.number.str, NULL))) {
			ast_debug(1, "Running after bridge goto h exten %s,h,1\n",
				ast_channel_context(chan));
			ast_pbx_h_exten_run(chan, after_bridge->context);
		}
	} else if (!ast_check_hangup(chan)) {
		if (after_bridge->specific) {
			goto_failed = ast_explicit_goto(chan, after_bridge->context,
				after_bridge->exten, after_bridge->priority);
		} else if (!ast_strlen_zero(after_bridge->parseable_goto)) {
			char *context;
			char *exten;
			int priority;

			/* Option F(x) for Bridge(), Dial(), and Queue() */

			/* Save current dialplan location in case of failure. */
			context = ast_strdupa(ast_channel_context(chan));
			exten = ast_strdupa(ast_channel_exten(chan));
			priority = ast_channel_priority(chan);

			/* Set current dialplan position to default dialplan position */
			ast_explicit_goto(chan, after_bridge->context, after_bridge->exten,
				after_bridge->priority);

			/* Then perform the goto */
			goto_failed = ast_parseable_goto(chan, after_bridge->parseable_goto);
			if (goto_failed) {
				/* Restore original dialplan location. */
				ast_channel_context_set(chan, context);
				ast_channel_exten_set(chan, exten);
				ast_channel_priority_set(chan, priority);
			}
		} else {
			/* Option F() for Bridge(), Dial(), and Queue() */
			goto_failed = ast_goto_if_exists(chan, after_bridge->context,
				after_bridge->exten, after_bridge->priority + 1);
		}
		if (!goto_failed) {
			ast_debug(1, "Setup after bridge goto location to %s,%s,%d.\n",
				ast_channel_context(chan),
				ast_channel_exten(chan),
				ast_channel_priority(chan));
		}
	}

	/* Discard after bridge goto datastore. */
	ast_datastore_free(datastore);

	return goto_failed;
}

void ast_after_bridge_goto_run(struct ast_channel *chan)
{
	int goto_failed;

	goto_failed = ast_after_bridge_goto_setup(chan);
	if (goto_failed || ast_pbx_run(chan)) {
		ast_hangup(chan);
	}
}

/*!
 * \internal
 * \brief Set after bridge goto location of channel.
 * \since 12.0.0
 *
 * \param chan Channel to setup after bridge goto location.
 * \param run_h_exten TRUE if the h exten should be run.
 * \param specific TRUE if the context/exten/priority is exactly specified.
 * \param context Context to goto after bridge.
 * \param exten Exten to goto after bridge. (Could be NULL if run_h_exten)
 * \param priority Priority to goto after bridge.
 * \param parseable_goto User specified goto string. (Could be NULL)
 *
 * \details Add a channel datastore to setup the goto location
 * when the channel leaves the bridge and run a PBX from there.
 *
 * If run_h_exten then execute the h exten found in the given context.
 * Else if specific then goto the given context/exten/priority.
 * Else if parseable_goto then use the given context/exten/priority
 *   as the relative position for the parseable_goto.
 * Else goto the given context/exten/priority+1.
 *
 * \return Nothing
 */
static void __after_bridge_set_goto(struct ast_channel *chan, int run_h_exten, int specific, const char *context, const char *exten, int priority, const char *parseable_goto)
{
	struct ast_datastore *datastore;
	struct after_bridge_goto_ds *after_bridge;

	/* Sanity checks. */
	ast_assert(chan != NULL);
	if (!chan) {
		return;
	}
	if (run_h_exten) {
		ast_assert(run_h_exten && context);
		if (!context) {
			return;
		}
	} else {
		ast_assert(context && exten && 0 < priority);
		if (!context || !exten || priority < 1) {
			return;
		}
	}

	/* Create a new datastore. */
	datastore = ast_datastore_alloc(&after_bridge_goto_info, NULL);
	if (!datastore) {
		return;
	}
	after_bridge = ast_calloc(1, sizeof(*after_bridge));
	if (!after_bridge) {
		ast_datastore_free(datastore);
		return;
	}

	/* Initialize it. */
	after_bridge->parseable_goto = ast_strdup(parseable_goto);
	after_bridge->context = ast_strdup(context);
	after_bridge->exten = ast_strdup(exten);
	after_bridge->priority = priority;
	after_bridge->run_h_exten = run_h_exten ? 1 : 0;
	after_bridge->specific = specific ? 1 : 0;
	datastore->data = after_bridge;
	if ((parseable_goto && !after_bridge->parseable_goto)
		|| (context && !after_bridge->context)
		|| (exten && !after_bridge->exten)) {
		ast_datastore_free(datastore);
		return;
	}

	/* Put it on the channel replacing any existing one. */
	ast_channel_lock(chan);
	ast_after_bridge_goto_discard(chan);
	ast_channel_datastore_add(chan, datastore);
	ast_channel_unlock(chan);
}

void ast_after_bridge_set_goto(struct ast_channel *chan, const char *context, const char *exten, int priority)
{
	__after_bridge_set_goto(chan, 0, 1, context, exten, priority, NULL);
}

void ast_after_bridge_set_h(struct ast_channel *chan, const char *context)
{
	__after_bridge_set_goto(chan, 1, 0, context, NULL, 1, NULL);
}

void ast_after_bridge_set_go_on(struct ast_channel *chan, const char *context, const char *exten, int priority, const char *parseable_goto)
{
	char *p_goto;

	if (!ast_strlen_zero(parseable_goto)) {
		p_goto = ast_strdupa(parseable_goto);
		ast_replace_subargument_delimiter(p_goto);
	} else {
		p_goto = NULL;
	}
	__after_bridge_set_goto(chan, 0, 0, context, exten, priority, p_goto);
}

/*
 * BUGBUG make ast_bridge_join() require features to be allocated just like ast_bridge_impart() and not expect the struct back.
 *
 * This change is really going to break ConfBridge.  All other
 * users are easily changed.  However, it is needed so the
 * bridging code can manipulate features on all channels
 * consistently no matter how they joined.
 *
 * Need to update the features parameter doxygen when this
 * change is made to be like ast_bridge_impart().
 */
enum ast_bridge_channel_state ast_bridge_join(struct ast_bridge *bridge,
	struct ast_channel *chan,
	struct ast_channel *swap,
	struct ast_bridge_features *features,
	struct ast_bridge_tech_optimizations *tech_args,
	int pass_reference)
{
	struct ast_bridge_channel *bridge_channel;
	enum ast_bridge_channel_state state;

	bridge_channel = bridge_channel_alloc(bridge);
	if (pass_reference) {
		ao2_ref(bridge, -1);
	}
	if (!bridge_channel) {
		state = AST_BRIDGE_CHANNEL_STATE_HANGUP;
		goto join_exit;
	}
	if (tech_args) {
		bridge_channel->tech_args = *tech_args;
	}

	/* Initialize various other elements of the bridge channel structure that we can't do above */
	ast_channel_internal_bridge_channel_set(chan, bridge_channel);
	bridge_channel->thread = pthread_self();
	bridge_channel->chan = chan;
	bridge_channel->swap = swap;
	bridge_channel->features = features;

	if (ast_bridge_channel_establish_roles(bridge_channel)) {
		/* A bridge channel should not be allowed to join if its roles couldn't be copied properly. */
		state = AST_BRIDGE_CHANNEL_STATE_HANGUP;
		ast_channel_internal_bridge_channel_set(chan, NULL);
		ao2_ref(bridge_channel, -1);
		goto join_exit;
	}

	bridge_channel_join(bridge_channel);
	state = bridge_channel->state;

	/* Cleanup all the data in the bridge channel after it leaves the bridge. */
	ast_channel_internal_bridge_channel_set(chan, NULL);
	bridge_channel->chan = NULL;
	bridge_channel->swap = NULL;
	bridge_channel->features = NULL;

	ao2_ref(bridge_channel, -1);

join_exit:;
/* BUGBUG this is going to cause problems for DTMF atxfer attended bridge between B & C.  Maybe an ast_bridge_join_internal() that does not do the after bridge goto for this case. */
	if (!(ast_channel_softhangup_internal_flag(chan) & AST_SOFTHANGUP_ASYNCGOTO)
		&& !ast_after_bridge_goto_setup(chan)) {
		/* Claim the after bridge goto is an async goto destination. */
		ast_channel_lock(chan);
		ast_softhangup_nolock(chan, AST_SOFTHANGUP_ASYNCGOTO);
		ast_channel_unlock(chan);
	}
	return state;
}

/*! \brief Thread responsible for imparted bridged channels to be departed */
static void *bridge_channel_depart_thread(void *data)
{
	struct ast_bridge_channel *bridge_channel = data;

	if (bridge_channel->callid) {
		ast_callid_threadassoc_add(bridge_channel->callid);
	}

	bridge_channel_join(bridge_channel);

	/* cleanup */
	bridge_channel->swap = NULL;
	ast_bridge_features_destroy(bridge_channel->features);
	bridge_channel->features = NULL;

	ast_after_bridge_goto_discard(bridge_channel->chan);

	return NULL;
}

/*! \brief Thread responsible for independent imparted bridged channels */
static void *bridge_channel_ind_thread(void *data)
{
	struct ast_bridge_channel *bridge_channel = data;
	struct ast_channel *chan;

	if (bridge_channel->callid) {
		ast_callid_threadassoc_add(bridge_channel->callid);
	}

	bridge_channel_join(bridge_channel);
	chan = bridge_channel->chan;

	/* cleanup */
	ast_channel_internal_bridge_channel_set(chan, NULL);
	bridge_channel->chan = NULL;
	bridge_channel->swap = NULL;
	ast_bridge_features_destroy(bridge_channel->features);
	bridge_channel->features = NULL;

	ao2_ref(bridge_channel, -1);

	ast_after_bridge_goto_run(chan);
	return NULL;
}

int ast_bridge_impart(struct ast_bridge *bridge, struct ast_channel *chan, struct ast_channel *swap, struct ast_bridge_features *features, int independent)
{
	int res;
	struct ast_bridge_channel *bridge_channel;

	/* Try to allocate a structure for the bridge channel */
	bridge_channel = bridge_channel_alloc(bridge);
	if (!bridge_channel) {
		return -1;
	}

	/* Setup various parameters */
	ast_channel_internal_bridge_channel_set(chan, bridge_channel);
	bridge_channel->chan = chan;
	bridge_channel->swap = swap;
	bridge_channel->features = features;
	bridge_channel->depart_wait = independent ? 0 : 1;
	bridge_channel->callid = ast_read_threadstorage_callid();

	if (ast_bridge_channel_establish_roles(bridge_channel)) {
		res = -1;
		goto bridge_impart_cleanup;
	}

	/* Actually create the thread that will handle the channel */
	if (independent) {
		/* Independently imparted channels cannot have a PBX. */
		ast_assert(!ast_channel_pbx(chan));

		res = ast_pthread_create_detached(&bridge_channel->thread, NULL,
			bridge_channel_ind_thread, bridge_channel);
	} else {
		/* Imparted channels to be departed should not have a PBX either. */
		ast_assert(!ast_channel_pbx(chan));

		res = ast_pthread_create(&bridge_channel->thread, NULL,
			bridge_channel_depart_thread, bridge_channel);
	}

bridge_impart_cleanup:
	if (res) {
		/* cleanup */
		ast_channel_internal_bridge_channel_set(chan, NULL);
		bridge_channel->chan = NULL;
		bridge_channel->swap = NULL;
		ast_bridge_features_destroy(bridge_channel->features);
		bridge_channel->features = NULL;

		ao2_ref(bridge_channel, -1);
		return -1;
	}

	return 0;
}

int ast_bridge_depart(struct ast_channel *chan)
{
	struct ast_bridge_channel *bridge_channel;

	bridge_channel = ast_channel_internal_bridge_channel(chan);
	if (!bridge_channel || !bridge_channel->depart_wait) {
		ast_log(LOG_ERROR, "Channel %s cannot be departed.\n",
			ast_channel_name(chan));
		/*
		 * Should never happen.  It likely means that
		 * ast_bridge_depart() is called by two threads for the same
		 * channel, the channel was never imparted to be departed, or it
		 * has already been departed.
		 */
		ast_assert(0);
		return -1;
	}

	/* We are claiming the reference held by the depart thread. */

	ast_bridge_change_state(bridge_channel, AST_BRIDGE_CHANNEL_STATE_HANGUP);

	/* Wait for the depart thread to die */
	pthread_join(bridge_channel->thread, NULL);

	ast_channel_internal_bridge_channel_set(chan, NULL);

	/* We can get rid of the bridge_channel after the depart thread has died. */
	ao2_ref(bridge_channel, -1);
	return 0;
}

int ast_bridge_remove(struct ast_bridge *bridge, struct ast_channel *chan)
{
	struct ast_bridge_channel *bridge_channel;

	ao2_lock(bridge);

	/* Try to find the channel that we want to remove */
	if (!(bridge_channel = find_bridge_channel(bridge, chan))) {
		ao2_unlock(bridge);
		return -1;
	}

	ast_bridge_change_state(bridge_channel, AST_BRIDGE_CHANNEL_STATE_HANGUP);

	ao2_unlock(bridge);

	return 0;
}

/*!
 * \internal
 * \brief Do the merge of two bridges.
 * \since 12.0.0
 *
 * \param bridge1 First bridge
 * \param bridge2 Second bridge
 *
 * \return Nothing
 *
 * \note The two bridges are assumed already locked.
 *
 * This merges the bridge pointed to by bridge2 into the bridge
 * pointed to by bridge1.  In reality all of the channels in
 * bridge2 are moved to bridge1.
 *
 * \note The second bridge has no active channels in it when
 * this operation is completed.  The caller must explicitly call
 * ast_bridge_destroy().
 */
static void ast_bridge_merge_do(struct ast_bridge *bridge1, struct ast_bridge *bridge2)
{
	struct ast_bridge_channel *bridge_channel;

	ast_debug(1, "Merging channels from bridge %p into bridge %p\n", bridge2, bridge1);

	/* Move channels from bridge2 over to bridge1 */
	while ((bridge_channel = AST_LIST_FIRST(&bridge2->channels))) {
		ast_bridge_channel_pull(bridge_channel);

		/* Point to new bridge.*/
		ao2_ref(bridge2, -1);
		bridge_channel->bridge = bridge1;
		ao2_ref(bridge1, +1);

		ast_bridge_channel_push(bridge_channel);
	}
	ast_bridge_reconfigured(bridge1);
	ast_bridge_reconfigured(bridge2);

	ast_debug(1, "Merged channels from bridge %p into bridge %p\n", bridge2, bridge1);
}

int ast_bridge_merge(struct ast_bridge *bridge1, struct ast_bridge *bridge2)
{
	int res = -1;

	/* Deadlock avoidance. */
	for (;;) {
		ao2_lock(bridge1);
		if (!ao2_trylock(bridge2)) {
			break;
		}
		ao2_unlock(bridge1);
		sched_yield();
	}

	if (bridge1->dissolved) {
		ast_debug(1, "Can't merge bridge %p into bridge %p, destination bridge is dissolved.\n",
			bridge2, bridge1);
	} else if (bridge1->inhibit_merge || bridge2->inhibit_merge
		|| ast_test_flag(&bridge1->feature_flags, AST_BRIDGE_FLAG_MASQUERADE_ONLY | AST_BRIDGE_FLAG_MERGE_INHIBIT_TO)
		|| ast_test_flag(&bridge2->feature_flags, AST_BRIDGE_FLAG_MASQUERADE_ONLY | AST_BRIDGE_FLAG_MERGE_INHIBIT_FROM)) {
		/* Merging is inhibited by either bridge. */
		ast_debug(1, "Can't merge bridge %p into bridge %p, merging inhibited.\n",
			bridge2, bridge1);
	} else if (2 < bridge1->num_channels + bridge2->num_channels
		&& !(bridge1->technology->capabilities & AST_BRIDGE_CAPABILITY_MULTIMIX)
		&& !ast_test_flag(&bridge1->feature_flags, AST_BRIDGE_FLAG_SMART)) {
		ast_debug(1, "Can't merge bridge %p into bridge %p, multimix is needed and it cannot be acquired.\n",
			bridge2, bridge1);
	} else {
		++bridge1->inhibit_merge;
		++bridge2->inhibit_merge;
		ast_bridge_merge_do(bridge1, bridge2);
		--bridge2->inhibit_merge;
		--bridge1->inhibit_merge;
		res = 0;
	}

	ao2_unlock(bridge2);
	ao2_unlock(bridge1);
	return res;
}

void ast_bridge_merge_inhibit(struct ast_bridge *bridge, int request)
{
	int new_request;

	ao2_lock(bridge);
	new_request = bridge->inhibit_merge + request;
	if (new_request < 0) {
		new_request = 0;
	}
	bridge->inhibit_merge = new_request;
	ao2_unlock(bridge);
}

int ast_bridge_suspend(struct ast_bridge *bridge, struct ast_channel *chan)
{
	struct ast_bridge_channel *bridge_channel;
/* BUGBUG the case of a disolved bridge while channel is suspended is not handled. */
/* BUGBUG suspend/unsuspend needs to be rethought. The caller must block until it has successfully suspended the channel for temporary control. */

	ao2_lock(bridge);

	if (!(bridge_channel = find_bridge_channel(bridge, chan))) {
		ao2_unlock(bridge);
		return -1;
	}

	bridge_channel_suspend(bridge, bridge_channel);

	ao2_unlock(bridge);

	return 0;
}

int ast_bridge_unsuspend(struct ast_bridge *bridge, struct ast_channel *chan)
{
	struct ast_bridge_channel *bridge_channel;
/* BUGBUG the case of a disolved bridge while channel is suspended is not handled. */

	ao2_lock(bridge);

	if (!(bridge_channel = find_bridge_channel(bridge, chan))) {
		ao2_unlock(bridge);
		return -1;
	}

	bridge_channel_unsuspend(bridge, bridge_channel);

	ao2_unlock(bridge);

	return 0;
}

void ast_bridge_technology_suspend(struct ast_bridge_technology *technology)
{
	technology->suspended = 1;
}

void ast_bridge_technology_unsuspend(struct ast_bridge_technology *technology)
{
/* BUGBUG unsuspending a bridge technology probably needs to prod all existing bridges to see if they should start using it. */
	technology->suspended = 0;
}

int ast_bridge_features_register(enum ast_bridge_builtin_feature feature, ast_bridge_hook_callback callback, const char *dtmf)
{
	if (ARRAY_LEN(builtin_features_handlers) <= feature
		|| builtin_features_handlers[feature]) {
		return -1;
	}

	if (!ast_strlen_zero(dtmf)) {
		ast_copy_string(builtin_features_dtmf[feature], dtmf, sizeof(builtin_features_dtmf[feature]));
	}

	builtin_features_handlers[feature] = callback;

	return 0;
}

int ast_bridge_features_unregister(enum ast_bridge_builtin_feature feature)
{
	if (ARRAY_LEN(builtin_features_handlers) <= feature
		|| !builtin_features_handlers[feature]) {
		return -1;
	}

	builtin_features_handlers[feature] = NULL;

	return 0;
}

int ast_bridge_interval_register(enum ast_bridge_builtin_interval interval, void *callback)
{
	if (ARRAY_LEN(builtin_interval_handlers) <= interval
		|| builtin_interval_handlers[interval]) {
		return -1;
	}

	builtin_interval_handlers[interval] = callback;

	return 0;
}

int ast_bridge_interval_unregister(enum ast_bridge_builtin_interval interval)
{
	if (ARRAY_LEN(builtin_interval_handlers) <= interval
		|| !builtin_interval_handlers[interval]) {
		return -1;
	}

	builtin_interval_handlers[interval] = NULL;

	return 0;

}

int ast_bridge_dtmf_hook(struct ast_bridge_features *features,
	const char *dtmf,
	ast_bridge_hook_callback callback,
	void *hook_pvt,
	ast_bridge_hook_pvt_destructor destructor)
{
	struct ast_bridge_hook *hook;

	/* Allocate new memory and setup it's various variables */
	hook = ast_calloc(1, sizeof(*hook));
	if (!hook) {
		return -1;
	}
	ast_copy_string(hook->parms.dtmf.code, dtmf, sizeof(hook->parms.dtmf.code));
	hook->callback = callback;
	hook->destructor = destructor;
	hook->hook_pvt = hook_pvt;

	/* Once done we add it onto the list. */
	AST_LIST_INSERT_TAIL(&features->dtmf_hooks, hook, entry);

	features->usable = 1;

	return 0;
}

int ast_bridge_hangup_hook(struct ast_bridge_features *features,
	ast_bridge_hook_callback callback,
	void *hook_pvt,
	ast_bridge_hook_pvt_destructor destructor)
{
	struct ast_bridge_hook *hook;

	/* Allocate new memory and setup it's various variables */
	hook = ast_calloc(1, sizeof(*hook));
	if (!hook) {
		return -1;
	}
	hook->callback = callback;
	hook->destructor = destructor;
	hook->hook_pvt = hook_pvt;

	/* Once done we add it onto the list. */
	AST_LIST_INSERT_TAIL(&features->hangup_hooks, hook, entry);

	features->usable = 1;

	return 0;
}

void ast_bridge_features_set_talk_detector(struct ast_bridge_features *features,
	ast_bridge_talking_indicate_callback talker_cb,
	ast_bridge_talking_indicate_destructor talker_destructor,
	void *pvt_data)
{
	features->talker_cb = talker_cb;
	features->talker_destructor_cb = talker_destructor;
	features->talker_pvt_data = pvt_data;
}

int ast_bridge_interval_hook(struct ast_bridge_features *features,
	unsigned int interval,
	ast_bridge_hook_callback callback,
	void *hook_pvt,
	ast_bridge_hook_pvt_destructor destructor)
{
	struct ast_bridge_hook *hook = NULL;

	if (!interval || !callback || !features || !features->interval_hooks
		|| !(hook = ast_calloc(1, sizeof(*hook)))) {
		return -1;
	}

	if (!features->interval_timer) {
		if (!(features->interval_timer = ast_timer_open())) {
			ast_log(LOG_ERROR, "Failed to open a timer when adding a timed bridging feature.\n");
			ast_free(hook);
			return -1;
		}
		ast_timer_set_rate(features->interval_timer, BRIDGE_FEATURES_INTERVAL_RATE);
	}

	hook->parms.timer.interval = interval;
	hook->callback = callback;
	hook->destructor = destructor;
	hook->hook_pvt = hook_pvt;

	ast_debug(1, "Putting interval hook %p with interval %u in the heap on features %p\n",
		hook, hook->parms.timer.interval, features);
	hook->parms.timer.trip_time = ast_tvadd(ast_tvnow(), ast_samp2tv(hook->parms.timer.interval, 1000));
	hook->parms.timer.seqno = ast_atomic_fetchadd_int((int *) &features->interval_sequence, +1);
	ast_heap_push(features->interval_hooks, hook);
	features->usable = 1;

	return 0;
}

int ast_bridge_interval_hook_update(struct ast_bridge_channel *bridge_channel, unsigned int interval)
{
	struct ast_bridge_hook *hook;

	if (!bridge_channel->features || !bridge_channel->features->usable
		|| !bridge_channel->features->interval_hooks) {
		return -1;
	}

	hook = ast_heap_peek(bridge_channel->features->interval_hooks, 1);
	if (!hook) {
		return -1;
	}
	hook->parms.timer.interval = interval;

	return 0;
}

int ast_bridge_features_enable(struct ast_bridge_features *features, enum ast_bridge_builtin_feature feature, const char *dtmf, void *config, ast_bridge_hook_pvt_destructor destructor)
{
	if (ARRAY_LEN(builtin_features_handlers) <= feature
		|| !builtin_features_handlers[feature]) {
		return -1;
	}

	/* If no alternate DTMF stream was provided use the default one */
	if (ast_strlen_zero(dtmf)) {
		dtmf = builtin_features_dtmf[feature];
		/* If no DTMF is still available (ie: it has been disabled) then error out now */
		if (ast_strlen_zero(dtmf)) {
			ast_debug(1, "Failed to enable built in feature %d on %p, no DTMF string is available for it.\n",
				feature, features);
			return -1;
		}
	}

	/*
	 * The rest is basically pretty easy.  We create another hook
	 * using the built in feature's DTMF callback.  Easy as pie.
	 */
	return ast_bridge_dtmf_hook(features, dtmf, builtin_features_handlers[feature], config, destructor);
}

int ast_bridge_features_limits_construct(struct ast_bridge_features_limits *limits)
{
	memset(limits, 0, sizeof(*limits));

	if (ast_string_field_init(limits, 256)) {
		ast_free(limits);
		return -1;
	}

	return 0;
}

void ast_bridge_features_limits_destroy(struct ast_bridge_features_limits *limits)
{
	ast_string_field_free_memory(limits);
}

int ast_bridge_features_set_limits(struct ast_bridge_features *features, struct ast_bridge_features_limits *limits)
{
	if (builtin_interval_handlers[AST_BRIDGE_BUILTIN_INTERVAL_LIMITS]) {
		int (*bridge_features_set_limits_callback)(struct ast_bridge_features *features, struct ast_bridge_features_limits *limits);

		bridge_features_set_limits_callback = builtin_interval_handlers[AST_BRIDGE_BUILTIN_INTERVAL_LIMITS];
		return bridge_features_set_limits_callback(features, limits);
	}

	ast_log(LOG_ERROR, "Attempted to set limits without an AST_BRIDGE_BUILTIN_INTERVAL_LIMITS callback registered.\n");
	return -1;
}

void ast_bridge_features_set_flag(struct ast_bridge_features *features, enum ast_bridge_feature_flags flag)
{
	ast_set_flag(&features->feature_flags, flag);
	features->usable = 1;
}

static int interval_hook_time_cmp(void *a, void *b)
{
	struct ast_bridge_hook *hook_a = a;
	struct ast_bridge_hook *hook_b = b;
	int cmp;

	cmp = ast_tvcmp(hook_b->parms.timer.trip_time, hook_a->parms.timer.trip_time);
	if (cmp) {
		return cmp;
	}

	cmp = hook_b->parms.timer.seqno - hook_a->parms.timer.seqno;
	return cmp;
}

/* BUGBUG make ast_bridge_features_init() static when make ast_bridge_join() requires features to be allocated. */
int ast_bridge_features_init(struct ast_bridge_features *features)
{
	/* Zero out the structure */
	memset(features, 0, sizeof(*features));

	/* Initialize the DTMF hooks list, just in case */
	AST_LIST_HEAD_INIT_NOLOCK(&features->dtmf_hooks);

	/* Initialize the hangup hooks list, just in case */
	AST_LIST_HEAD_INIT_NOLOCK(&features->hangup_hooks);

	/* Initialize the interval hook heap */
	features->interval_hooks = ast_heap_create(8, interval_hook_time_cmp,
		offsetof(struct ast_bridge_hook, parms.timer.__heap_index));

	return 0;
}

/* BUGBUG make ast_bridge_features_cleanup() static when make ast_bridge_join() requires features to be allocated. */
void ast_bridge_features_cleanup(struct ast_bridge_features *features)
{
	struct ast_bridge_hook *hook;

	/* Destroy each interval hook. */
	if (features->interval_hooks) {
		while ((hook = ast_heap_pop(features->interval_hooks))) {
			if (hook->destructor) {
				hook->destructor(hook->hook_pvt);
			}
			ast_free(hook);
		}

		features->interval_hooks = ast_heap_destroy(features->interval_hooks);
	}
	if (features->interval_timer) {
		ast_timer_close(features->interval_timer);
		features->interval_timer = NULL;
	}

	/* If the features contains a limits pvt, destroy that as well. */
	if (features->limits) {
		ast_bridge_features_limits_destroy(features->limits);
		ast_free(features->limits);
		features->limits = NULL;
	}

	if (features->talker_destructor_cb && features->talker_pvt_data) {
		features->talker_destructor_cb(features->talker_pvt_data);
		features->talker_pvt_data = NULL;
	}

	/* Destroy each hangup hook. */
	while ((hook = AST_LIST_REMOVE_HEAD(&features->hangup_hooks, entry))) {
		if (hook->destructor) {
			hook->destructor(hook->hook_pvt);
		}
		ast_free(hook);
	}

	/* Destroy each DTMF feature hook. */
	while ((hook = AST_LIST_REMOVE_HEAD(&features->dtmf_hooks, entry))) {
		if (hook->destructor) {
			hook->destructor(hook->hook_pvt);
		}
		ast_free(hook);
	}
}

struct ast_bridge_features *ast_bridge_features_new(void)
{
	struct ast_bridge_features *features;

	features = ast_malloc(sizeof(*features));
	if (features) {
		ast_bridge_features_init(features);
	}

	return features;
}

void ast_bridge_features_destroy(struct ast_bridge_features *features)
{
	if (!features) {
		return;
	}
	ast_bridge_features_cleanup(features);
	ast_free(features);
}

int ast_bridge_dtmf_stream(struct ast_bridge *bridge, const char *dtmf, struct ast_channel *chan)
{
	struct ast_bridge_channel *bridge_channel;
	struct ast_frame action = {
		.frametype = AST_FRAME_BRIDGE_ACTION,
		.subclass.integer = AST_BRIDGE_ACTION_DTMF_STREAM,
		.datalen = strlen(dtmf) + 1,
		.data.ptr = (char *) dtmf,
	};

	ao2_lock(bridge);

	AST_LIST_TRAVERSE(&bridge->channels, bridge_channel, entry) {
		if (bridge_channel->chan == chan) {
			continue;
		}
		ast_bridge_channel_queue_action(bridge_channel, &action);
	}

	ao2_unlock(bridge);

	return 0;
}

void ast_bridge_set_mixing_interval(struct ast_bridge *bridge, unsigned int mixing_interval)
{
	ao2_lock(bridge);
	bridge->internal_mixing_interval = mixing_interval;
	ao2_unlock(bridge);
}

void ast_bridge_set_internal_sample_rate(struct ast_bridge *bridge, unsigned int sample_rate)
{

	ao2_lock(bridge);
	bridge->internal_sample_rate = sample_rate;
	ao2_unlock(bridge);
}

static void cleanup_video_mode(struct ast_bridge *bridge)
{
	switch (bridge->video_mode.mode) {
	case AST_BRIDGE_VIDEO_MODE_NONE:
		break;
	case AST_BRIDGE_VIDEO_MODE_SINGLE_SRC:
		if (bridge->video_mode.mode_data.single_src_data.chan_vsrc) {
			ast_channel_unref(bridge->video_mode.mode_data.single_src_data.chan_vsrc);
		}
		break;
	case AST_BRIDGE_VIDEO_MODE_TALKER_SRC:
		if (bridge->video_mode.mode_data.talker_src_data.chan_vsrc) {
			ast_channel_unref(bridge->video_mode.mode_data.talker_src_data.chan_vsrc);
		}
		if (bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc) {
			ast_channel_unref(bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc);
		}
	}
	memset(&bridge->video_mode, 0, sizeof(bridge->video_mode));
}

void ast_bridge_set_single_src_video_mode(struct ast_bridge *bridge, struct ast_channel *video_src_chan)
{
	ao2_lock(bridge);
	cleanup_video_mode(bridge);
	bridge->video_mode.mode = AST_BRIDGE_VIDEO_MODE_SINGLE_SRC;
	bridge->video_mode.mode_data.single_src_data.chan_vsrc = ast_channel_ref(video_src_chan);
	ast_test_suite_event_notify("BRIDGE_VIDEO_MODE", "Message: video mode set to single source\r\nVideo Mode: %d\r\nVideo Channel: %s", bridge->video_mode.mode, ast_channel_name(video_src_chan));
	ast_indicate(video_src_chan, AST_CONTROL_VIDUPDATE);
	ao2_unlock(bridge);
}

void ast_bridge_set_talker_src_video_mode(struct ast_bridge *bridge)
{
	ao2_lock(bridge);
	cleanup_video_mode(bridge);
	bridge->video_mode.mode = AST_BRIDGE_VIDEO_MODE_TALKER_SRC;
	ast_test_suite_event_notify("BRIDGE_VIDEO_MODE", "Message: video mode set to talker source\r\nVideo Mode: %d", bridge->video_mode.mode);
	ao2_unlock(bridge);
}

void ast_bridge_update_talker_src_video_mode(struct ast_bridge *bridge, struct ast_channel *chan, int talker_energy, int is_keyframe)
{
	struct ast_bridge_video_talker_src_data *data;
	/* If the channel doesn't support video, we don't care about it */
	if (!ast_format_cap_has_type(ast_channel_nativeformats(chan), AST_FORMAT_TYPE_VIDEO)) {
		return;
	}

	ao2_lock(bridge);
	data = &bridge->video_mode.mode_data.talker_src_data;

	if (data->chan_vsrc == chan) {
		data->average_talking_energy = talker_energy;
	} else if ((data->average_talking_energy < talker_energy) && is_keyframe) {
		if (data->chan_old_vsrc) {
			ast_channel_unref(data->chan_old_vsrc);
		}
		if (data->chan_vsrc) {
			data->chan_old_vsrc = data->chan_vsrc;
			ast_indicate(data->chan_old_vsrc, AST_CONTROL_VIDUPDATE);
		}
		data->chan_vsrc = ast_channel_ref(chan);
		data->average_talking_energy = talker_energy;
		ast_test_suite_event_notify("BRIDGE_VIDEO_SRC", "Message: video source updated\r\nVideo Channel: %s", ast_channel_name(data->chan_vsrc));
		ast_indicate(data->chan_vsrc, AST_CONTROL_VIDUPDATE);
	} else if ((data->average_talking_energy < talker_energy) && !is_keyframe) {
		ast_indicate(chan, AST_CONTROL_VIDUPDATE);
	} else if (!data->chan_vsrc && is_keyframe) {
		data->chan_vsrc = ast_channel_ref(chan);
		data->average_talking_energy = talker_energy;
		ast_test_suite_event_notify("BRIDGE_VIDEO_SRC", "Message: video source updated\r\nVideo Channel: %s", ast_channel_name(data->chan_vsrc));
		ast_indicate(chan, AST_CONTROL_VIDUPDATE);
	} else if (!data->chan_old_vsrc && is_keyframe) {
		data->chan_old_vsrc = ast_channel_ref(chan);
		ast_indicate(chan, AST_CONTROL_VIDUPDATE);
	}
	ao2_unlock(bridge);
}

int ast_bridge_number_video_src(struct ast_bridge *bridge)
{
	int res = 0;

	ao2_lock(bridge);
	switch (bridge->video_mode.mode) {
	case AST_BRIDGE_VIDEO_MODE_NONE:
		break;
	case AST_BRIDGE_VIDEO_MODE_SINGLE_SRC:
		if (bridge->video_mode.mode_data.single_src_data.chan_vsrc) {
			res = 1;
		}
		break;
	case AST_BRIDGE_VIDEO_MODE_TALKER_SRC:
		if (bridge->video_mode.mode_data.talker_src_data.chan_vsrc) {
			res++;
		}
		if (bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc) {
			res++;
		}
	}
	ao2_unlock(bridge);
	return res;
}

int ast_bridge_is_video_src(struct ast_bridge *bridge, struct ast_channel *chan)
{
	int res = 0;

	ao2_lock(bridge);
	switch (bridge->video_mode.mode) {
	case AST_BRIDGE_VIDEO_MODE_NONE:
		break;
	case AST_BRIDGE_VIDEO_MODE_SINGLE_SRC:
		if (bridge->video_mode.mode_data.single_src_data.chan_vsrc == chan) {
			res = 1;
		}
		break;
	case AST_BRIDGE_VIDEO_MODE_TALKER_SRC:
		if (bridge->video_mode.mode_data.talker_src_data.chan_vsrc == chan) {
			res = 1;
		} else if (bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc == chan) {
			res = 2;
		}

	}
	ao2_unlock(bridge);
	return res;
}

void ast_bridge_remove_video_src(struct ast_bridge *bridge, struct ast_channel *chan)
{
	ao2_lock(bridge);
	switch (bridge->video_mode.mode) {
	case AST_BRIDGE_VIDEO_MODE_NONE:
		break;
	case AST_BRIDGE_VIDEO_MODE_SINGLE_SRC:
		if (bridge->video_mode.mode_data.single_src_data.chan_vsrc == chan) {
			if (bridge->video_mode.mode_data.single_src_data.chan_vsrc) {
				ast_channel_unref(bridge->video_mode.mode_data.single_src_data.chan_vsrc);
			}
			bridge->video_mode.mode_data.single_src_data.chan_vsrc = NULL;
		}
		break;
	case AST_BRIDGE_VIDEO_MODE_TALKER_SRC:
		if (bridge->video_mode.mode_data.talker_src_data.chan_vsrc == chan) {
			if (bridge->video_mode.mode_data.talker_src_data.chan_vsrc) {
				ast_channel_unref(bridge->video_mode.mode_data.talker_src_data.chan_vsrc);
			}
			bridge->video_mode.mode_data.talker_src_data.chan_vsrc = NULL;
			bridge->video_mode.mode_data.talker_src_data.average_talking_energy = 0;
		}
		if (bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc == chan) {
			if (bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc) {
				ast_channel_unref(bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc);
			}
			bridge->video_mode.mode_data.talker_src_data.chan_old_vsrc = NULL;
		}
	}
	ao2_unlock(bridge);
}

/*!
 * \internal
 * \brief Service the bridge manager request.
 * \since 12.0.0
 *
 * \param bridge requesting service.
 *
 * \return Nothing
 */
static void bridge_manager_service(struct ast_bridge *bridge)
{
	struct ast_frame *action;

	ao2_lock(bridge);
	if (bridge->callid) {
		ast_callid_threadassoc_change(bridge->callid);
	}

	/* Run a pending bridge action. */
	action = AST_LIST_REMOVE_HEAD(&bridge->action_queue, frame_list);
	if (action) {
		switch (action->frametype) {
		case AST_FRAME_BRIDGE_ACTION:
			bridge_action_bridge(bridge, action);
			break;
		default:
			/* Unexpected deferred frame type.  Should never happen. */
			ast_assert(0);
			break;
		}
		ast_frfree(action);
	}
	ao2_unlock(bridge);
}

/*!
 * \internal
 * \brief Bridge manager service thread.
 * \since 12.0.0
 *
 * \return Nothing
 */
static void *bridge_manager_thread(void *data)
{
	struct bridge_manager_controller *manager = data;
	struct bridge_manager_request *request;

	ao2_lock(manager);
	while (!manager->stop) {
		request = AST_LIST_REMOVE_HEAD(&manager->service_requests, node);
		if (!request) {
			ast_cond_wait(&manager->cond, ao2_object_get_lockaddr(manager));
			continue;
		}
		ao2_unlock(manager);

		/* Service the bridge. */
		bridge_manager_service(request->bridge);
		ao2_ref(request->bridge, -1);
		ast_free(request);

		ao2_lock(manager);
	}
	ao2_unlock(manager);

	return NULL;
}

/*!
 * \internal
 * \brief Destroy the bridge manager controller.
 * \since 12.0.0
 *
 * \param obj Bridge manager to destroy.
 *
 * \return Nothing
 */
static void bridge_manager_destroy(void *obj)
{
	struct bridge_manager_controller *manager = obj;
	struct bridge_manager_request *request;

	if (manager->thread != AST_PTHREADT_NULL) {
		/* Stop the manager thread. */
		ao2_lock(manager);
		manager->stop = 1;
		ast_cond_signal(&manager->cond);
		ao2_unlock(manager);
		pthread_join(manager->thread, NULL);
	}

	/* Destroy the service request queue. */
	while ((request = AST_LIST_REMOVE_HEAD(&manager->service_requests, node))) {
		ao2_ref(request->bridge, -1);
		ast_free(request);
	}

	ast_cond_destroy(&manager->cond);
}

/*!
 * \internal
 * \brief Create the bridge manager controller.
 * \since 12.0.0
 *
 * \retval manager on success.
 * \retval NULL on error.
 */
static struct bridge_manager_controller *bridge_manager_create(void)
{
	struct bridge_manager_controller *manager;

	manager = ao2_alloc(sizeof(*manager), bridge_manager_destroy);
	if (!manager) {
		/* Well. This isn't good. */
		return NULL;
	}
	ast_cond_init(&manager->cond, NULL);
	AST_LIST_HEAD_INIT_NOLOCK(&manager->service_requests);

	/* Create the bridge manager thread. */
	if (ast_pthread_create(&manager->thread, NULL, bridge_manager_thread, manager)) {
		/* Well. This isn't good either. */
		manager->thread = AST_PTHREADT_NULL;
		ao2_ref(manager, -1);
		manager = NULL;
	}

	return manager;
}

/*!
 * \internal
 * \brief Shutdown the bridging system.
 * \since 12.0.0
 *
 * \return Nothing
 */
static void bridge_shutdown(void)
{
	ao2_cleanup(bridge_manager);
	bridge_manager = NULL;
}

int ast_bridge_init(void)
{
	bridge_manager = bridge_manager_create();
	if (!bridge_manager) {
		return -1;
	}

	ast_register_atexit(bridge_shutdown);
	return 0;
}
