/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, 2013, Digium, Inc.
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

/*! \file
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Richard Mudgett <rmudgett@digium.com>
 *
 * \brief Local proxy channel and other unreal channel derivatives framework.
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <fcntl.h>
#include <sys/signal.h>

#include "asterisk/lock.h"
#include "asterisk/causes.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/sched.h"
#include "asterisk/io.h"
#include "asterisk/acl.h"
#include "asterisk/callerid.h"
#include "asterisk/file.h"
#include "asterisk/cli.h"
#include "asterisk/app.h"
#include "asterisk/musiconhold.h"
#include "asterisk/manager.h"
#include "asterisk/stringfields.h"
#include "asterisk/devicestate.h"
#include "asterisk/astobj2.h"
#include "asterisk/bridging.h"
#include "asterisk/core_local.h"
#include "asterisk/_private.h"

/*** DOCUMENTATION
	<manager name="LocalOptimizeAway" language="en_US">
		<synopsis>
			Optimize away a local channel when possible.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Channel" required="true">
				<para>The channel name to optimize away.</para>
			</parameter>
		</syntax>
		<description>
			<para>A local channel created with "/n" will not automatically optimize away.
			Calling this command on the local channel will clear that flag and allow
			it to optimize away if it's bridged or when it becomes bridged.</para>
		</description>
	</manager>
 ***/

static const char tdesc[] = "Local Proxy Channel Driver";

static struct ao2_container *locals;

static unsigned int name_sequence = 0;

static struct ast_channel *local_request(const char *type, struct ast_format_cap *cap, const struct ast_channel *requestor, const char *data, int *cause);
static int local_call(struct ast_channel *ast, const char *dest, int timeout);
static int local_hangup(struct ast_channel *ast);
static int local_devicestate(const char *data);

/* PBX interface structure for channel registration */
static struct ast_channel_tech local_tech = {
	.type = "Local",
	.description = tdesc,
	.requester = local_request,
	.send_digit_begin = ast_unreal_digit_begin,
	.send_digit_end = ast_unreal_digit_end,
	.call = local_call,
	.hangup = local_hangup,
	.answer = ast_unreal_answer,
	.read = ast_unreal_read,
	.write = ast_unreal_write,
	.write_video = ast_unreal_write,
	.exception = ast_unreal_read,
	.indicate = ast_unreal_indicate,
	.fixup = ast_unreal_fixup,
	.send_html = ast_unreal_sendhtml,
	.send_text = ast_unreal_sendtext,
	.devicestate = local_devicestate,
	.queryoption = ast_unreal_queryoption,
	.setoption = ast_unreal_setoption,
};

/*! What to do with the ;2 channel when ast_call() happens. */
enum local_call_action {
	/* The ast_call() will run dialplan on the ;2 channel. */
	LOCAL_CALL_ACTION_DIALPLAN,
	/* The ast_call() will impart the ;2 channel into a bridge. */
	LOCAL_CALL_ACTION_BRIDGE,
	/* The ast_call() will masquerade the ;2 channel into a channel. */
	LOCAL_CALL_ACTION_MASQUERADE,
};

/*! Join a bridge on ast_call() parameters. */
struct local_bridge {
	/*! Bridge to join. */
	struct ast_bridge *join;
	/*! Channel to swap with when joining bridge. */
	struct ast_channel *swap;
	/*! Features that are specific to this channel when pushed into the bridge. */
	struct ast_bridge_features *features;
};

/*!
 * \brief the local pvt structure for all channels
 *
 * The local channel pvt has two ast_chan objects - the "owner" and the "next channel", the outbound channel
 *
 * ast_chan owner -> local_pvt -> ast_chan chan
 */
struct local_pvt {
	/*! Unreal channel driver base class values. */
	struct ast_unreal_pvt base;
	/*! Additional action arguments */
	union {
		/*! Make ;2 join a bridge on ast_call(). */
		struct local_bridge bridge;
		/*! Make ;2 masquerade into this channel on ast_call(). */
		struct ast_channel *masq;
	} action;
	/*! What to do with the ;2 channel on ast_call(). */
	enum local_call_action type;
	/*! Context to call */
	char context[AST_MAX_CONTEXT];
	/*! Extension to call */
	char exten[AST_MAX_EXTENSION];
};

void ast_unreal_lock_all(struct ast_unreal_pvt *p, struct ast_channel **outchan, struct ast_channel **outowner)
{
	struct ast_channel *chan = NULL;
	struct ast_channel *owner = NULL;

	ao2_lock(p);
	for (;;) {
		if (p->chan) {
			chan = p->chan;
			ast_channel_ref(chan);
		}
		if (p->owner) {
			owner = p->owner;
			ast_channel_ref(owner);
		}
		ao2_unlock(p);

		/* if we don't have both channels, then this is very easy */
		if (!owner || !chan) {
			if (owner) {
				ast_channel_lock(owner);
			} else if(chan) {
				ast_channel_lock(chan);
			}
		} else {
			/* lock both channels first, then get the pvt lock */
			ast_channel_lock_both(chan, owner);
		}
		ao2_lock(p);

		/* Now that we have all the locks, validate that nothing changed */
		if (p->owner != owner || p->chan != chan) {
			if (owner) {
				ast_channel_unlock(owner);
				owner = ast_channel_unref(owner);
			}
			if (chan) {
				ast_channel_unlock(chan);
				chan = ast_channel_unref(chan);
			}
			continue;
		}

		break;
	}
	*outowner = p->owner;
	*outchan = p->chan;
}

struct ast_channel *ast_local_get_peer(struct ast_channel *ast)
{
	struct local_pvt *p = ast_channel_tech_pvt(ast);
	struct local_pvt *found;
	struct ast_channel *peer;

	if (!p) {
		return NULL;
	}

	found = p ? ao2_find(locals, p, 0) : NULL;
	if (!found) {
		/* ast is either not a local channel or it has alredy been hungup */
		return NULL;
	}
	ao2_lock(found);
	if (ast == p->base.owner) {
		peer = p->base.chan;
	} else if (ast == p->base.chan) {
		peer = p->base.owner;
	} else {
		peer = NULL;
	}
	if (peer) {
		ast_channel_ref(peer);
	}
	ao2_unlock(found);
	ao2_ref(found, -1);
	return peer;
}

/* Called with ast locked */
int ast_unreal_setoption(struct ast_channel *ast, int option, void *data, int datalen)
{
	int res = 0;
	struct ast_unreal_pvt *p;
	struct ast_channel *otherchan = NULL;
	ast_chan_write_info_t *write_info;

	if (option != AST_OPTION_CHANNEL_WRITE) {
		return -1;
	}

	write_info = data;

	if (write_info->version != AST_CHAN_WRITE_INFO_T_VERSION) {
		ast_log(LOG_ERROR, "The chan_write_info_t type has changed, and this channel hasn't been updated!\n");
		return -1;
	}

	if (!strcmp(write_info->function, "CHANNEL")
		&& !strncasecmp(write_info->data, "hangup_handler_", 15)) {
		/* Block CHANNEL(hangup_handler_xxx) writes to the other unreal channel. */
		return 0;
	}

	/* get the tech pvt */
	if (!(p = ast_channel_tech_pvt(ast))) {
		return -1;
	}
	ao2_ref(p, 1);
	ast_channel_unlock(ast); /* Held when called, unlock before locking another channel */

	/* get the channel we are supposed to write to */
	ao2_lock(p);
	otherchan = (write_info->chan == p->owner) ? p->chan : p->owner;
	if (!otherchan || otherchan == write_info->chan) {
		res = -1;
		otherchan = NULL;
		ao2_unlock(p);
		goto setoption_cleanup;
	}
	ast_channel_ref(otherchan);

	/* clear the pvt lock before grabbing the channel */
	ao2_unlock(p);

	ast_channel_lock(otherchan);
	res = write_info->write_fn(otherchan, write_info->function, write_info->data, write_info->value);
	ast_channel_unlock(otherchan);

setoption_cleanup:
	ao2_ref(p, -1);
	if (otherchan) {
		ast_channel_unref(otherchan);
	}
	ast_channel_lock(ast); /* Lock back before we leave */
	return res;
}

/*! \brief Adds devicestate to local channels */
static int local_devicestate(const char *data)
{
	int is_inuse = 0;
	int res = AST_DEVICE_INVALID;
	char *exten = ast_strdupa(data);
	char *context;
	char *opts;
	struct local_pvt *lp;
	struct ao2_iterator it;

	/* Strip options if they exist */
	opts = strchr(exten, '/');
	if (opts) {
		*opts = '\0';
	}

	context = strchr(exten, '@');
	if (!context) {
		ast_log(LOG_WARNING,
			"Someone used Local/%s somewhere without a @context. This is bad.\n", data);
		return AST_DEVICE_INVALID;
	}
	*context++ = '\0';

	it = ao2_iterator_init(locals, 0);
	for (; (lp = ao2_iterator_next(&it)); ao2_ref(lp, -1)) {
		ao2_lock(lp);
		if (!strcmp(exten, lp->exten)
			&& !strcmp(context, lp->context)) {
			res = AST_DEVICE_NOT_INUSE;
			if (lp->base.owner
				&& ast_test_flag(&lp->base, AST_UNREAL_CARETAKER_THREAD)) {
				is_inuse = 1;
			}
		}
		ao2_unlock(lp);
		if (is_inuse) {
			res = AST_DEVICE_INUSE;
			ao2_ref(lp, -1);
			break;
		}
	}
	ao2_iterator_destroy(&it);

	if (res == AST_DEVICE_INVALID) {
		ast_debug(3, "Checking if extension %s@%s exists (devicestate)\n", exten, context);
		if (ast_exists_extension(NULL, context, exten, 1, NULL)) {
			res = AST_DEVICE_NOT_INUSE;
		}
	}

	return res;
}

/* Called with ast locked */
int ast_unreal_queryoption(struct ast_channel *ast, int option, void *data, int *datalen)
{
	struct ast_unreal_pvt *p;
	struct ast_channel *peer;
	struct ast_channel *other;
	int res = 0;

	if (option != AST_OPTION_T38_STATE) {
		/* AST_OPTION_T38_STATE is the only supported option at this time */
		return -1;
	}

	/* for some reason the channel is not locked in channel.c when this function is called */
	if (!(p = ast_channel_tech_pvt(ast))) {
		return -1;
	}

	ao2_lock(p);
	other = AST_UNREAL_IS_OUTBOUND(ast, p) ? p->owner : p->chan;
	if (!other) {
		ao2_unlock(p);
		return -1;
	}
	ast_channel_ref(other);
	ao2_unlock(p);
	ast_channel_unlock(ast); /* Held when called, unlock before locking another channel */

	peer = ast_channel_bridge_peer(other);
	if (peer) {
		res = ast_channel_queryoption(peer, option, data, datalen, 0);
		ast_channel_unref(peer);
	}
	ast_channel_unref(other);
	ast_channel_lock(ast); /* Lock back before we leave */

	return res;
}

/*!
 * \brief queue a frame onto either the p->owner or p->chan
 *
 * \note the ast_unreal_pvt MUST have it's ref count bumped before entering this function and
 * decremented after this function is called.  This is a side effect of the deadlock
 * avoidance that is necessary to lock 2 channels and a tech_pvt.  Without a ref counted
 * ast_unreal_pvt, it is impossible to guarantee it will not be destroyed by another thread
 * during deadlock avoidance.
 */
static int unreal_queue_frame(struct ast_unreal_pvt *p, int isoutbound, struct ast_frame *f,
	struct ast_channel *us, int us_locked)
{
	struct ast_channel *other;

	/* Recalculate outbound channel */
	other = isoutbound ? p->owner : p->chan;
	if (!other) {
		return 0;
	}

	/* do not queue frame if generator is on both unreal channels */
	if (us && ast_channel_generator(us) && ast_channel_generator(other)) {
		return 0;
	}

	/* grab a ref on the channel before unlocking the pvt,
	 * other can not go away from us now regardless of locking */
	ast_channel_ref(other);
	if (us && us_locked) {
		ast_channel_unlock(us);
	}
	ao2_unlock(p);

	if (f->frametype == AST_FRAME_CONTROL && f->subclass.integer == AST_CONTROL_RINGING) {
		ast_setstate(other, AST_STATE_RINGING);
	}
	ast_queue_frame(other, f);

	other = ast_channel_unref(other);
	if (us && us_locked) {
		ast_channel_lock(us);
	}
	ao2_lock(p);

	return 0;
}

int ast_unreal_answer(struct ast_channel *ast)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(ast);
	int isoutbound;
	int res = -1;

	if (!p) {
		return -1;
	}

	ao2_ref(p, 1);
	ao2_lock(p);
	isoutbound = AST_UNREAL_IS_OUTBOUND(ast, p);
	if (isoutbound) {
		/* Pass along answer since somebody answered us */
		struct ast_frame answer = { AST_FRAME_CONTROL, { AST_CONTROL_ANSWER } };

		res = unreal_queue_frame(p, isoutbound, &answer, ast, 1);
	} else {
		ast_log(LOG_WARNING, "Huh?  %s is being asked to answer?\n",
			ast_channel_name(ast));
	}
	ao2_unlock(p);
	ao2_ref(p, -1);
	return res;
}

/*!
 * \internal
 * \brief Check and optimize out the unreal channels between bridges.
 * \since 12.0.0
 *
 * \param ast Channel writing a frame into the unreal channels.
 * \param p Local channel private.
 *
 * \note It is assumed that ast is locked.
 * \note It is assumed that p is locked.
 *
 * \retval 0 if unreal channels were not optimized out.
 * \retval non-zero if unreal channels were optimized out.
 */
static int got_optimized_out(struct ast_channel *ast, struct ast_unreal_pvt *p)
{
	/* Do a few conditional checks early on just to see if this optimization is possible */
	if (ast_test_flag(p, AST_UNREAL_NO_OPTIMIZATION) || !p->chan || !p->owner) {
		return 0;
	}
	if (ast == p->owner) {
		return ast_bridge_unreal_optimized_out(p->owner, p->chan);
	}
	if (ast == p->chan) {
		return ast_bridge_unreal_optimized_out(p->chan, p->owner);
	}
	/* ast is not valid to optimize. */
	return 0;
}

struct ast_frame  *ast_unreal_read(struct ast_channel *ast)
{
	return &ast_null_frame;
}

int ast_unreal_write(struct ast_channel *ast, struct ast_frame *f)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(ast);
	int res = -1;

	if (!p) {
		return -1;
	}

	/* Just queue for delivery to the other side */
	ao2_ref(p, 1);
	ao2_lock(p);
	switch (f->frametype) {
	case AST_FRAME_VOICE:
	case AST_FRAME_VIDEO:
		if (got_optimized_out(ast, p)) {
			break;
		}
		/* fall through */
	default:
		res = unreal_queue_frame(p, AST_UNREAL_IS_OUTBOUND(ast, p), f, ast, 1);
		break;
	}
	ao2_unlock(p);
	ao2_ref(p, -1);

	return res;
}

int ast_unreal_fixup(struct ast_channel *oldchan, struct ast_channel *newchan)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(newchan);
	struct ast_bridge *bridge_owner;
	struct ast_bridge *bridge_chan;

	if (!p) {
		return -1;
	}

	ao2_lock(p);

	if ((p->owner != oldchan) && (p->chan != oldchan)) {
		ast_log(LOG_WARNING, "Old channel %p wasn't %p or %p\n", oldchan, p->owner, p->chan);
		ao2_unlock(p);
		return -1;
	}
	if (p->owner == oldchan) {
		p->owner = newchan;
	} else {
		p->chan = newchan;
	}

	if (ast_check_hangup(newchan) || !p->owner || !p->chan) {
		ao2_unlock(p);
		return 0;
	}

	/* Do not let a masquerade cause a Local channel to be bridged to itself! */
	bridge_owner = ast_channel_internal_bridge(p->owner);
	bridge_chan = ast_channel_internal_bridge(p->chan);
	if (bridge_owner && bridge_owner == bridge_chan) {
		ast_log(LOG_WARNING, "You can not bridge a Local channel to itself!\n");
		ao2_unlock(p);
		ast_queue_hangup(newchan);
		return -1;
	}

	ao2_unlock(p);
	return 0;
}

/*!
 * \internal
 * \brief Queue up a frame representing the indication as a control frame.
 * \since 12.0.0
 *
 * \param p Unreal private structure.
 * \param ast Channel indicating the condition.
 * \param condition What is being indicated.
 * \param data Extra data.
 * \param datalen Length of extra data.
 *
 * \retval 0 on success.
 * \retval AST_T38_REQUEST_PARMS if successful and condition is AST_CONTROL_T38_PARAMETERS.
 * \retval -1 on error.
 */
static int unreal_queue_indicate(struct ast_unreal_pvt *p, struct ast_channel *ast, int condition, const void *data, size_t datalen)
{
	int res = 0;
	int isoutbound;

	ao2_lock(p);
	/*
	 * Block -1 stop tones events if we are to be optimized out.  We
	 * don't need a flurry of these events on an unreal channel chain
	 * when initially connected to slow the optimization process.
	 */
	if (0 <= condition || ast_test_flag(p, AST_UNREAL_NO_OPTIMIZATION)) {
		struct ast_frame f = {
			.frametype = AST_FRAME_CONTROL,
			.subclass.integer = condition,
			.data.ptr = (void *) data,
			.datalen = datalen,
		};

		isoutbound = AST_UNREAL_IS_OUTBOUND(ast, p);
		res = unreal_queue_frame(p, isoutbound, &f, ast, 1);
		if (!res
			&& condition == AST_CONTROL_T38_PARAMETERS
			&& datalen == sizeof(struct ast_control_t38_parameters)) {
			const struct ast_control_t38_parameters *parameters = data;

			if (parameters->request_response == AST_T38_REQUEST_PARMS) {
				res = AST_T38_REQUEST_PARMS;
			}
		}
	} else {
		ast_debug(4, "Blocked indication %d\n", condition);
	}
	ao2_unlock(p);

	return res;
}

/*!
 * \internal
 * \brief Handle COLP and redirecting conditions.
 * \since 12.0.0
 *
 * \param p Unreal private structure.
 * \param ast Channel indicating the condition.
 * \param condition What is being indicated.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
static int unreal_colp_redirect_indicate(struct ast_unreal_pvt *p, struct ast_channel *ast, int condition)
{
	struct ast_channel *this_channel;
	struct ast_channel *the_other_channel;
	int isoutbound;
	int res = 0;

	/*
	 * A connected line update frame may only contain a partial
	 * amount of data, such as just a source, or just a ton, and not
	 * the full amount of information.  However, the collected
	 * information is all stored in the outgoing channel's
	 * connectedline structure, so when receiving a connected line
	 * update on an outgoing unreal channel, we need to transmit the
	 * collected connected line information instead of whatever
	 * happens to be in this control frame.  The same applies for
	 * redirecting information, which is why it is handled here as
	 * well.
	 */
	ao2_lock(p);
	isoutbound = AST_UNREAL_IS_OUTBOUND(ast, p);
	if (isoutbound) {
		this_channel = p->chan;
		the_other_channel = p->owner;
	} else {
		this_channel = p->owner;
		the_other_channel = p->chan;
	}
	if (the_other_channel) {
		unsigned char frame_data[1024];
		struct ast_frame f = {
			.frametype = AST_FRAME_CONTROL,
			.subclass.integer = condition,
			.data.ptr = frame_data,
		};

		if (condition == AST_CONTROL_CONNECTED_LINE) {
			ast_connected_line_copy_to_caller(ast_channel_caller(the_other_channel),
				ast_channel_connected(this_channel));
			f.datalen = ast_connected_line_build_data(frame_data, sizeof(frame_data),
				ast_channel_connected(this_channel), NULL);
		} else {
			f.datalen = ast_redirecting_build_data(frame_data, sizeof(frame_data),
				ast_channel_redirecting(this_channel), NULL);
		}
		res = unreal_queue_frame(p, isoutbound, &f, ast, 1);
	}
	ao2_unlock(p);

	return res;
}

int ast_unreal_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(ast);
	int res = 0;

	if (!p) {
		return -1;
	}

	ao2_ref(p, 1); /* ref for unreal_queue_frame */

	switch (condition) {
	case AST_CONTROL_CONNECTED_LINE:
	case AST_CONTROL_REDIRECTING:
		res = unreal_colp_redirect_indicate(p, ast, condition);
		break;
	case AST_CONTROL_HOLD:
		if (ast_test_flag(p, AST_UNREAL_MOH_INTERCEPT)) {
			ast_moh_start(ast, data, NULL);
			break;
		}
		res = unreal_queue_indicate(p, ast, condition, data, datalen);
		break;
	case AST_CONTROL_UNHOLD:
		if (ast_test_flag(p, AST_UNREAL_MOH_INTERCEPT)) {
			ast_moh_stop(ast);
			break;
		}
		res = unreal_queue_indicate(p, ast, condition, data, datalen);
		break;
	default:
		res = unreal_queue_indicate(p, ast, condition, data, datalen);
		break;
	}

	ao2_ref(p, -1);
	return res;
}

int ast_unreal_digit_begin(struct ast_channel *ast, char digit)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(ast);
	int res = -1;
	struct ast_frame f = { AST_FRAME_DTMF_BEGIN, };
	int isoutbound;

	if (!p) {
		return -1;
	}

	ao2_ref(p, 1); /* ref for unreal_queue_frame */
	ao2_lock(p);
	isoutbound = AST_UNREAL_IS_OUTBOUND(ast, p);
	f.subclass.integer = digit;
	res = unreal_queue_frame(p, isoutbound, &f, ast, 0);
	ao2_unlock(p);
	ao2_ref(p, -1);

	return res;
}

int ast_unreal_digit_end(struct ast_channel *ast, char digit, unsigned int duration)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(ast);
	int res = -1;
	struct ast_frame f = { AST_FRAME_DTMF_END, };
	int isoutbound;

	if (!p) {
		return -1;
	}

	ao2_ref(p, 1); /* ref for unreal_queue_frame */
	ao2_lock(p);
	isoutbound = AST_UNREAL_IS_OUTBOUND(ast, p);
	f.subclass.integer = digit;
	f.len = duration;
	res = unreal_queue_frame(p, isoutbound, &f, ast, 0);
	ao2_unlock(p);
	ao2_ref(p, -1);

	return res;
}

int ast_unreal_sendtext(struct ast_channel *ast, const char *text)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(ast);
	int res = -1;
	struct ast_frame f = { AST_FRAME_TEXT, };
	int isoutbound;

	if (!p) {
		return -1;
	}

	ao2_ref(p, 1); /* ref for unreal_queue_frame */
	ao2_lock(p);
	isoutbound = AST_UNREAL_IS_OUTBOUND(ast, p);
	f.data.ptr = (char *) text;
	f.datalen = strlen(text) + 1;
	res = unreal_queue_frame(p, isoutbound, &f, ast, 0);
	ao2_unlock(p);
	ao2_ref(p, -1);
	return res;
}

int ast_unreal_sendhtml(struct ast_channel *ast, int subclass, const char *data, int datalen)
{
	struct ast_unreal_pvt *p = ast_channel_tech_pvt(ast);
	int res = -1;
	struct ast_frame f = { AST_FRAME_HTML, };
	int isoutbound;

	if (!p) {
		return -1;
	}

	ao2_ref(p, 1); /* ref for unreal_queue_frame */
	ao2_lock(p);
	isoutbound = AST_UNREAL_IS_OUTBOUND(ast, p);
	f.subclass.integer = subclass;
	f.data.ptr = (char *)data;
	f.datalen = datalen;
	res = unreal_queue_frame(p, isoutbound, &f, ast, 0);
	ao2_unlock(p);
	ao2_ref(p, -1);

	return res;
}

void ast_unreal_call_setup(struct ast_channel *semi1, struct ast_channel *semi2)
{
	struct ast_var_t *varptr;
	struct ast_var_t *clone_var;

	/*
	 * Note that cid_num and cid_name aren't passed in the
	 * ast_channel_alloc calls in ast_unreal_new_channels().  It's
	 * done here instead.
	 */
	ast_party_redirecting_copy(ast_channel_redirecting(semi2), ast_channel_redirecting(semi1));

	ast_party_dialed_copy(ast_channel_dialed(semi2), ast_channel_dialed(semi1));

	ast_connected_line_copy_to_caller(ast_channel_caller(semi2), ast_channel_connected(semi1));
	ast_connected_line_copy_from_caller(ast_channel_connected(semi2), ast_channel_caller(semi1));

	ast_channel_language_set(semi2, ast_channel_language(semi1));
	ast_channel_accountcode_set(semi2, ast_channel_accountcode(semi1));
	ast_channel_musicclass_set(semi2, ast_channel_musicclass(semi1));

	ast_channel_cc_params_init(semi2, ast_channel_get_cc_config_params(semi1));

	/*
	 * Make sure we inherit the AST_CAUSE_ANSWERED_ELSEWHERE if it's
	 * set on the queue/dial call request in the dialplan.
	 */
	if (ast_channel_hangupcause(semi1) == AST_CAUSE_ANSWERED_ELSEWHERE) {
		ast_channel_hangupcause_set(semi2, AST_CAUSE_ANSWERED_ELSEWHERE);
	}

	/*
	 * Copy the channel variables from the semi1 channel to the
	 * outgoing channel.
	 *
	 * Note that due to certain assumptions, they MUST be in the
	 * same order.
	 */
	AST_LIST_TRAVERSE(ast_channel_varshead(semi1), varptr, entries) {
		clone_var = ast_var_assign(varptr->name, varptr->value);
		if (clone_var) {
			AST_LIST_INSERT_TAIL(ast_channel_varshead(semi2), clone_var, entries);
		}
	}
	ast_channel_datastore_inherit(semi1, semi2);
}

/*!
 * \internal
 * \brief Post the LocalBridge AMI event.
 * \since 12.0.0
 *
 * \param p local_pvt to raise the bridge event.
 *
 * \return Nothing
 */
static void local_bridge_event(struct local_pvt *p)
{
	ao2_lock(p);
	/*** DOCUMENTATION
		<managerEventInstance>
			<synopsis>Raised when two halves of a Local Channel form a bridge.</synopsis>
			<syntax>
				<parameter name="Channel1">
					<para>The name of the Local Channel half that bridges to another channel.</para>
				</parameter>
				<parameter name="Channel2">
					<para>The name of the Local Channel half that executes the dialplan.</para>
				</parameter>
				<parameter name="Context">
					<para>The context in the dialplan that Channel2 starts in.</para>
				</parameter>
				<parameter name="Exten">
					<para>The extension in the dialplan that Channel2 starts in.</para>
				</parameter>
				<parameter name="LocalOptimization">
					<enumlist>
						<enum name="Yes"/>
						<enum name="No"/>
					</enumlist>
				</parameter>
			</syntax>
		</managerEventInstance>
	***/
	manager_event(EVENT_FLAG_CALL, "LocalBridge",
		"Channel1: %s\r\n"
		"Channel2: %s\r\n"
		"Uniqueid1: %s\r\n"
		"Uniqueid2: %s\r\n"
		"Context: %s\r\n"
		"Exten: %s\r\n"
		"LocalOptimization: %s\r\n",
		ast_channel_name(p->base.owner), ast_channel_name(p->base.chan),
		ast_channel_uniqueid(p->base.owner), ast_channel_uniqueid(p->base.chan),
		p->context, p->exten,
		ast_test_flag(&p->base, AST_UNREAL_NO_OPTIMIZATION) ? "Yes" : "No");
	ao2_unlock(p);
}

int ast_local_setup_bridge(struct ast_channel *ast, struct ast_bridge *bridge, struct ast_channel *swap, struct ast_bridge_features *features)
{
	struct local_pvt *p;
	struct local_pvt *found;
	int res = -1;

	/* Sanity checks. */
	if (!ast || !bridge) {
		ast_bridge_features_destroy(features);
		return -1;
	}

	ast_channel_lock(ast);
	p = ast_channel_tech_pvt(ast);
	ast_channel_unlock(ast);

	found = p ? ao2_find(locals, p, 0) : NULL;
	if (found) {
		ao2_lock(found);
		if (found->type == LOCAL_CALL_ACTION_DIALPLAN
			&& found->base.owner
			&& found->base.chan
			&& !ast_test_flag(&found->base, AST_UNREAL_CARETAKER_THREAD)) {
			ao2_ref(bridge, +1);
			if (swap) {
				ast_channel_ref(swap);
			}
			found->type = LOCAL_CALL_ACTION_BRIDGE;
			found->action.bridge.join = bridge;
			found->action.bridge.swap = swap;
			found->action.bridge.features = features;
			res = 0;
		} else {
			ast_bridge_features_destroy(features);
		}
		ao2_unlock(found);
		ao2_ref(found, -1);
	}

	return res;
}

int ast_local_setup_masquerade(struct ast_channel *ast, struct ast_channel *masq)
{
	struct local_pvt *p;
	struct local_pvt *found;
	int res = -1;

	/* Sanity checks. */
	if (!ast || !masq) {
		return -1;
	}

	ast_channel_lock(ast);
	p = ast_channel_tech_pvt(ast);
	ast_channel_unlock(ast);

	found = p ? ao2_find(locals, p, 0) : NULL;
	if (found) {
		ao2_lock(found);
		if (found->type == LOCAL_CALL_ACTION_DIALPLAN
			&& found->base.owner
			&& found->base.chan
			&& !ast_test_flag(&found->base, AST_UNREAL_CARETAKER_THREAD)) {
			ast_channel_ref(masq);
			found->type = LOCAL_CALL_ACTION_MASQUERADE;
			found->action.masq = masq;
			res = 0;
		}
		ao2_unlock(found);
		ao2_ref(found, -1);
	}

	return res;
}

/*! \brief Initiate new call, part of PBX interface
 *         dest is the dial string */
static int local_call(struct ast_channel *ast, const char *dest, int timeout)
{
	struct local_pvt *p = ast_channel_tech_pvt(ast);
	int pvt_locked = 0;

	struct ast_channel *owner = NULL;
	struct ast_channel *chan = NULL;
	int res;
	char *reduced_dest = ast_strdupa(dest);
	char *slash;
	const char *chan_cid;

	if (!p) {
		return -1;
	}

	/* since we are letting go of channel locks that were locked coming into
	 * this function, then we need to give the tech pvt a ref */
	ao2_ref(p, 1);
	ast_channel_unlock(ast);

	ast_unreal_lock_all(&p->base, &chan, &owner);
	pvt_locked = 1;

	if (owner != ast) {
		res = -1;
		goto return_cleanup;
	}

	if (!owner || !chan) {
		res = -1;
		goto return_cleanup;
	}

	ast_unreal_call_setup(owner, chan);

	/*
	 * If the local channel has /n on the end of it, we need to lop
	 * that off for our argument to setting up the CC_INTERFACES
	 * variable.
	 */
	if ((slash = strrchr(reduced_dest, '/'))) {
		*slash = '\0';
	}
	ast_set_cc_interfaces_chanvar(chan, reduced_dest);

	ao2_unlock(p);
	pvt_locked = 0;

	ast_channel_unlock(owner);

	chan_cid = S_COR(ast_channel_caller(chan)->id.number.valid,
		ast_channel_caller(chan)->id.number.str, NULL);
	if (chan_cid) {
		chan_cid = ast_strdupa(chan_cid);
	}
	ast_channel_unlock(chan);

	res = -1;
	switch (p->type) {
	case LOCAL_CALL_ACTION_DIALPLAN:
		if (!ast_exists_extension(NULL, p->context, p->exten, 1, chan_cid)) {
			ast_log(LOG_NOTICE, "No such extension/context %s@%s while calling Local channel\n",
				p->exten, p->context);
		} else {
			local_bridge_event(p);

			/* Start switch on sub channel */
			res = ast_pbx_start(chan);
		}
		break;
	case LOCAL_CALL_ACTION_BRIDGE:
		local_bridge_event(p);
		ast_answer(chan);
		res = ast_bridge_impart(p->action.bridge.join, chan, p->action.bridge.swap,
			p->action.bridge.features, 1);
		ao2_ref(p->action.bridge.join, -1);
		p->action.bridge.join = NULL;
		ao2_cleanup(p->action.bridge.swap);
		p->action.bridge.swap = NULL;
		p->action.bridge.features = NULL;
		break;
	case LOCAL_CALL_ACTION_MASQUERADE:
		local_bridge_event(p);
		ast_answer(chan);
		res = ast_channel_masquerade(p->action.masq, chan);
		if (!res) {
			ast_do_masquerade(p->action.masq);
			/* Chan is now an orphaned zombie.  Destroy it. */
			ast_hangup(chan);
		}
		p->action.masq = ast_channel_unref(p->action.masq);
		break;
	}
	if (!res) {
		ao2_lock(p);
		ast_set_flag(&p->base, AST_UNREAL_CARETAKER_THREAD);
		ao2_unlock(p);
	}

	/* we already unlocked them, clear them here so the cleanup label won't touch them. */
	owner = ast_channel_unref(owner);
	chan = ast_channel_unref(chan);

return_cleanup:
	if (p) {
		if (pvt_locked) {
			ao2_unlock(p);
		}
		ao2_ref(p, -1);
	}
	if (chan) {
		ast_channel_unlock(chan);
		ast_channel_unref(chan);
	}

	/*
	 * owner is supposed to be == to ast, if it is, don't unlock it
	 * because ast must exit locked
	 */
	if (owner) {
		if (owner != ast) {
			ast_channel_unlock(owner);
			ast_channel_lock(ast);
		}
		ast_channel_unref(owner);
	} else {
		/* we have to exit with ast locked */
		ast_channel_lock(ast);
	}

	return res;
}

int ast_unreal_hangup(struct ast_unreal_pvt *p, struct ast_channel *ast)
{
	int hangup_chan = 0;
	int res = 0;
	int cause;
	struct ast_channel *owner = NULL;
	struct ast_channel *chan = NULL;

	/* the pvt isn't going anywhere, it has a ref */
	ast_channel_unlock(ast);

	/* lock everything */
	ast_unreal_lock_all(p, &chan, &owner);

	if (ast != chan && ast != owner) {
		res = -1;
		goto unreal_hangup_cleanup;
	}

	cause = ast_channel_hangupcause(ast);

	if (ast == p->chan) {
		/* Outgoing side is hanging up. */
		ast_clear_flag(p, AST_UNREAL_CARETAKER_THREAD);
		p->chan = NULL;
		if (p->owner) {
			const char *status = pbx_builtin_getvar_helper(p->chan, "DIALSTATUS");

			if (status) {
				ast_channel_hangupcause_set(p->owner, cause);
				pbx_builtin_setvar_helper(p->owner, "CHANLOCALSTATUS", status);
			}
			ast_queue_hangup_with_cause(p->owner, cause);
		}
	} else {
		/* Owner side is hanging up. */
		p->owner = NULL;
		if (p->chan) {
			if (cause == AST_CAUSE_ANSWERED_ELSEWHERE) {
				ast_channel_hangupcause_set(p->chan, AST_CAUSE_ANSWERED_ELSEWHERE);
				ast_debug(2, "%s has AST_CAUSE_ANSWERED_ELSEWHERE set.\n",
					ast_channel_name(p->chan));
			}
			if (!ast_test_flag(p, AST_UNREAL_CARETAKER_THREAD)) {
				/*
				 * Need to actually hangup p->chan since nothing else is taking
				 * care of it.
				 */
				hangup_chan = 1;
			} else {
				ast_queue_hangup_with_cause(p->chan, cause);
			}
		}
	}

	/* this is one of our locked channels, doesn't matter which */
	ast_channel_tech_pvt_set(ast, NULL);
	ao2_ref(p, -1);

unreal_hangup_cleanup:
	ao2_unlock(p);
	if (owner) {
		ast_channel_unlock(owner);
		ast_channel_unref(owner);
	}
	if (chan) {
		ast_channel_unlock(chan);
		if (hangup_chan) {
			ast_hangup(chan);
		}
		ast_channel_unref(chan);
	}

	/* leave with the channel locked that came in */
	ast_channel_lock(ast);

	return res;
}

/*! \brief Hangup a call through the local proxy channel */
static int local_hangup(struct ast_channel *ast)
{
	struct local_pvt *p = ast_channel_tech_pvt(ast);
	int res;

	if (!p) {
		return -1;
	}

	/* give the pvt a ref to fulfill calling requirements. */
	ao2_ref(p, +1);
	res = ast_unreal_hangup(&p->base, ast);
	if (!res) {
		int unlink;

		ao2_lock(p);
		unlink = !p->base.owner && !p->base.chan;
		ao2_unlock(p);
		if (unlink) {
			ao2_unlink(locals, p);
		}
	}
	ao2_ref(p, -1);

	return res;
}

void ast_unreal_destructor(void *vdoomed)
{
	struct ast_unreal_pvt *doomed = vdoomed;

	doomed->reqcap = ast_format_cap_destroy(doomed->reqcap);
}

struct ast_unreal_pvt *ast_unreal_alloc(size_t size, ao2_destructor_fn destructor, struct ast_format_cap *cap)
{
	struct ast_unreal_pvt *unreal;

	static const struct ast_jb_conf jb_conf = {
		.flags = 0,
		.max_size = -1,
		.resync_threshold = -1,
		.impl = "",
		.target_extra = -1,
	};

	unreal = ao2_alloc(size, destructor);
	if (!unreal) {
		return NULL;
	}
	unreal->reqcap = ast_format_cap_dup(cap);
	if (!unreal->reqcap) {
		ao2_ref(unreal, -1);
		return NULL;
	}

	memcpy(&unreal->jb_conf, &jb_conf, sizeof(unreal->jb_conf));

	return unreal;
}

/*!
 * \internal
 * \brief struct local_pvt destructor.
 *
 * \param vdoomed Object to destroy.
 *
 * \return Nothing
 */
static void local_pvt_destructor(void *vdoomed)
{
	struct local_pvt *doomed = vdoomed;

	switch (doomed->type) {
	case LOCAL_CALL_ACTION_DIALPLAN:
		break;
	case LOCAL_CALL_ACTION_BRIDGE:
		ao2_cleanup(doomed->action.bridge.join);
		ao2_cleanup(doomed->action.bridge.swap);
		ast_bridge_features_destroy(doomed->action.bridge.features);
		break;
	case LOCAL_CALL_ACTION_MASQUERADE:
		ao2_cleanup(doomed->action.masq);
		break;
	}
	ast_unreal_destructor(&doomed->base);
}

/*! \brief Create a call structure */
static struct local_pvt *local_alloc(const char *data, struct ast_format_cap *cap)
{
	struct local_pvt *pvt;
	char *parse;
	char *context;
	char *opts;

	pvt = (struct local_pvt *) ast_unreal_alloc(sizeof(*pvt), local_pvt_destructor, cap);
	if (!pvt) {
		return NULL;
	}

	parse = ast_strdupa(data);

	/*
	 * Local channels intercept MOH by default.
	 *
	 * This is a silly default because it represents state held by
	 * the local channels.  Unless local channel optimization is
	 * disabled, the state will dissapear when the local channels
	 * optimize out.
	 */
	ast_set_flag(&pvt->base, AST_UNREAL_MOH_INTERCEPT);

	/* Look for options */
	if ((opts = strchr(parse, '/'))) {
		*opts++ = '\0';
		if (strchr(opts, 'n')) {
			ast_set_flag(&pvt->base, AST_UNREAL_NO_OPTIMIZATION);
		}
		if (strchr(opts, 'j')) {
			if (ast_test_flag(&pvt->base, AST_UNREAL_NO_OPTIMIZATION)) {
				ast_set_flag(&pvt->base.jb_conf, AST_JB_ENABLED);
			} else {
				ast_log(LOG_ERROR, "You must use the 'n' option with the 'j' option to enable the jitter buffer\n");
			}
		}
		if (strchr(opts, 'm')) {
			ast_clear_flag(&pvt->base, AST_UNREAL_MOH_INTERCEPT);
		}
	}

	/* Look for a context */
	if ((context = strchr(parse, '@'))) {
		*context++ = '\0';
	}

	ast_copy_string(pvt->context, S_OR(context, "default"), sizeof(pvt->context));
	ast_copy_string(pvt->exten, parse, sizeof(pvt->exten));
	snprintf(pvt->base.name, sizeof(pvt->base.name), "%s@%s", pvt->exten, pvt->context);

	return pvt; /* this is returned with a ref */
}

struct ast_channel *ast_unreal_new_channels(struct ast_unreal_pvt *p,
	const struct ast_channel_tech *tech, int semi1_state, int semi2_state,
	const char *exten, const char *context, struct ast_channel *requestor,
	struct ast_callid *callid)
{
	struct ast_channel *owner;
	struct ast_channel *chan;
	const char *linkedid = requestor ? ast_channel_linkedid(requestor) : NULL;
	struct ast_format fmt;
	int generated_seqno = ast_atomic_fetchadd_int((int *) &name_sequence, +1);

	/*
	 * Allocate two new Asterisk channels
	 *
	 * Make sure that the ;2 channel gets the same linkedid as ;1.
	 * You can't pass linkedid to both allocations since if linkedid
	 * isn't set, then each channel will generate its own linkedid.
	 */
	if (!(owner = ast_channel_alloc(1, semi1_state, NULL, NULL, NULL,
			exten, context, linkedid, 0,
			"%s/%s-%08x;1", tech->type, p->name, generated_seqno))
		|| !(chan = ast_channel_alloc(1, semi2_state, NULL, NULL, NULL,
			exten, context, ast_channel_linkedid(owner), 0,
			"%s/%s-%08x;2", tech->type, p->name, generated_seqno))) {
		if (owner) {
			owner = ast_channel_release(owner);
		}
		ast_log(LOG_WARNING, "Unable to allocate channel structure(s)\n");
		return NULL;
	}

	if (callid) {
		ast_channel_callid_set(owner, callid);
		ast_channel_callid_set(chan, callid);
	}

	ast_channel_tech_set(owner, tech);
	ast_channel_tech_set(chan, tech);
	ast_channel_tech_pvt_set(owner, p);
	ast_channel_tech_pvt_set(chan, p);

	ast_format_cap_copy(ast_channel_nativeformats(owner), p->reqcap);
	ast_format_cap_copy(ast_channel_nativeformats(chan), p->reqcap);

	/* Determine our read/write format and set it on each channel */
	ast_best_codec(p->reqcap, &fmt);
	ast_format_copy(ast_channel_writeformat(owner), &fmt);
	ast_format_copy(ast_channel_writeformat(chan), &fmt);
	ast_format_copy(ast_channel_rawwriteformat(owner), &fmt);
	ast_format_copy(ast_channel_rawwriteformat(chan), &fmt);
	ast_format_copy(ast_channel_readformat(owner), &fmt);
	ast_format_copy(ast_channel_readformat(chan), &fmt);
	ast_format_copy(ast_channel_rawreadformat(owner), &fmt);
	ast_format_copy(ast_channel_rawreadformat(chan), &fmt);

	ast_set_flag(ast_channel_flags(owner), AST_FLAG_DISABLE_DEVSTATE_CACHE);
	ast_set_flag(ast_channel_flags(chan), AST_FLAG_DISABLE_DEVSTATE_CACHE);

	ast_jb_configure(owner, &p->jb_conf);

	if (ast_channel_cc_params_init(owner, requestor ? ast_channel_get_cc_config_params(requestor) : NULL)) {
		ast_channel_release(owner);
		ast_channel_release(chan);
		return NULL;
	}

	/* Give the private a ref for each channel. */
	ao2_ref(p, +2);
	p->owner = owner;
	p->chan = chan;

	return owner;
}

/*! \brief Part of PBX interface */
static struct ast_channel *local_request(const char *type, struct ast_format_cap *cap, const struct ast_channel *requestor, const char *data, int *cause)
{
	struct local_pvt *p;
	struct ast_channel *chan;
	struct ast_callid *callid;

	/* Allocate a new private structure and then Asterisk channels */
	p = local_alloc(data, cap);
	if (!p) {
		return NULL;
	}
	callid = ast_read_threadstorage_callid();
	chan = ast_unreal_new_channels(&p->base, &local_tech, AST_STATE_DOWN, AST_STATE_RING,
		p->exten, p->context, (struct ast_channel *) requestor, callid);
	if (chan) {
		ao2_link(locals, p);
	}
	if (callid) {
		ast_callid_unref(callid);
	}
	ao2_ref(p, -1); /* kill the ref from the alloc */

	return chan;
}

/*! \brief CLI command "local show channels" */
static char *locals_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct local_pvt *p;
	struct ao2_iterator it;

	switch (cmd) {
	case CLI_INIT:
		e->command = "local show channels";
		e->usage =
			"Usage: local show channels\n"
			"       Provides summary information on active local proxy channels.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	if (ao2_container_count(locals) == 0) {
		ast_cli(a->fd, "No local channels in use\n");
		return RESULT_SUCCESS;
	}

	it = ao2_iterator_init(locals, 0);
	while ((p = ao2_iterator_next(&it))) {
		ao2_lock(p);
		ast_cli(a->fd, "%s -- %s\n",
			p->base.owner ? ast_channel_name(p->base.owner) : "<unowned>",
			p->base.name);
		ao2_unlock(p);
		ao2_ref(p, -1);
	}
	ao2_iterator_destroy(&it);

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_local[] = {
	AST_CLI_DEFINE(locals_show, "List status of local channels"),
};

static int manager_optimize_away(struct mansession *s, const struct message *m)
{
	const char *channel;
	struct local_pvt *p;
	struct local_pvt *found;
	struct ast_channel *chan;

	channel = astman_get_header(m, "Channel");
	if (ast_strlen_zero(channel)) {
		astman_send_error(s, m, "'Channel' not specified.");
		return 0;
	}

	chan = ast_channel_get_by_name(channel);
	if (!chan) {
		astman_send_error(s, m, "Channel does not exist.");
		return 0;
	}

	p = ast_channel_tech_pvt(chan);
	ast_channel_unref(chan);

	found = p ? ao2_find(locals, p, 0) : NULL;
	if (found) {
		ao2_lock(found);
		ast_clear_flag(&found->base, AST_UNREAL_NO_OPTIMIZATION);
		ao2_unlock(found);
		ao2_ref(found, -1);
		astman_send_ack(s, m, "Queued channel to be optimized away");
	} else {
		astman_send_error(s, m, "Unable to find channel");
	}

	return 0;
}


static int locals_cmp_cb(void *obj, void *arg, int flags)
{
	return (obj == arg) ? CMP_MATCH : 0;
}

/*!
 * \internal
 * \brief Shutdown the local proxy channel and unreal derivative framework system.
 * \since 12.0.0
 *
 * \return Nothing
 */
static void unreal_shutdown(void)
{
	struct local_pvt *p;
	struct ao2_iterator it;

	/* First, take us out of the channel loop */
	ast_cli_unregister_multiple(cli_local, ARRAY_LEN(cli_local));
	ast_manager_unregister("LocalOptimizeAway");
	ast_channel_unregister(&local_tech);

	it = ao2_iterator_init(locals, 0);
	while ((p = ao2_iterator_next(&it))) {
		if (p->base.owner) {
			ast_softhangup(p->base.owner, AST_SOFTHANGUP_APPUNLOAD);
		}
		ao2_ref(p, -1);
	}
	ao2_iterator_destroy(&it);
	ao2_ref(locals, -1);
	locals = NULL;

	ast_format_cap_destroy(local_tech.capabilities);
}

int ast_unreal_init(void)
{
	if (!(local_tech.capabilities = ast_format_cap_alloc())) {
		return -1;
	}
	ast_format_cap_add_all(local_tech.capabilities);

	locals = ao2_container_alloc_list(AO2_ALLOC_OPT_LOCK_MUTEX, 0, NULL, locals_cmp_cb);
	if (!locals) {
		ast_format_cap_destroy(local_tech.capabilities);
		return -1;
	}

	/* Make sure we can register our channel type */
	if (ast_channel_register(&local_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'Local'\n");
		ao2_ref(locals, -1);
		ast_format_cap_destroy(local_tech.capabilities);
		return -1;
	}
	ast_cli_register_multiple(cli_local, ARRAY_LEN(cli_local));
	ast_manager_register_xml_core("LocalOptimizeAway", EVENT_FLAG_SYSTEM|EVENT_FLAG_CALL, manager_optimize_away);

	ast_register_atexit(unreal_shutdown);
	return 0;
}
