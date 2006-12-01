/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 * and Edvina AB, Sollentuna, Sweden (chan_sip3 changes/additions)
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
 * \brief The SIP monitor thread
 * Version 3 of chan_sip
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Olle E. Johansson <oej@edvina.net> (all the chan_sip3 changes)
 *
 * See Also:
 * \arg \ref AstCREDITS
 *
 */

/*! \page SIP3_monitor Chan_sip3:: The monitor thread
 *
 * The monitor thread is a background process that takes care of maintenance of the
 * SIP channel
 * 	- Destruction of SIP dialogs at timeout
 *	- Scheduled items, like retransmits, registrations that expire etc
 *	- Voicemail notifications
*/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 47624 $")

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <regex.h>

#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/options.h"
#include "asterisk/lock.h"
#include "asterisk/sched.h"
#include "asterisk/io.h"
#include "asterisk/rtp.h"
#include "asterisk/udptl.h"
#include "asterisk/acl.h"
#include "asterisk/manager.h"
#include "asterisk/callerid.h"
#include "asterisk/cli.h"
#include "asterisk/app.h"
#include "asterisk/musiconhold.h"
#include "asterisk/dsp.h"
#include "asterisk/features.h"
#include "asterisk/acl.h"
#include "asterisk/srv.h"
#include "asterisk/astdb.h"
#include "asterisk/causes.h"
#include "asterisk/utils.h"
#include "asterisk/file.h"
#include "asterisk/astobj.h"
#include "asterisk/dnsmgr.h"
#include "asterisk/devicestate.h"
#include "asterisk/linkedlists.h"
#include "asterisk/stringfields.h"
#include "asterisk/monitor.h"
#include "asterisk/localtime.h"
#include "asterisk/abstract_jb.h"
#include "asterisk/compiler.h"
#include "sip3.h"
#include "sip3funcs.h"

/*! \brief This is the thread for the monitor which checks for input on the channels
   which are not currently in use.  */
static pthread_t monitor_thread = AST_PTHREADT_NULL;


/*! \brief Protect the monitoring thread, so only one process can kill or start it, and not
   when it's doing something critical. */
AST_MUTEX_DEFINE_STATIC(monlock);

/*! \brief kill monitor thread (only at module unload) */
void kill_monitor(void)
{
	/* Kill the monitor thread */
	ast_mutex_lock(&monlock);
	if (monitor_thread && (monitor_thread != AST_PTHREADT_STOP)) {
		pthread_cancel(monitor_thread);
		pthread_kill(monitor_thread, SIGURG);
		pthread_join(monitor_thread, NULL);
	}
	monitor_thread = AST_PTHREADT_STOP;
	ast_mutex_unlock(&monlock);
}


/*! \brief Start the channel monitor thread */
int restart_monitor(void)
{
	/* If we're supposed to be stopped -- stay stopped */
	if (monitor_thread == AST_PTHREADT_STOP)
		return 0;
	/* Lock the monitor lock to keep the new monitor thread under control */
	ast_mutex_lock(&monlock);
	if (monitor_thread == pthread_self()) {
		ast_mutex_unlock(&monlock);
		ast_log(LOG_WARNING, "Cannot kill myself\n");
		return -1;
	}
	if (monitor_thread != AST_PTHREADT_NULL) {
		/* Wake up the thread */
		pthread_kill(monitor_thread, SIGURG);
	} else {
		/* Start a new monitor */
		if (ast_pthread_create_background(&monitor_thread, NULL, do_sip_monitor, NULL) < 0) {
			ast_mutex_unlock(&monlock);
			ast_log(LOG_ERROR, "Unable to start monitor thread.\n");
			return -1;
		}
	}

	/* Let the monitor run by itself now */
	ast_mutex_unlock(&monlock);
	return 0;
}


/*! \brief Check if we need to send RTP keepalive or hangup, due to RTP timers */
static void check_rtp_timeout(struct sip_dialog *sip, time_t t)
{
	/* Do we have a channel that is UP and do we handle RTP inside the box? */
	if (!(sip->rtp && sip->owner && (sip->owner->_state == AST_STATE_UP) &&
	    !sip->redirip.sin_addr.s_addr) )
		return;

	/* Do we need to sent RTP keepalive ? */
	if (sip->lastrtptx && sip->rtpkeepalive &&
	    (t > sip->lastrtptx + sip->rtpkeepalive)) {
		/* Need to send an empty RTP packet */
		sip->lastrtptx = time(NULL);
		ast_rtp_sendcng(sip->rtp, 0);
	}

	if (sip->lastrtprx && (sip->rtptimeout || sip->rtpholdtimeout) &&
	    (t > sip->lastrtprx + sip->rtptimeout)) {
		/* Might be a timeout now -- see if we're on hold */
		struct sockaddr_in sin;
		ast_rtp_get_peer(sip->rtp, &sin);
		if (sin.sin_addr.s_addr || 
		    (sip->rtpholdtimeout && (t > sip->lastrtprx + sip->rtpholdtimeout))) {
			/* Needs a hangup */
			if (!sip->rtptimeout)
				return;
			while (sip->owner && ast_channel_trylock(sip->owner)) {
				dialog_lock(sip, FALSE);
				usleep(1);
				dialog_lock(sip, TRUE);
			}
			if (!sip->owner) 
				return;

			if (ast_rtp_get_bridged(sip->rtp)) 
				ast_log(LOG_NOTICE, "'%s' will not be disconnected in %ld seconds because it is directly bridged to another RTP stream\n", sip->owner->name, (long) (t - sip->lastrtprx));
			else {
				ast_log(LOG_NOTICE, "Disconnecting call '%s' for lack of RTP activity in %ld seconds\n",
					sip->owner->name,
					(long) (t - sip->lastrtprx));
				/* Issue a softhangup */
				ast_softhangup_nolock(sip->owner, AST_SOFTHANGUP_DEV);
			} 
			ast_channel_unlock(sip->owner);
			/* forget the timeouts for this call, since a hangup
			   has already been requested and we don't want to
			   repeatedly request hangups
			*/
			sip->rtptimeout = 0;
			sip->rtpholdtimeout = 0;
		}
	}
}

/*! \brief Check whether peer needs a new MWI notification check */
static int does_peer_need_mwi(struct sip_peer *peer)
{
	time_t t = time(NULL);

	if (ast_test_flag(&peer->flags[1], SIP_PAGE2_SUBSCRIBEMWIONLY) &&
	    !peer->mwipvt) {	/* We don't have a subscription */
		peer->lastmsgcheck = t;	/* Reset timer */
		return FALSE;
	}

	if (!ast_strlen_zero(peer->mailbox) && (t - peer->lastmsgcheck) > global.mwitime)
		return TRUE;

	return FALSE;
}


/*! \brief The SIP monitoring thread 
\note	This thread monitors all the SIP sessions and peers that needs notification of mwi
	(and thus do not have a separate thread) indefinitely 
*/
void *do_sip_monitor(void *data)
{
	int res;
	struct sip_dialog *sip;
	struct sip_peer *peer = NULL;
	time_t t;
	int fastrestart = FALSE;
	int lastpeernum = -1;
	int curpeernum;
	int reloading;

	/* Add an I/O event to our SIP UDP socket */
	if (sipsocket_initialized())
		sipnet.read_id = ast_io_add(io, sipnet.sipsock, sipsock_read, AST_IO_IN, NULL);
	
	/* From here on out, we die whenever asked */
	for(;;) {
		/*------  Check for a reload request */
		if (sip_reload_check()) {
			if (option_verbose > 0)
				ast_verbose(VERBOSE_PREFIX_1 "Reloading SIP\n");
			sip_do_reload();

			/* Change the I/O fd of our UDP socket */
			if (sipsocket_initialized())
				sipnet.read_id = ast_io_change(io, sipnet.read_id, sipnet.sipsock, NULL, 0, NULL);
		}

		/*----- Check for interfaces needing to be killed */
		if (dialoglist != NULL) {
			ast_log(LOG_DEBUG, ":: MONITOR :: Walking dialog list.\n");
			dialoglist_lock();
restartsearch:		
			t = time(NULL);
			/* don't scan the interface list if it hasn't been a reasonable period
		   	of time since the last time we did it (when MWI is being sent, we can
		   	get back to this point every millisecond or less)
			*/
			for (sip = dialoglist; !fastrestart && sip; sip = sip->next) {
				dialog_lock(sip, TRUE);
				/* Check RTP timeouts and kill calls if we have a timeout set and do not get RTP or RTCP */
				check_rtp_timeout(sip, t);
				/* If we have sessions that needs to be destroyed, do it now */
				if (ast_test_flag(&sip->flags[0], SIP_NEEDDESTROY) && !sip->packets && !sip->owner) {
					dialog_lock(sip, FALSE);
					__sip_destroy(sip, TRUE, FALSE);
					goto restartsearch;
				}
				dialog_lock(sip, FALSE);
			}
			dialoglist_unlock();
		} else if (sipdebug && option_debug > 4) {
			ast_log(LOG_DEBUG, ":: MONITOR :: Empty dialog list. No walk today \n");
		}

		pthread_testcancel();

		/*------ Wait for sched or io */
		res = ast_sched_wait(sched);

		if ((res < 0) || (res > 1000))
			res = 1000;
		/* If we might need to send more mailboxes, don't wait long at all.*/
		if (fastrestart)
			res = 1;

		res = ast_io_wait(io, res);
		if (option_debug && res > 20)
			ast_log(LOG_DEBUG, "chan_sip: ast_io_wait ran %d all at once\n", res);
		ast_mutex_lock(&monlock);
		if (res >= 0)  {
			res = ast_sched_runq(sched);	/* Check for scheduled items, like retransmits */
			if (option_debug && res >= 20)
				ast_log(LOG_DEBUG, "chan_sip: ast_sched_runq ran %d all at once\n", res);
		}

		/*----- Send MWI notifications to peers - static and cached realtime peers */
		if (sipcounters.peers_with_mwi > 0 ) {
			t = time(NULL);
			fastrestart = FALSE;
			curpeernum = 0;
			peer = NULL;
			/* Find next peer that needs mwi */
			ASTOBJ_CONTAINER_TRAVERSE(&devicelist, !peer, do {
				if ((curpeernum > lastpeernum) && does_peer_need_mwi(iterator)) {
					fastrestart = TRUE;
					lastpeernum = curpeernum;
					peer = ASTOBJ_REF(iterator);
				};
				curpeernum++;
			} while (0)
			);
			/* Send MWI to the peer */
			if (peer) {
				ASTOBJ_WRLOCK(peer);
				sip_send_mwi_to_peer(peer);
				ASTOBJ_UNLOCK(peer);
				ASTOBJ_UNREF(peer,sip_destroy_device);
			} else {
				/* Reset where we come from */
				lastpeernum = -1;
			}
		}
		ast_mutex_unlock(&monlock);
	}
	/* Never reached */
	return NULL;
	
}

