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
 * \brief Various SIP dialog handlers
 * Version 3 of chan_sip
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Olle E. Johansson <oej@edvina.net> (all the chan_sip3 changes)
 *
 * See Also:
 * \arg \ref AstCREDITS
 *
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

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
#include "asterisk/threadstorage.h"
#include "sip3.h"
#include "sip3funcs.h"

/*! \page chan_sip3_dialogs Chan_sip3: The dialog list
	\title The dialog list
	The dialog list contains all active dialogs in various states.
	A dialog can be 
	- an active call
	- a call in hangup state - waiting for cleanup
	- a subscription
	- an inbound or outbound registration
	
	\ref dialoglist

	\title Dialog states
	Dialog states affect operation, especially in an INVITE
	dialog. We now try to change dialog state in a clear way
	\ref enum dialogstate

*/

/* Forward declaration */
static int temp_pvt_init(void *data);
static void temp_pvt_cleanup(void *data);

/*! \brief A per-thread temporary pvt structure */
AST_THREADSTORAGE_CUSTOM(ts_temp_pvt, temp_pvt_init, temp_pvt_cleanup);

/*! \brief Protect the SIP dialog list (of sip_dialog's) */
AST_MUTEX_DEFINE_STATIC(dialoglock);

/*! \brief Lock list of active SIP dialogs */
void dialoglist_lock(void)
{
	int counter = 0;
	while (ast_mutex_trylock(&dialoglock) && counter < 100) {
		if (option_debug > 4)
			ast_log(LOG_DEBUG, "---Trying to lock dialoglist -- %d \n", ++counter);
	} 
	if (counter == 100)
		ast_mutex_lock(&dialoglock);
	if (sipdebug && option_debug > 4)
		ast_log(LOG_DEBUG, "=== SIP dialog list: LOCKED\n");
}

/*! \brief Unlock list of active SIP dialogs */
void dialoglist_unlock(void)
{
	ast_mutex_unlock(&dialoglock);
	if (sipdebug && option_debug > 4)
		ast_log(LOG_DEBUG, "=== SIP dialog list: UNLOCKED\n");
}

/*! \brief Helper function to lock and unlock, hiding the underlying locking mechanism. 
	\param state TRUE for lock, FALSE for unlock
*/
void dialog_lock(struct sip_dialog *dialog, int state)
{
	if (!dialog) {
		ast_log(LOG_ERROR, "-DIALOGLOCK- Trying to %s non-existing dialog. Giving up.\n", state ? "lock" : "unlock");
		return;
	}
	if (sipdebug && option_debug > 4)
		ast_log(LOG_DEBUG, "-DIALOGLOCK- %s dialog %s\n", state ? "  locking" : "unlocking", dialog->callid ? dialog->callid : "<no callid>");

	if (state)
		ast_mutex_lock(&dialog->lock);
	else
		ast_mutex_unlock(&dialog->lock);
}

/*! \brief Convert SIP dialog states to string */
const char *dialogstate2str(const enum dialogstate state)
{
	const char *reply = "<unknown>";
	switch (state) {
	case DIALOG_STATE_TRYING:
		reply = "Trying";
		break;
	case DIALOG_STATE_PROCEEDING:
		reply = "Proceeding";
		break;
	case DIALOG_STATE_EARLY:
		reply = "Early";
		break;
	case DIALOG_STATE_CONFIRMED:
		reply = "Confirmed";
		break;
	case DIALOG_STATE_CONFIRMED_HOLD:
		reply = "Confirmed, on hold";
		break;
	case DIALOG_STATE_TERMINATED:
		reply = "Terminated";
		break;
	case DIALOG_STATE_TERMINATED_AUTH:
		reply = "Terminated, auth";
		break;
	}
	return reply;
}

/*! \brief Change dialog state for a SIP dialog and output to debug */
void dialogstatechange(struct sip_dialog *dialog, enum dialogstate newstate)
{
	if (dialog->state == newstate) {
		if (option_debug > 3)
			ast_log(LOG_DEBUG, "Asked to change state to dialog that already has requested state: %s State %s\n", dialog->callid, dialogstate2str(newstate));
	} else {
		dialog->state = newstate;
		if (sipdebug && option_debug > 1)
			ast_log(LOG_DEBUG, "-- Dialog %s changed state to %s\n", dialog->callid, dialogstate2str(newstate));
		if (global.recordhistory)
			append_history(dialog, "DialogState", "New state: %s O-Cseq %d I-Cseq %d", dialogstate2str(newstate), dialog->ocseq, dialog->icseq);
	}
	/* When state is terminated, keep it for 32 secs to allow for retransmits 
	 */
}


/*! \brief Transmit final response to a request and close dialog 
	Set dialog state to TERMINATED to avoid problems
	At some point, after debugging, we can remove the reliable flag. Only responses to INVITEs are sent reliably 
 */
int transmit_final_response(struct sip_dialog *dialog, const char *msg, const struct sip_request *req, enum xmittype reliable)
{
	int res;

	/* If this is a final response to an INVITE */
	if (reliable == XMIT_RELIABLE && req->method != SIP_INVITE)
		ast_log(LOG_WARNING, "Transmitting RELIABLE response to %s - Call ID %s (?? BUG ?? ) \n", sip_method2txt(req->method), dialog->callid);
	res = __transmit_response(dialog, msg, req, reliable);
	sip_scheddestroy(dialog, -1);	/* Destroy by using T1 timer if available */
	dialogstatechange(dialog, DIALOG_STATE_TERMINATED);
	return res;
}

/*! \brief For a reliable transmission, we need to get an reply to stop retransmission. 
	Acknowledges receipt of a packet and stops retransmission 
	\note Assume that the dialog is locked. 
 */
/* We need a method for responses too ... */
void __sip_ack(struct sip_dialog *dialog, int seqno, int resp, int sipmethod, int reset)
{
	struct sip_request *cur, *prev = NULL;
	int res = FALSE;

	dialog_lock(dialog, TRUE);

	/* Find proper transactoin */
	for (cur = dialog->packets; cur; prev = cur, cur = cur->next) {
		/* Match on seqno AND req/resp AND method? */
		if ((cur->seqno == seqno) && ((ast_test_flag(cur, SIP_PKT_RESPONSE)) == resp) &&
			((ast_test_flag(cur, SIP_PKT_RESPONSE)) || (cur->method == sipmethod))) {
			if (!resp && (seqno == dialog->pendinginvite)) {
				if (option_debug)
					ast_log(LOG_DEBUG, "Acked pending invite %d\n", dialog->pendinginvite);
				dialog->pendinginvite = 0;
			}
			/* this is our baby */
			res = TRUE;
			UNLINK(cur, dialog->packets, prev);
			if (cur->retransid > -1) {
				if (sipdebug && option_debug > 3)
					ast_log(LOG_DEBUG, "** SIP TIMER: Cancelling retransmit of packet (reply received) Retransid #%d\n", cur->retransid);
				ast_sched_del(sched, cur->retransid);
			}
			if (!reset)
				free(cur);	/* We might want to keep this somewhere else */
			break;
		}
	}
	dialog_lock(dialog, FALSE);
	if (option_debug)
		ast_log(LOG_DEBUG, "Stopping retransmission on '%s' of %s %d: Match %s\n", dialog->callid, resp ? "Response" : "Request", seqno, res ? "Not Found" : "Found");
}

/*! \brief Pretend to ack all packets - nothing to do with SIP_ACK (the method)
 *   maybe the lock on p is not strictly necessary but there might be a race */
GNURK void __sip_pretend_ack(struct sip_dialog *dialog)
{
	struct sip_request *cur = NULL;

	while (dialog->packets) {
		int method;
		if (cur == dialog->packets) {
			ast_log(LOG_WARNING, "Have a packet that doesn't want to give up! %s\n", sip_method2txt(cur->method));
			return;
		}
		cur = dialog->packets;
		method = (cur->method) ? cur->method : find_sip_method(cur->data);
		__sip_ack(dialog, cur->seqno, ast_test_flag(cur, SIP_PKT_RESPONSE), method, FALSE);
	}
}

/*! \brief Acks receipt of packet, keep it around (used for provisional responses) 
	\note Assume that the dialog is locked.
 */
int __sip_semi_ack(struct sip_dialog *dialog, int seqno, int resp, int sipmethod)
{
	struct sip_request *cur;
	int res = -1;

	for (cur = dialog->packets; cur; cur = cur->next) {
		if (cur->seqno == seqno && ast_test_flag(cur, SIP_PKT_RESPONSE) == resp &&
			(ast_test_flag(cur, SIP_PKT_RESPONSE) || method_match(sipmethod, cur->data))) {
			/* this is our baby */
			if (cur->retransid > -1) {
				if (option_debug > 3 && sipdebug)
					ast_log(LOG_DEBUG, "*** SIP TIMER: Cancelling retransmission #%d - %s (got response)\n", cur->retransid, sip_method2txt(sipmethod));
				ast_sched_del(sched, cur->retransid);
			}
			cur->retransid = -1;
			res = 0;
			break;
		}
	}
	if (option_debug)
		ast_log(LOG_DEBUG, "(Provisional) Stopping retransmission (but retaining packet) on '%s' %s %d: %s\n", dialog->callid, resp ? "Response" : "Request", seqno, res ? "Not Found" : "Found");
	return res;
}

/*! \brief Execute destruction of SIP dialog structure, release memory */
void __sip_destroy(struct sip_dialog *dialog, int lockowner, int lockdialoglist)
{
	struct sip_dialog *cur, *prev = NULL;
	struct sip_request *cp;

	if (ast_test_flag(&dialog->flags[0], SIP_INC_COUNT)) 			/* This dialog has incremented call count */
		update_call_counter(dialog, DEC_CALL_LIMIT);				/* Since it was forgotten, decrement call count */
	if (ast_test_flag(&dialog->flags[1], SIP_PAGE2_INC_RINGING)) 			/* This dialog has incremented ring count */
		update_call_counter(dialog, DEC_CALL_RINGING);				/* Since it was forgotten, decrement ring count */

	if (sip_debug_test_pvt(dialog) || option_debug > 2)
		ast_verbose("Really destroying SIP dialog '%s' Method: %s\n", dialog->callid, sip_method2txt(dialog->method));

	/* Remove link from peer to subscription of MWI */
	if (dialog->relatedpeer && dialog->relatedpeer->mwipvt)
		dialog->relatedpeer->mwipvt = NULL;

	if (global.dumphistory)
		sip_dump_history(dialog);


	if (dialog->stateid > -1)
		ast_extension_state_del(dialog->stateid, NULL);
	if (dialog->initid > -1)
		ast_sched_del(sched, dialog->initid);
	if (dialog->autokillid > -1)
		ast_sched_del(sched, dialog->autokillid);

	if (dialog->options)
		free(dialog->options);

	if (dialog->rtp)
		ast_rtp_destroy(dialog->rtp);
	if (dialog->vrtp)
		ast_rtp_destroy(dialog->vrtp);
	if (dialog->udptl)
		ast_udptl_destroy(dialog->udptl);
	if (dialog->refer)
		free(dialog->refer);
	if (dialog->route) {
		free_old_route(dialog->route);
		dialog->route = NULL;
	}
	if (dialog->registry) {
		if (dialog->registry->call == dialog)
			dialog->registry->call = NULL;
		ASTOBJ_UNREF(dialog->registry, sip_registry_destroy);
	}

	/* Unlink us from the owner if we have one */
	if (dialog->owner) {
		if (lockowner)
			ast_channel_lock(dialog->owner);
		if (option_debug)
			ast_log(LOG_DEBUG, "Detaching from %s\n", dialog->owner->name);
		dialog->owner->tech_pvt = NULL;
		if (lockowner)
			ast_channel_unlock(dialog->owner);
	}
	/* Clear history */
	if (dialog->history) {
		struct sip_history *hist;
		while( (hist = AST_LIST_REMOVE_HEAD(dialog->history, list)) )
			free(hist);
		free(dialog->history);
		dialog->history = NULL;
	}

	/* Unlink us from the dialog list */
	if (lockdialoglist)
		dialoglist_lock();
	for (prev = NULL, cur = dialoglist; cur; prev = cur, cur = cur->next) {
		if (cur == dialog) {
			UNLINK(cur, dialoglist, prev);
			break;
		}
	}
	if (lockdialoglist)
		dialoglist_unlock();

	if (!cur) {
		ast_log(LOG_WARNING, "Trying to destroy \"%s\", not found in dialog list?!?! \n", dialog->callid);
		return;
	} 

	/* remove all current packets in this dialog */
	while((cp = dialog->packets)) {
		dialog->packets = dialog->packets->next;
		if (cp->retransid > -1)
			ast_sched_del(sched, cp->retransid);
		free(cp);
	}
	if (dialog->chanvars) {
		ast_variables_destroy(dialog->chanvars);
		dialog->chanvars = NULL;
	}
	ast_mutex_destroy(&dialog->lock);

	ast_string_field_free_pools(dialog);

	/* Finally, release the dialog */
	free(dialog);

	sipcounters.dialog_objects--;
	if (option_debug > 3)
		ast_log(LOG_DEBUG, "--DIALOGS-- Counter %d\n", sipcounters.dialog_objects);
}

/*! \brief Destroy SIP call structure */
void sip_destroy(struct sip_dialog *dialog)
{
	if (option_debug > 2)
		ast_log(LOG_DEBUG, "Destroying SIP dialog %s\n", dialog->callid);
	__sip_destroy(dialog, TRUE, TRUE);
}


/*! \brief Kill a SIP dialog (called by scheduler) 
 */
static int __sip_autodestruct(void *data)
{
	struct sip_dialog *dialog = data;

	/* If this is a subscription, tell the phone that we got a timeout */
	if (dialog->subscribed) {
		transmit_state_notify(dialog, AST_EXTENSION_DEACTIVATED, 1, TRUE);	/* Send last notification */
		dialog->subscribed = NONE;
		append_history(dialog, "Subscribestatus", "timeout");
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "Re-scheduled destruction of SIP subsription %s\n", dialog->callid ? dialog->callid : "<unknown>");
		return 10000;	/* Reschedule this destruction so that we know that it's gone */
	}

	if (dialog->subscribed == MWI_NOTIFICATION && dialog->relatedpeer)
		ASTOBJ_UNREF(dialog->relatedpeer,sip_destroy_device);

	/* Reset schedule ID */
	dialog->autokillid = -1;

	append_history(dialog, "AutoDestroy", "%s", dialog->callid);
	if (dialog->owner) {
		ast_log(LOG_WARNING, "Autodestruct on dialog '%s' with owner in place (Method: %s)\n", dialog->callid, sip_method2txt(dialog->method));
		ast_queue_hangup(dialog->owner);
	} else if (dialog->refer) {
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "Finally hanging up channel after transfer: %s\n", dialog->callid);
		transmit_request_with_auth(dialog, SIP_BYE, 0, XMIT_RELIABLE, 1);
		append_history(dialog, "ReferBYE", "Sending BYE on transferer call leg %s", dialog->callid);
		sip_scheddestroy(dialog, DEFAULT_TRANS_TIMEOUT);
	} else  {
		append_history(dialog, "AutoDestroy", "%s", dialog->callid);
		if (option_debug)
			ast_log(LOG_DEBUG, "Auto destroying SIP dialog '%s'\n", dialog->callid);
		sip_destroy(dialog);
	}
	return 0;
}

/*! \brief Schedule destruction of SIP dialog */
GNURK void sip_scheddestroy(struct sip_dialog *p, int ms)
{
	if (ms < 0) {
		if (p->timer_t1 == 0)
			p->timer_t1 = 500;	/* Set timer T1 if not set (RFC 3261) */
		ms = p->timer_t1 * 64;
	}
	if (sip_debug_test_pvt(p))
		ast_verbose("Scheduling destruction of SIP dialog '%s' in %d ms (Method: %s)\n", p->callid, ms, sip_method2txt(p->method));
	if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY))
		append_history(p, "SchedDestroy", "%d ms", ms);

	if (p->autokillid > -1)
		ast_sched_del(sched, p->autokillid);
	p->autokillid = ast_sched_add(sched, ms, __sip_autodestruct, p);
}

/*! \brief Cancel destruction of SIP dialog */
GNURK void sip_cancel_destroy(struct sip_dialog *p)
{
	if (p->autokillid > -1) {
		ast_sched_del(sched, p->autokillid);
		append_history(p, "CancelDestroy", "");
		p->autokillid = -1;
	}
}

/*! \brief Convert SIP hangup causes to Asterisk hangup causes */
/* \page SIP_isdn2sip Conversion from ISDN to SIP codes
	- see function \ref hangup_sip2cause()
*/
int hangup_sip2cause(int cause)
{
	/* Possible values taken from causes.h */

	switch(cause) {
		case 401:	/* Unauthorized */
			return AST_CAUSE_CALL_REJECTED;
		case 403:	/* Not found */
			return AST_CAUSE_CALL_REJECTED;
		case 404:	/* Not found */
			return AST_CAUSE_UNALLOCATED;
		case 405:	/* Method not allowed */
			return AST_CAUSE_INTERWORKING;
		case 407:	/* Proxy authentication required */
			return AST_CAUSE_CALL_REJECTED;
		case 408:	/* No reaction */
			return AST_CAUSE_NO_USER_RESPONSE;
		case 409:	/* Conflict */
			return AST_CAUSE_NORMAL_TEMPORARY_FAILURE;
		case 410:	/* Gone */
			return AST_CAUSE_UNALLOCATED;
		case 411:	/* Length required */
			return AST_CAUSE_INTERWORKING;
		case 413:	/* Request entity too large */
			return AST_CAUSE_INTERWORKING;
		case 414:	/* Request URI too large */
			return AST_CAUSE_INTERWORKING;
		case 415:	/* Unsupported media type */
			return AST_CAUSE_INTERWORKING;
		case 420:	/* Bad extension */
			return AST_CAUSE_NO_ROUTE_DESTINATION;
		case 480:	/* No answer */
			return AST_CAUSE_NO_ANSWER;
		case 481:	/* No answer */
			return AST_CAUSE_INTERWORKING;
		case 482:	/* Loop detected */
			return AST_CAUSE_INTERWORKING;
		case 483:	/* Too many hops */
			return AST_CAUSE_NO_ANSWER;
		case 484:	/* Address incomplete */
			return AST_CAUSE_INVALID_NUMBER_FORMAT;
		case 485:	/* Ambigous */
			return AST_CAUSE_UNALLOCATED;
		case 486:	/* Busy everywhere */
			return AST_CAUSE_BUSY;
		case 487:	/* Request terminated */
			return AST_CAUSE_INTERWORKING;
		case 488:	/* No codecs approved */
			return AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
		case 491:	/* Request pending */
			return AST_CAUSE_INTERWORKING;
		case 493:	/* Undecipherable */
			return AST_CAUSE_INTERWORKING;
		case 500:	/* Server internal failure */
			return AST_CAUSE_FAILURE;
		case 501:	/* Call rejected */
			return AST_CAUSE_FACILITY_REJECTED;
		case 502:	
			return AST_CAUSE_DESTINATION_OUT_OF_ORDER;
		case 503:	/* Service unavailable */
			return AST_CAUSE_CONGESTION;
		case 504:	/* Gateway timeout */
			return AST_CAUSE_RECOVERY_ON_TIMER_EXPIRE;
		case 505:	/* SIP version not supported */
			return AST_CAUSE_INTERWORKING;
		case 600:	/* Busy everywhere */
			return AST_CAUSE_USER_BUSY;
		case 603:	/* Decline */
			return AST_CAUSE_CALL_REJECTED;
		case 604:	/* Does not exist anywhere */
			return AST_CAUSE_UNALLOCATED;
		case 606:	/* Not acceptable */
			return AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
		default:
			return AST_CAUSE_NORMAL;
	}
	/* Never reached */
	return 0;
}

/*! \brief Convert Asterisk hangup causes to SIP codes 
\page SIP_isdn2sip Conversion from ISDN to SIP codes
\verbatim
 Possible values from causes.h
        AST_CAUSE_NOTDEFINED    AST_CAUSE_NORMAL        AST_CAUSE_BUSY
        AST_CAUSE_FAILURE       AST_CAUSE_CONGESTION    AST_CAUSE_UNALLOCATED

	In addition to these, a lot of PRI codes is defined in causes.h 
	...should we take care of them too ?
	
	Quote RFC 3398

   ISUP Cause value                        SIP response
   ----------------                        ------------
   1  unallocated number                   404 Not Found
   2  no route to network                  404 Not found
   3  no route to destination              404 Not found
   16 normal call clearing                 --- (*)
   17 user busy                            486 Busy here
   18 no user responding                   408 Request Timeout
   19 no answer from the user              480 Temporarily unavailable
   20 subscriber absent                    480 Temporarily unavailable
   21 call rejected                        403 Forbidden (+)
   22 number changed (w/o diagnostic)      410 Gone
   22 number changed (w/ diagnostic)       301 Moved Permanently
   23 redirection to new destination       410 Gone
   26 non-selected user clearing           404 Not Found (=)
   27 destination out of order             502 Bad Gateway
   28 address incomplete                   484 Address incomplete
   29 facility rejected                    501 Not implemented
   31 normal unspecified                   480 Temporarily unavailable
\endverbatim
Also see \ref SIP_sip2isdn
*/
const char *hangup_cause2sip(int cause)
{
	switch (cause) {
		case AST_CAUSE_UNALLOCATED:		/* 1 */
		case AST_CAUSE_NO_ROUTE_DESTINATION:	/* 3 IAX2: Can't find extension in context */
		case AST_CAUSE_NO_ROUTE_TRANSIT_NET:	/* 2 */
			return "404 Not Found";
		case AST_CAUSE_CONGESTION:		/* 34 */
		case AST_CAUSE_SWITCH_CONGESTION:	/* 42 */
			return "503 Service Unavailable";
		case AST_CAUSE_NO_USER_RESPONSE:	/* 18 */
			return "408 Request Timeout";
		case AST_CAUSE_NO_ANSWER:		/* 19 */
			return "480 Temporarily unavailable";
		case AST_CAUSE_CALL_REJECTED:		/* 21 */
			return "403 Forbidden";
		case AST_CAUSE_NUMBER_CHANGED:		/* 22 */
			return "410 Gone";
		case AST_CAUSE_NORMAL_UNSPECIFIED:	/* 31 */
			return "480 Temporarily unavailable";
		case AST_CAUSE_INVALID_NUMBER_FORMAT:
			return "484 Address incomplete";
		case AST_CAUSE_USER_BUSY:
			return "486 Busy here";
		case AST_CAUSE_FAILURE:
			return "500 Server internal failure";
		case AST_CAUSE_FACILITY_REJECTED:	/* 29 */
			return "501 Not Implemented";
		case AST_CAUSE_CHAN_NOT_IMPLEMENTED:
			return "503 Service Unavailable";
		/* Used in chan_iax2 */
		case AST_CAUSE_DESTINATION_OUT_OF_ORDER:
			return "502 Bad Gateway";
		case AST_CAUSE_BEARERCAPABILITY_NOTAVAIL:	/* Can't find codec to connect to host */
			return "488 Not Acceptable Here";
			
		case AST_CAUSE_NOTDEFINED:
		default:
			if (option_debug)
				ast_log(LOG_DEBUG, "AST hangup cause %d (no match found in SIP)\n", cause);
			return NULL;
	}

	/* Never reached */
	return 0;
}

/*! \brief Make our SIP dialog tag */
GNURK void make_our_tag(char *tagbuf, size_t len)
{
	if (sipdebug)
		snprintf(tagbuf, len, "asterisk%08lx", ast_random());
	else
		snprintf(tagbuf, len, "%08lx", ast_random());
}

/*! \brief Allocate SIP dialog structure and set defaults */
struct sip_dialog *sip_alloc(ast_string_field callid, struct sockaddr_in *sin,
				 int useglobal_nat, const int intended_method)
{
	struct sip_dialog *p;

	if (!(p = ast_calloc(1, sizeof(*p))))
		return NULL;

	if (ast_string_field_init(p, 512)) {
		free(p);
		return NULL;
	}
	sipcounters.dialog_objects++;
	if (option_debug > 3)
		ast_log(LOG_DEBUG, "--DIALOGS-- Counter %d\n", sipcounters.dialog_objects);

	ast_mutex_init(&p->lock);

	p->method = intended_method;
	p->initid = -1;
	p->autokillid = -1;
	p->subscribed = NONE;
	p->stateid = -1;
	p->prefs = global.default_prefs;		/* Set default codecs for this call */

	if (intended_method != SIP_OPTIONS)	/* Peerpoke has it's own system */
		p->timer_t1 = SIP_TIMER_T1_DEFAULT;	/* 500 ms Default SIP retransmission timer T1 (RFC 3261) */

	if (sin) {
		p->sa = *sin;
		if (sip_ouraddrfor(&p->sa.sin_addr, &p->ourip))
			p->ourip = sipnet.__ourip;
	} else
		p->ourip = sipnet.__ourip;

	/* Copy global flags to this PVT at setup. */
	ast_copy_flags(&p->flags[0], &global.flags[0], SIP_FLAGS_TO_COPY);
	ast_copy_flags(&p->flags[1], &global.flags[1], SIP_PAGE2_FLAGS_TO_COPY);

	ast_set2_flag(&p->flags[0], !global.recordhistory, SIP_NO_HISTORY);

	make_our_tag(p->tag, sizeof(p->tag));
	p->ocseq = INITIAL_CSEQ;

	if (sip_method_needrtp(intended_method)) {
		p->rtp = ast_rtp_new_with_bindaddr(sched, io, 1, 0, sipnet.bindaddr.sin_addr);
		/* If the global videosupport flag is on, we always create a RTP interface for video */
		if (ast_test_flag(&p->flags[1], SIP_PAGE2_VIDEOSUPPORT))
			p->vrtp = ast_rtp_new_with_bindaddr(sched, io, 1, 0, sipnet.bindaddr.sin_addr);
		if (ast_test_flag(&p->flags[1], SIP_PAGE2_T38SUPPORT))
			p->udptl = ast_udptl_new_with_bindaddr(sched, io, 0, sipnet.bindaddr.sin_addr);
		if (!p->rtp || (ast_test_flag(&p->flags[1], SIP_PAGE2_VIDEOSUPPORT) && !p->vrtp)) {
			ast_log(LOG_WARNING, "Unable to create RTP audio %s session: %s\n",
				ast_test_flag(&p->flags[1], SIP_PAGE2_VIDEOSUPPORT) ? "and video" : "", strerror(errno));
			ast_mutex_destroy(&p->lock);
			if (p->chanvars) {
				ast_variables_destroy(p->chanvars);
				p->chanvars = NULL;
			}
			free(p);
			return NULL;
		}
		ast_rtp_setdtmf(p->rtp, ast_test_flag(&p->flags[0], SIP_DTMF) != SIP_DTMF_INFO);
		ast_rtp_setdtmfcompensate(p->rtp, ast_test_flag(&p->flags[1], SIP_PAGE2_RFC2833_COMPENSATE));
		ast_rtp_settos(p->rtp, global.tos_audio);
		ast_rtp_set_rtptimeout(p->rtp, global.rtptimeout);
		ast_rtp_set_rtpholdtimeout(p->rtp, global.rtpholdtimeout);
		ast_rtp_set_rtpkeepalive(p->rtp, global.rtpkeepalive);
		if (p->vrtp) {
			ast_rtp_settos(p->vrtp, global.tos_video);
			ast_rtp_setdtmf(p->vrtp, 0);
			ast_rtp_setdtmfcompensate(p->vrtp, 0);
			ast_rtp_set_rtptimeout(p->vrtp, global.rtptimeout);
			ast_rtp_set_rtpholdtimeout(p->vrtp, global.rtpholdtimeout);
			ast_rtp_set_rtpkeepalive(p->vrtp, global.rtpkeepalive);
		}
		if (p->udptl)
			ast_udptl_settos(p->udptl, global.tos_audio);
		p->maxcallbitrate = global.default_maxcallbitrate;
	}

	if (useglobal_nat && sin) {
		/* Setup NAT structure according to global settings if we have an address */
		ast_copy_flags(&p->flags[0], &global.flags[0], SIP_NAT);
		p->recv = *sin;
		do_setnat(p, ast_test_flag(&p->flags[0], SIP_NAT) & SIP_NAT_ROUTE);
	}

	if (p->method != SIP_REGISTER)
		ast_string_field_set(p, fromdomain, global.default_fromdomain);

	build_via(p, TRUE);
	if (!callid)					/* Make sure we have a unique call ID */
		build_callid_pvt(p);
	else
		ast_string_field_set(p, callid, callid);

	dialogstatechange(p, DIALOG_STATE_TRYING);	/* Set dialog state */

							/* Assign default music on hold class */
	ast_string_field_set(p, mohinterpret, global.default_mohinterpret);
	ast_string_field_set(p, mohsuggest, global.default_mohsuggest);
	
	p->capability = global.capability;		/* Set default codec settings */

	if ((ast_test_flag(&p->flags[0], SIP_DTMF) == SIP_DTMF_RFC2833) ||
	    (ast_test_flag(&p->flags[0], SIP_DTMF) == SIP_DTMF_AUTO))
		p->noncodeccapability |= AST_RTP_DTMF;

	if (p->udptl) {					/* T.38 fax properties */
		p->t38.capability = global.t38_capability;
		if (ast_udptl_get_error_correction_scheme(p->udptl) == UDPTL_ERROR_CORRECTION_REDUNDANCY)
			p->t38.capability |= T38FAX_UDP_EC_REDUNDANCY;
		else if (ast_udptl_get_error_correction_scheme(p->udptl) == UDPTL_ERROR_CORRECTION_FEC)
			p->t38.capability |= T38FAX_UDP_EC_FEC;
		else if (ast_udptl_get_error_correction_scheme(p->udptl) == UDPTL_ERROR_CORRECTION_NONE)
			p->t38.capability |= T38FAX_UDP_EC_NONE;
		p->t38.capability |= T38FAX_RATE_MANAGEMENT_TRANSFERED_TCF;
		p->t38.jointcapability = p->t38.capability;
	}
	ast_string_field_set(p, context, global.default_context);
	p->allowtransfer = global.allowtransfer;	/* Default transfer mode */


	/* Add to active dialog list */
	dialoglist_lock();
	p->next = dialoglist;
	dialoglist = p;
	dialoglist_unlock();
	if (option_debug)
		ast_log(LOG_DEBUG, "Allocating new SIP dialog for %s - %s (%s)\n", callid ? callid : "(No Call-ID)", sip_method2txt(intended_method), p->rtp ? "With RTP" : "No RTP");
	return p;
}

/*! \brief Initialize temporary PVT */
static int temp_pvt_init(void *data)
{
	struct sip_dialog *p = data;

	ast_set_flag(&p->flags[0], SIP_NO_HISTORY);
	return ast_string_field_init(p, 512);
}

/*! \brief Cleanup temporary PVT */
static void temp_pvt_cleanup(void *data)
{
	struct sip_dialog *p = data;

	ast_string_field_free_pools(p);

	free(data);
}

/*! \brief Transmit response, no retransmits, using a temporary pvt structure */
static int transmit_response_using_temp(ast_string_field callid, struct sockaddr_in *sin, int useglobal_nat, const int intended_method, const struct sip_request *req, const char *msg)
{
	struct sip_dialog *p = NULL;

	if (!(p = ast_threadstorage_get(&ts_temp_pvt, sizeof(*p)))) {
		ast_log(LOG_NOTICE, "Failed to get temporary pvt\n");
		return -1;
	}

	/* if the structure was just allocated, initialize it */
	if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY)) {
		ast_set_flag(&p->flags[0], SIP_NO_HISTORY);
		if (ast_string_field_init(p, 512))
			return -1;
	}

	/* Initialize the bare minimum */
	p->method = intended_method;

	if (sin) {
		p->sa = *sin;
		if (sip_ouraddrfor(&p->sa.sin_addr, &p->ourip))
			p->ourip = sipnet.__ourip;
	} else
		p->ourip = sipnet.__ourip;

	make_our_tag(p->tag, sizeof(p->tag));
	p->ocseq = INITIAL_CSEQ;

	if (useglobal_nat && sin) {
		ast_copy_flags(&p->flags[0], &global.flags[0], SIP_NAT);
		p->recv = *sin;
		do_setnat(p, ast_test_flag(&p->flags[0], SIP_NAT) & SIP_NAT_ROUTE);
	}

	ast_string_field_set(p, fromdomain, global.default_fromdomain);
	build_via(p, TRUE);
	ast_string_field_set(p, callid, callid);

	/* Use this temporary pvt structure to send the message */
	__transmit_response(p, msg, req, XMIT_UNRELIABLE);

	/* Free the string fields, but not the pool space */
	ast_string_field_free_all(p);

	return 0;
}

/*! \brief Connect incoming SIP message to current dialog or create new dialog structure
	\note Called by handle_request, sipsock_read 

	\page sip3_dialog_match chan_sip3:: Dialog matching and scenarios
	\title Dialog matching

	SIP can be forked, so we need to separate dialogs from each other in a 
	good way.

	\title 1. Calling out, getting the same call back
	An OUTBOUND INVITE can be sent to a SiP proxy and come back twice. We
	separate the two different calls by branch tag in the topmost via header.
		Asterisk1 ----> INVITE ---> PROXY
				    PROXY --> INVITE branch 1 ---> Asterisk1
				    PROXY --> INVITE branch 2 ---> Asterisk1
				    PROXY --> INVITE branch 3 ---> UA3 (not Asterisk)
	We have to treat the two calls as separate calls. But how do we handle
	this situation, where we actually can take the media internally somehow?
	If the proxy does not add Record-Route, we can just tear down the SIP
	signalling and shortcut the call internally. If the proxy Record-Route the
	call, we need to keep the SIP signalling or just fake a tear down with
	a fake BYE and handle it internally, which wouuld be bad if the proxy
	logs are important.
	
	\title 2. Getting the same INCOMING call multiple times
		UAC ----> INVITE ---> PROXY
				    PROXY --> INVITE branch 1 ---> Asterisk1
				    PROXY --> INVITE branch 2 ---> Asterisk1
				    PROXY --> INVITE branch 3 ---> UA3 (not Asterisk)

	\title 3. Sending INVITE, getting many replies
				
	An OUTBOUND INVITE may be forked to two or more separate UA's. If there's
	a stateless SIP proxy between us and the UA's, we get multiple replies.
	In a worst case scenario, we get multiple 200 OK at the same time.
	Since we don't know about the fork, we won't send CANCEL.
		INVITE -->
			<--- 100 trying from UA1
			<--- 100 trying from UA2
			<--- 200 OK from UA1
			<--- 200 OK from UA2
	in this case

	If it's a secondary 200 OK to a current
	INVITE, we're in interesting waters.
	In this case, we have to copy the current dialog, create
	a new and send ACK, then immediately BYE since there's
	no call to bridge it with.
	of course, there's a usability issue here. how do you
	tell the person that answers the forked call that someone
	else answered already? Too late to cancel the call...

	Scenarios:
	INVITE
		100 from first device
		100 from second device
		183 from first device
		183 from second device
			- provisional responses, don't create new dialog, 
			  just ignore the secondary answers and be happy
	--- 2. Double 200 OKs
		200 OK from first device
		200 OK from second
			- Creates new branch
	--- 3. Error and 200 OK from different devices
		200 OK from first device response
		603 Declined from secondary device response
			- Sorry, just ACK the 603 and close

		603 declined from first response
		200 OK from second response
			- In this case, the call failed. We can't wait
				for the possibility that we get a 200 OK
				from a device we don't know about.	
			- But we might be clever, if we get two 100 trying
			  then we know that something's going on.
			- Without trickery, the second 200 OK will have to
			  get an ACK, then a BYE

	\title 4. How do we handle this in Asterisk chan_sip3 ???

	
*/
struct sip_dialog *match_or_create_dialog(struct sip_request *req, struct sockaddr_in *sin, const int intended_method)
{
	struct sip_dialog *cur = NULL;
	char *tag = "";	/* note, tag is never NULL */
	char totag[128];
	char fromtag[128];
	char branch[128];

	if (ast_strlen_zero(req->callid))
		req->callid = get_header(req, "Call-ID");
	if (ast_strlen_zero(req->from))
		req->from = get_header(req, "From");
	if (ast_strlen_zero(req->to))
		req->to = get_header(req, "To");
	if (ast_strlen_zero(req->cseqheader))
		req->cseqheader = get_header(req, "Cseq");

	/* Call-ID, to, from and Cseq are required by RFC 3261. (Max-forwards and via too - ignored now) */
	/* get_header always returns non-NULL so we must use ast_strlen_zero() */
	if (ast_strlen_zero(req->callid) || ast_strlen_zero(req->to) ||
			ast_strlen_zero(req->from) || ast_strlen_zero(req->cseqheader))
		return NULL;	/* Invalid packet */

	/* In principle Call-ID's uniquely identify a call, but with a forking SIP proxy
	   we need more to identify a branch - so we have to check branch, from
	   and to tags to identify a call leg.
	   */
	if (gettag(req->to, totag, sizeof(totag)))
		ast_set_flag(req, SIP_PKT_WITH_TOTAG);	/* Used in handle_request/response */
	gettag(req->from, fromtag, sizeof(fromtag));

	tag = (req->method == SIP_RESPONSE) ? totag : fromtag;

	/* All messages must always have From: tag */
	if (ast_strlen_zero(fromtag)) {
		if (option_debug > 4 ) 
			ast_log(LOG_DEBUG, "%s request has no from tag, dropping callid: %s from: %s\n", sip_methods[req->method].text, req->callid, req->from );
		return NULL;
	}
	/* reject requests that must always have a To: tag */
	if (ast_strlen_zero(totag) && (req->method == SIP_ACK || req->method == SIP_BYE || req->method == SIP_INFO )) {
		if (option_debug > 4) 
			ast_log(LOG_DEBUG, "%s must have a to tag. dropping callid: %s from: %s\n", sip_methods[req->method].text, req->callid, req->from );
		return NULL;
 	}
 
 	dialoglist_lock();

	if (option_debug > 4 )
		ast_log(LOG_DEBUG, "= Looking for  Call ID: %s (Checking %s) --From tag %s --To-tag %s  \n", req->callid, req->method==SIP_RESPONSE ? "To" : "From", fromtag, totag);

	find_via_branch(req, branch, sizeof(branch));
	for (cur = dialoglist; cur; cur = cur->next) {
		/* we do not want packets with bad syntax to be connected to a PVT */
		int found = FALSE;
		if (req->method == SIP_REGISTER)
			found = (!strcmp(cur->callid, req->callid));
		else 
			found = (!strcmp(cur->callid, req->callid) && 
			(!tag || ast_strlen_zero(cur->theirtag) || !strcmp(cur->theirtag, tag))) ;

		if (option_debug > 4)
			ast_log(LOG_DEBUG, "= %s Their Call ID: %s Their Tag %s Our tag: %s\n", found ? "Found" : "No match", cur->callid, cur->theirtag, cur->tag);

		/* If we get a new request within an existing to-tag - check the to tag as well */
		if (found  && req->method != SIP_RESPONSE) {	/* SIP Request */
			if (cur->tag[0] == '\0' && totag[0]) {
				/* We have no to tag, but they have. Wrong dialog */
				found = FALSE;
			} else if (totag[0]) {			/* Both have tags, compare them */
				if (strcmp(totag, cur->tag)) {
					found = FALSE;		/* This is not our dialog */
				}
			}
			if (!found && option_debug > 4)
				ast_log(LOG_DEBUG, "= Being pedantic: This is not our match on request: Call ID: %s Ourtag <null> Totag %s Method %s\n", cur->callid, totag, sip_method2txt(req->method));
		}
		
		/* We need to check the branch too, to make sure this is the proper reply */
		/* If it is an INVITE from us coming back with a new branch, we need to
			do some masquerading trickery with the audio.
			We might also get several INVITEs with different branches
			and have to treat them as several calls 
		 */
		if (found) {
			if (!strcmp(cur->ourbranch, branch)) {
				/* This is our own request coming back to us strangely enough */
				/* Propably through DNS, but not a proxy */
				/* Bad dialplan design... ; -) */
				/* Any way we can handle this??? */
			}
			/* If we have a remote branch already, and get a new branch with the
				same call ID, then something is happening.
				For responses - we might have a forking proxy and get responses
				from several UAs on one request.
				For requests, we might be getting a statelessly forked call to us. 
			*/
			if (!ast_strlen_zero(cur->remotebranch) && strcmp(cur->remotebranch, branch)) {
				/* XXX What do we do here ? */
				
			}
		}


		if (found) {
			/* Found the dialog */
			dialog_lock(cur, TRUE);	/* Lock the dialog */
			dialoglist_unlock();	/* Unlock the list */
			return cur;
		}
	}
	dialoglist_unlock();
	if (sip_methods[intended_method].creates_dialog != CAN_CREATE_DIALOG) {
		if (intended_method != SIP_RESPONSE && intended_method != SIP_ACK)
			transmit_response_using_temp(req->callid, sin, TRUE, intended_method, req, "481 Call leg/transaction does not exist");
		else
			logdebug(2, "Got response or ACK to non-existing transaction. No action taken. Call-ID: %s\n", req->callid);
		return cur;
	}
	switch (intended_method) {
	case SIP_REFER:
		/* We do not support out-of-dialog REFERs yet */
		transmit_response_using_temp(req->callid, sin, TRUE, intended_method, req, "603 Declined (no dialog)");
		break;
	case SIP_NOTIFY:
		/* We do not support out-of-dialog NOTIFY either,
		  like voicemail notification, so cancel that early */
		transmit_response_using_temp(req->callid, sin, TRUE, intended_method, req, "489 Bad event");
		break;
	default:
		/* ready to create a new dialog. */
		if ((cur = sip_alloc(req->callid, sin, TRUE, intended_method))) {
			/* This method creates dialog */
			/* Ok, 	we've created a dialog, let's go and process it */
			dialog_lock(cur, TRUE);
		}
		break;
	}

	return cur;
}
