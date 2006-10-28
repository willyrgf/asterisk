/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
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
 * \brief Various SIP transfer/refer functions
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
#include "sip3.h"
#include "sip3funcs.h"

/*! \brief Table to convert from REFER status variable to string */
static const struct c_referstatusstring {
	enum referstatus status;
	char *text;
} referstatusstrings[] = {
	{ REFER_IDLE,		"<none>" },
	{ REFER_SENT,		"Request sent" },
	{ REFER_RECEIVED,	"Request received" },
	{ REFER_ACCEPTED,	"Accepted" },
	{ REFER_RINGING,	"Target ringing" },
	{ REFER_200OK,		"Done" },
	{ REFER_FAILED,		"Failed" },
	{ REFER_NOAUTH,		"Failed - auth failure" }
} ;


/*! \brief Convert transfer status to string */
const char *referstatus2str(enum referstatus rstatus)
{
	int i = (sizeof(referstatusstrings) / sizeof(referstatusstrings[0]));
	int x;

	for (x = 0; x < i; x++) {
		if (referstatusstrings[x].status ==  rstatus)
			return (char *) referstatusstrings[x].text;
	}
	return "";
}

/*! \brief Allocate SIP refer structure */
int sip_refer_allocate(struct sip_dialog *p)
{
	p->refer = ast_calloc(1, sizeof(struct sip_refer)); 
	return p->refer ? 1 : 0;
}

/*! \brief Park SIP call support function 
	Starts in a new thread, then parks the call
	XXX Should we add a wait period after streaming audio and before hangup?? Sometimes the
		audio can't be heard before hangup
*/
static void *sip_park_thread(void *stuff)
{
	struct ast_channel *transferee, *transferer;	/* Chan1: The transferee, Chan2: The transferer */
	struct sip_dual *d;
	struct sip_request req;
	int ext;
	int res;

	d = stuff;
	transferee = d->chan1;
	transferer = d->chan2;
	copy_request(&req, &d->req);
	free(d);

	if (!transferee || !transferer) {
		ast_log(LOG_ERROR, "Missing channels for parking! Transferer %s Transferee %s\n", transferer ? "<available>" : "<missing>", transferee ? "<available>" : "<missing>" );
		return NULL;
	}
	if (option_debug > 3) 
		ast_log(LOG_DEBUG, "SIP Park: Transferer channel %s, Transferee %s\n", transferer->name, transferee->name);

	ast_channel_lock(transferee);
	if (ast_do_masquerade(transferee)) {
		ast_log(LOG_WARNING, "Masquerade failed.\n");
		transmit_response(transferer->tech_pvt, "503 Internal error", &req);
		ast_channel_unlock(transferee);
		return NULL;
	} 
	ast_channel_unlock(transferee);

	res = ast_park_call(transferee, transferer, 0, &ext);
	

#ifdef WHEN_WE_KNOW_THAT_THE_CLIENT_SUPPORTS_MESSAGE
	if (!res) {
		transmit_message_with_text(transferer->tech_pvt, "Unable to park call.\n");
	} else {
		/* Then tell the transferer what happened */
		sprintf(buf, "Call parked on extension '%d'", ext);
		transmit_message_with_text(transferer->tech_pvt, buf);
	}
#endif

	/* Any way back to the current call??? */
	/* Transmit response to the REFER request */
	transmit_response(transferer->tech_pvt, "202 Accepted", &req);
	if (!res)	{
		/* Transfer succeeded */
		append_history(transferer->tech_pvt, "SIPpark","Parked call on %d", ext);
		transmit_notify_with_sipfrag(transferer->tech_pvt, d->seqno, "200 OK", TRUE);
		transferer->hangupcause = AST_CAUSE_NORMAL_CLEARING;
		ast_hangup(transferer); /* This will cause a BYE */
		if (option_debug)
			ast_log(LOG_DEBUG, "SIP Call parked on extension '%d'\n", ext);
	} else {
		transmit_notify_with_sipfrag(transferer->tech_pvt, d->seqno, "503 Service Unavailable", TRUE);
		append_history(transferer->tech_pvt, "SIPpark","Parking failed\n");
		if (option_debug)
			ast_log(LOG_DEBUG, "SIP Call parked failed \n");
		/* Do not hangup call */
	}
	return NULL;
}

/*! \brief Call transfer support (the REFER method) 
 * 	Extracts Refer headers into pvt dialog structure */
static int get_refer_info(struct sip_dialog *transferer, struct sip_request *outgoing_req)
{

	const char *p_referred_by = NULL;
	char *h_refer_to = NULL; 
	char *h_referred_by = NULL;
	char *refer_to;
	const char *p_refer_to;
	char *referred_by_uri = NULL;
	char *ptr;
	struct sip_request *req = NULL;
	const char *transfer_context = NULL;
	struct sip_refer *referdata;


	req = outgoing_req;
	referdata = transferer->refer;

	if (!req)
		req = &transferer->initreq;

	p_refer_to = get_header(req, "Refer-To");
	if (ast_strlen_zero(p_refer_to)) {
		ast_log(LOG_WARNING, "Refer-To Header missing. Skipping transfer.\n");
		return -2;	/* Syntax error */
	}
	h_refer_to = ast_strdupa(p_refer_to);
	refer_to = get_in_brackets(h_refer_to);
	ast_uri_decode(refer_to);

	if (strncasecmp(refer_to, "sip:", 4)) {
		ast_log(LOG_WARNING, "Can't transfer to non-sip: URI.  (Refer-to: %s)?\n", refer_to);
		return -3;
	}
	refer_to += 4;			/* Skip sip: */

	/* Get referred by header if it exists */
	p_referred_by = get_header(req, "Referred-By");
	if (!ast_strlen_zero(p_referred_by)) {
		char *lessthan;
		h_referred_by = ast_strdupa(p_referred_by);
		ast_uri_decode(h_referred_by);

		/* Store referrer's caller ID name */
		ast_copy_string(referdata->referred_by_name, h_referred_by, sizeof(referdata->referred_by_name));
		if ((lessthan = strchr(referdata->referred_by_name, '<'))) {
			*(lessthan - 1) = '\0';	/* Space */
		}

		referred_by_uri = get_in_brackets(h_referred_by);
		if(strncasecmp(referred_by_uri, "sip:", 4)) {
			ast_log(LOG_WARNING, "Huh?  Not a sip: header (Referred-by: %s). Skipping.\n", referred_by_uri);
			referred_by_uri = (char *) NULL;
		} else {
			referred_by_uri += 4;		/* Skip sip: */
		}
	}

	/* Check for arguments in the refer_to header */
	if ((ptr = strchr(refer_to, '?'))) { /* Search for arguments */
		*ptr++ = '\0';
		if (!strncasecmp(ptr, "REPLACES=", 9)) {
			char *to = NULL, *from = NULL;

			/* This is an attended transfer */
			referdata->attendedtransfer = 1;
			strncpy(referdata->replaces_callid, ptr+9, sizeof(referdata->replaces_callid));
			ast_uri_decode(referdata->replaces_callid);
			if ((ptr = strchr(referdata->replaces_callid, ';'))) 	/* Find options */ {
				*ptr++ = '\0';
			}

			if (ptr) {
				/* Find the different tags before we destroy the string */
				to = strcasestr(ptr, "to-tag=");
				from = strcasestr(ptr, "from-tag=");
			}

			/* Grab the to header */
			if (to) {
				ptr = to + 7;
				if ((to = strchr(ptr, '&')))
					*to = '\0';
				if ((to = strchr(ptr, ';')))
					*to = '\0';
				ast_copy_string(referdata->replaces_callid_totag, ptr, sizeof(referdata->replaces_callid_totag));
			}

			if (from) {
				ptr = from + 9;
				if ((to = strchr(ptr, '&')))
					*to = '\0';
				if ((to = strchr(ptr, ';')))
					*to = '\0';
				ast_copy_string(referdata->replaces_callid_fromtag, ptr, sizeof(referdata->replaces_callid_fromtag));
			}

			if (option_debug > 1)
				ast_log(LOG_DEBUG,"Attended transfer: Will use Replace-Call-ID : %s F-tag: %s T-tag: %s\n", referdata->replaces_callid, referdata->replaces_callid_fromtag ? referdata->replaces_callid_fromtag : "<none>", referdata->replaces_callid_totag ? referdata->replaces_callid_totag : "<none>" );
		}
	}
	
	if ((ptr = strchr(refer_to, '@'))) {	/* Separate domain */
		char *urioption;

		*ptr++ = '\0';
		if ((urioption = strchr(ptr, ';')))
			*urioption++ = '\0';
		/* Save the domain for the dial plan */
		strncpy(referdata->refer_to_domain, ptr, sizeof(referdata->refer_to_domain));
		if (urioption)
			strncpy(referdata->refer_to_urioption, urioption, sizeof(referdata->refer_to_urioption));
	}

	if ((ptr = strchr(refer_to, ';'))) 	/* Remove options */
		*ptr = '\0';
	ast_copy_string(referdata->refer_to, refer_to, sizeof(referdata->refer_to));
	
	if (referred_by_uri) {
		if ((ptr = strchr(referred_by_uri, ';'))) 	/* Remove options */
			*ptr = '\0';
		ast_copy_string(referdata->referred_by, referred_by_uri, sizeof(referdata->referred_by));
	} else {
		referdata->referred_by[0] = '\0';
	}

	/* Determine transfer context */
	if (transferer->owner)	/* Mimic behaviour in res_features.c */
		transfer_context = pbx_builtin_getvar_helper(transferer->owner, "TRANSFER_CONTEXT");

	/* By default, use the context in the channel sending the REFER */
	if (ast_strlen_zero(transfer_context)) {
		transfer_context = S_OR(transferer->owner->macrocontext,
					S_OR(transferer->context, global.default_context));
	}

	strncpy(referdata->refer_to_context, transfer_context, sizeof(referdata->refer_to_context));
	
	/* Either an existing extension or the parking extension */
	if (ast_exists_extension(NULL, transfer_context, refer_to, 1, NULL) ) {
		if (sip_debug_test_pvt(transferer)) {
			ast_verbose("SIP transfer to extension %s@%s by %s\n", refer_to, transfer_context, referred_by_uri);
		}
		/* We are ready to transfer to the extension */
		return 0;
	} 
	if (sip_debug_test_pvt(transferer))
		ast_verbose("Failed SIP Transfer to non-existing extension %s in context %s\n n", refer_to, transfer_context);

	/* Failure, we can't find this extension */
	return -1;
}


/*! \brief Park a call using the subsystem in res_features.c 
	This is executed in a separate thread
*/
static int sip_park(struct ast_channel *chan1, struct ast_channel *chan2, struct sip_request *req, int seqno)
{
	struct sip_dual *d;
	struct ast_channel *transferee, *transferer;
		/* Chan2m: The transferer, chan1m: The transferee */
	pthread_t th;

	transferee = ast_channel_alloc(0);
	transferer = ast_channel_alloc(0);
	if ((!transferer) || (!transferee)) {
		if (transferee) {
			transferee->hangupcause = AST_CAUSE_SWITCH_CONGESTION;
			ast_hangup(transferee);
		}
		if (transferer) {
			transferer->hangupcause = AST_CAUSE_SWITCH_CONGESTION;
			ast_hangup(transferer);
		}
		return -1;
	}
	ast_string_field_build(transferee, name,  "Parking/%s", chan1->name);

	/* Make formats okay */
	transferee->readformat = chan1->readformat;
	transferee->writeformat = chan1->writeformat;

	/* Prepare for taking over the channel */
	ast_channel_masquerade(transferee, chan1);

	/* Setup the extensions and such */
	ast_copy_string(transferee->context, chan1->context, sizeof(transferee->context));
	ast_copy_string(transferee->exten, chan1->exten, sizeof(transferee->exten));
	transferee->priority = chan1->priority;
		
	/* We make a clone of the peer channel too, so we can play
	   back the announcement */
	ast_string_field_build(transferer, name, "SIPPeer/%s", chan2->name);

	/* Make formats okay */
	transferer->readformat = chan2->readformat;
	transferer->writeformat = chan2->writeformat;

	/* Prepare for taking over the channel */
	ast_channel_masquerade(transferer, chan2);

	/* Setup the extensions and such */
	ast_copy_string(transferer->context, chan2->context, sizeof(transferer->context));
	ast_copy_string(transferer->exten, chan2->exten, sizeof(transferer->exten));
	transferer->priority = chan2->priority;

	ast_channel_lock(transferer);
	if (ast_do_masquerade(transferer)) {
		ast_log(LOG_WARNING, "Masquerade failed :(\n");
		ast_channel_unlock(transferer);
		transferer->hangupcause = AST_CAUSE_SWITCH_CONGESTION;
		ast_hangup(transferer);
		return -1;
	}
	ast_channel_unlock(transferer);
	if (!transferer || !transferee) {
		if (!transferer) { 
			if (option_debug)
				ast_log(LOG_DEBUG, "No transferer channel, giving up parking\n");
		}
		if (!transferee) {
			if (option_debug)
				ast_log(LOG_DEBUG, "No transferee channel, giving up parking\n");
		}
		return -1;
	}
	if ((d = ast_calloc(1, sizeof(*d)))) {
		/* Save original request for followup */
		copy_request(&d->req, req);
		d->chan1 = transferee;	/* Transferee */
		d->chan2 = transferer;	/* Transferer */
		d->seqno = seqno;
		if (ast_pthread_create_background(&th, NULL, sip_park_thread, d) < 0) {
			/* Could not start thread */
			free(d);	/* We don't need it anymore. If thread is created, d will be free'd
					   by sip_park_thread() */
			return 0;
		}
	} 
	return -1;
}

/*! \brief Attempt transfer of SIP call 
	This fix for attended transfers on a local PBX */
static int attempt_transfer(struct sip_dual *transferer, struct sip_dual *target)
{
	int res = 0;
	struct ast_channel *peera = NULL,	
		*peerb = NULL,
		*peerc = NULL,
		*peerd = NULL;


	/* We will try to connect the transferee with the target and hangup
   	all channels to the transferer */	
	if (option_debug > 3) {
		ast_log(LOG_DEBUG, "Sip transfer:--------------------\n");
		if (transferer->chan1)
			ast_log(LOG_DEBUG, "-- Transferer to PBX channel: %s State %s\n", transferer->chan1->name, ast_state2str(transferer->chan1->_state));
		else
			ast_log(LOG_DEBUG, "-- No transferer first channel - odd??? \n");
		if (target->chan1)
			ast_log(LOG_DEBUG, "-- Transferer to PBX second channel (target): %s State %s\n", target->chan1->name, ast_state2str(target->chan1->_state));
		else
			ast_log(LOG_DEBUG, "-- No target first channel ---\n");
		if (transferer->chan2)
			ast_log(LOG_DEBUG, "-- Bridged call to transferee: %s State %s\n", transferer->chan2->name, ast_state2str(transferer->chan2->_state));
		else
			ast_log(LOG_DEBUG, "-- No bridged call to transferee\n");
		if (target->chan2)
			ast_log(LOG_DEBUG, "-- Bridged call to transfer target: %s State %s\n", target->chan2 ? target->chan2->name : "<none>", target->chan2 ? ast_state2str(target->chan2->_state) : "(none)");
		else
			ast_log(LOG_DEBUG, "-- No target second channel ---\n");
		ast_log(LOG_DEBUG, "-- END Sip transfer:--------------------\n");
	}
	if (transferer->chan2) {			/* We have a bridge on the transferer's channel */
		peera = transferer->chan1;	/* Transferer - PBX -> transferee channel * the one we hangup */
		peerb = target->chan1;		/* Transferer - PBX -> target channel - This will get lost in masq */
		peerc = transferer->chan2;	/* Asterisk to Transferee */
		peerd = target->chan2;		/* Asterisk to Target */
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "SIP transfer: Four channels to handle\n");
	} else if (target->chan2) {	/* Transferer has no bridge (IVR), but transferee */
		peera = target->chan1;		/* Transferer to PBX -> target channel */
		peerb = transferer->chan1;	/* Transferer to IVR*/
		peerc = target->chan2;		/* Asterisk to Target */
		peerd = transferer->chan2;	/* Nothing */
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "SIP transfer: Three channels to handle\n");
	}

	if (peera && peerb && peerc && (peerb != peerc)) {
		ast_quiet_chan(peera);		/* Stop generators */
		ast_quiet_chan(peerb);	
		ast_quiet_chan(peerc);
		if (peerd)
			ast_quiet_chan(peerd);

		/* Fix CDRs so they're attached to the remaining channel */
		if (peera->cdr && peerb->cdr)
			peerb->cdr = ast_cdr_append(peerb->cdr, peera->cdr);
		else if (peera->cdr) 
			peerb->cdr = peera->cdr;
		peera->cdr = NULL;

		if (peerb->cdr && peerc->cdr) 
			peerb->cdr = ast_cdr_append(peerb->cdr, peerc->cdr);
		else if (peerc->cdr)
			peerb->cdr = peerc->cdr;
		peerc->cdr = NULL;
	
		if (option_debug > 3)
			ast_log(LOG_DEBUG, "SIP transfer: trying to masquerade %s into %s\n", peerc->name, peerb->name);
		if (ast_channel_masquerade(peerb, peerc)) {
			ast_log(LOG_WARNING, "Failed to masquerade %s into %s\n", peerb->name, peerc->name);
			res = -1;
		} else
			ast_log(LOG_DEBUG, "SIP transfer: Succeeded to masquerade channels.\n");
		return res;
	} else {
		ast_log(LOG_NOTICE, "SIP Transfer attempted with no appropriate bridged calls to transfer\n");
		if (transferer->chan1)
			ast_softhangup_nolock(transferer->chan1, AST_SOFTHANGUP_DEV);
		if (target->chan1)
			ast_softhangup_nolock(target->chan1, AST_SOFTHANGUP_DEV);
		return -1;
	}
	return 0;
}

/*! \brief  Find all call legs and bridge transferee with target 
 *	called from handle_request_refer */
static int local_attended_transfer(struct sip_dialog *transferer, struct sip_dual *current, struct sip_request *req, int seqno)
{
	struct sip_dual target;		/* Chan 1: Call from tranferer to Asterisk */
					/* Chan 2: Call from Asterisk to target */
	int res = 0;
	struct sip_dialog *targetcall_pvt;
	int error = 0;

	/* Check if the call ID of the replaces header does exist locally */
	if (!(targetcall_pvt = get_sip_dialog_byid_locked(transferer->refer->replaces_callid, transferer->refer->replaces_callid_totag, 
		transferer->refer->replaces_callid_fromtag))) {
		if (transferer->refer->localtransfer) {
			/* We did not find the refered call. Sorry, can't accept then */
			transmit_response(transferer, "202 Accepted", req);
			/* Let's fake a response from someone else in order
		   	to follow the standard */
			transmit_notify_with_sipfrag(transferer, seqno, "481 Call leg/transaction does not exist", TRUE);
			append_history(transferer, "Xfer", "Refer failed");
			ast_clear_flag(&transferer->flags[0], SIP_GOTREFER);	
			transferer->refer->status = REFER_FAILED;
			return -1;
		}
		/* Fall through for remote transfers that we did not find locally */
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "SIP attended transfer: Not our call - generating INVITE with replaces\n");
		return 0;
	}

	/* Ok, we can accept this transfer */
	transmit_response(transferer, "202 Accepted", req);
	append_history(transferer, "Xfer", "Refer accepted");
	if (!targetcall_pvt->owner) {	/* No active channel */
		if (option_debug > 3)
			ast_log(LOG_DEBUG, "SIP attended transfer: Error: No owner of target call\n");
		error = 1;
	}
	/* We have a channel, find the bridge */
	target.chan1 = targetcall_pvt->owner;				/* Transferer to Asterisk */

	if (!error) {
		target.chan2 = ast_bridged_channel(targetcall_pvt->owner);	/* Asterisk to target */

		if (!target.chan2 || !(target.chan2->_state == AST_STATE_UP || target.chan2->_state == AST_STATE_RINGING) ) {
			/* Wrong state of new channel */
			if (option_debug > 3) {
				if (target.chan2) 
					ast_log(LOG_DEBUG, "SIP attended transfer: Error: Wrong state of target call: %s\n", ast_state2str(target.chan2->_state));
				else if (target.chan1->_state != AST_STATE_RING)
					ast_log(LOG_DEBUG, "SIP attended transfer: Error: No target channel\n");
				else
					ast_log(LOG_DEBUG, "SIP attended transfer: Attempting transfer in ringing state\n");
			}
			if (target.chan1->_state != AST_STATE_RING)
				error = 1;
		}
	}
	if (error) {	/* Cancel transfer */
		transmit_notify_with_sipfrag(transferer, seqno, "503 Service Unavailable", TRUE);
		append_history(transferer, "Xfer", "Refer failed");
		ast_clear_flag(&transferer->flags[0], SIP_GOTREFER);	
		transferer->refer->status = REFER_FAILED;
		ast_mutex_unlock(&targetcall_pvt->lock);
		ast_channel_unlock(current->chan1);
		ast_channel_unlock(target.chan1);
		return -1;
	}

	/* Transfer */
	if (option_debug > 3 && sipdebug) {
		if (current->chan2)	/* We have two bridges */
			ast_log(LOG_DEBUG, "SIP attended transfer: trying to bridge %s and %s\n", target.chan1->name, current->chan2->name);
		else			/* One bridge, propably transfer of IVR/voicemail etc */
			ast_log(LOG_DEBUG, "SIP attended transfer: trying to make %s take over (masq) %s\n", target.chan1->name, current->chan1->name);
	}

	ast_set_flag(&transferer->flags[0], SIP_DEFER_BYE_ON_TRANSFER);	/* Delay hangup */

	/* Perform the transfer */
	res = attempt_transfer(current, &target);
	ast_mutex_unlock(&targetcall_pvt->lock);
	if (res) {
		/* Failed transfer */
		/* Could find better message, but they will get the point */
		transmit_notify_with_sipfrag(transferer, seqno, "486 Busy", TRUE);
		append_history(transferer, "Xfer", "Refer failed");
		if (targetcall_pvt->owner)
			ast_channel_unlock(targetcall_pvt->owner);
		/* Right now, we have to hangup, sorry. Bridge is destroyed */
		ast_hangup(transferer->owner);
	} else {
		/* Transfer succeeded! */

		/* Tell transferer that we're done. */
		transmit_notify_with_sipfrag(transferer, seqno, "200 OK", TRUE);
		append_history(transferer, "Xfer", "Refer succeeded");
		transferer->refer->status = REFER_200OK;
		if (targetcall_pvt->owner) {
			if (option_debug)
				ast_log(LOG_DEBUG, "SIP attended transfer: Unlocking channel %s\n", targetcall_pvt->owner->name);
			ast_channel_unlock(targetcall_pvt->owner);
		}
	}
	return 1;
}

/*! \brief Handle incoming REFER request */
/*! \page SIP_REFER SIP transfer Support (REFER)

	REFER is used for call transfer in SIP. We get a REFER
	to place a new call with an INVITE somwhere and then
	keep the transferor up-to-date of the transfer. If the
	transfer fails, get back on line with the orginal call. 

	- REFER can be sent outside or inside of a dialog.
	  Asterisk only accepts REFER inside of a dialog.

	- If we get a replaces header, it is an attended transfer

	\par Blind transfers
	The transferor provides the transferee
	with the transfer targets contact. The signalling between
	transferer or transferee should not be cancelled, so the
	call is recoverable if the transfer target can not be reached 
	by the transferee.

	In this case, Asterisk receives a TRANSFER from
	the transferor, thus is the transferee. We should
	try to set up a call to the contact provided
	and if that fails, re-connect the current session.
	If the new call is set up, we issue a hangup.
	In this scenario, we are following section 5.2
	in the SIP CC Transfer draft. (Transfer without
	a GRUU)

	\par Transfer with consultation hold
	In this case, the transferor
	talks to the transfer target before the transfer takes place.
	This is implemented with SIP hold and transfer.
	Note: The invite From: string could indicate a transfer.
	(Section 6. Transfer with consultation hold)
	The transferor places the transferee on hold, starts a call
	with the transfer target to alert them to the impending
	transfer, terminates the connection with the target, then
	proceeds with the transfer (as in Blind transfer above)

	\par Attended transfer
	The transferor places the transferee
	on hold, calls the transfer target to alert them,
	places the target on hold, then proceeds with the transfer
	using a Replaces header field in the Refer-to header. This
	will force the transfee to send an Invite to the target,
	with a replaces header that instructs the target to
	hangup the call between the transferor and the target.
	In this case, the Refer/to: uses the AOR address. (The same
	URI that the transferee used to establish the session with
	the transfer target (To: ). The Require: replaces header should
	be in the INVITE to avoid the wrong UA in a forked SIP proxy
	scenario to answer and have no call to replace with.

	The referred-by header is *NOT* required, but if we get it,
	can be copied into the INVITE to the transfer target to 
	inform the target about the transferor

	"Any REFER request has to be appropriately authenticated.".
	
	We can't destroy dialogs, since we want the call to continue.
	
	*/
/*	XXX note that out-of-dialog refers are killed in match_or_create_dialog() */
int handle_request_refer(struct sip_dialog *p, struct sip_request *req, int debug, int seqno, int *nounlock)
{
	struct sip_dual current;	/* Chan1: Call between asterisk and transferer */
					/* Chan2: Call between asterisk and transferee */

	int res = 0;

	if (ast_test_flag(req, SIP_PKT_DEBUG))
		ast_verbose("Call %s got a SIP call transfer from %s: (REFER)!\n", p->callid, ast_test_flag(&p->flags[0], SIP_OUTGOING) ? "callee" : "caller");

	if (!p->owner) {
		/* This is a REFER outside of an existing SIP dialog */
		/* We can't handle that, so decline it */
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "Call %s: Declined REFER, outside of dialog...\n", p->callid);
		transmit_response(p, "603 Declined (No dialog)", req);
		if (!ast_test_flag(req, SIP_PKT_IGNORE)) {
			append_history(p, "Xfer", "Refer failed. Outside of dialog.");
			ast_set_flag(&p->flags[0], SIP_ALREADYGONE);	
			ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
		}
		return 0;
	}	


	/* Check if transfer is allowed from this device */
	if (p->allowtransfer == TRANSFER_CLOSED ) {
		/* Transfer not allowed, decline */
		transmit_response(p, "603 Declined (policy)", req);
		append_history(p, "Xfer", "Refer failed. Allowtransfer == closed.");
		/* Do not destroy SIP session */
		return 0;
	}

	if(!ast_test_flag(req, SIP_PKT_IGNORE) && ast_test_flag(&p->flags[0], SIP_GOTREFER)) {
		/* Already have a pending REFER */	
		transmit_response(p, "491 Request pending", req);
		append_history(p, "Xfer", "Refer failed. Request pending.");
		return 0;
	}

	/* Allocate memory for call transfer data */
	if (!p->refer && !sip_refer_allocate(p)) {
		transmit_response(p, "500 Internal Server Error", req);
		append_history(p, "Xfer", "Refer failed. Memory allocation error.");
		return -3;
	}

	res = get_refer_info(p, req);	/* Extract headers */

	p->refer->status = REFER_SENT;

	if (res != 0) {
		switch (res) {
		case -2:	/* Syntax error */
			transmit_response(p, "400 Bad Request (Refer-to missing)", req);
			append_history(p, "Xfer", "Refer failed. Refer-to missing.");
			if (ast_test_flag(req, SIP_PKT_DEBUG) && option_debug)
				ast_log(LOG_DEBUG, "SIP transfer to black hole can't be handled (no refer-to: )\n");
			break;
		case -3:
			transmit_response(p, "603 Declined (Non sip: uri)", req);
			append_history(p, "Xfer", "Refer failed. Non SIP uri");
			if (ast_test_flag(req, SIP_PKT_DEBUG) && option_debug)
				ast_log(LOG_DEBUG, "SIP transfer to non-SIP uri denied\n");
			break;
		default:
			/* Refer-to extension not found, fake a failed transfer */
			transmit_response(p, "202 Accepted", req);
			append_history(p, "Xfer", "Refer failed. Bad extension.");
			transmit_notify_with_sipfrag(p, seqno, "404 Not found", TRUE);
			ast_clear_flag(&p->flags[0], SIP_GOTREFER);	
			if (ast_test_flag(req, SIP_PKT_DEBUG) && option_debug)
				ast_log(LOG_DEBUG, "SIP transfer to bad extension: %s\n", p->refer->refer_to);
			break;
		} 
		return 0;
	}
	if (ast_strlen_zero(p->context))
		ast_string_field_set(p, context, global.default_context);

	/* If we do not support SIP domains, all transfers are local */
	if (global.allow_external_domains && check_sip_domain(p->refer->refer_to_domain, NULL, 0)) {
		p->refer->localtransfer = 1;
		if (sipdebug && option_debug > 2)
			ast_log(LOG_DEBUG, "This SIP transfer is local : %s\n", p->refer->refer_to_domain);
	} else if (domains_configured()) {
		/* This PBX don't bother with SIP domains, so all transfers are local */
		p->refer->localtransfer = 1;
	} else
		if (sipdebug && option_debug > 2)
			ast_log(LOG_DEBUG, "This SIP transfer is to a remote SIP extension (remote domain %s)\n", p->refer->refer_to_domain);
	
	/* Is this a repeat of a current request? Ignore it */
	/* Don't know what else to do right now. */
	if (ast_test_flag(req, SIP_PKT_IGNORE)) 
		return res;

	/* If this is a blind transfer, we have the following
   	channels to work with:
   	- chan1, chan2: The current call between transferer and transferee (2 channels)
   	- target_channel: A new call from the transferee to the target (1 channel)
   	We need to stay tuned to what happens in order to be able
   	to bring back the call to the transferer */

	/* If this is a attended transfer, we should have all call legs within reach:
   	- chan1, chan2: The call between the transferer and transferee (2 channels)
   	- target_channel, targetcall_pvt: The call between the transferer and the target (2 channels)
	We want to bridge chan2 with targetcall_pvt!
	
   	The replaces call id in the refer message points
   	to the call leg between Asterisk and the transferer.
   	So we need to connect the target and the transferee channel
   	and hangup the two other channels silently 
	
   	If the target is non-local, the call ID could be on a remote
   	machine and we need to send an INVITE with replaces to the
   	target. We basically handle this as a blind transfer
   	and let the sip_call function catch that we need replaces
   	header in the INVITE.
	*/


	/* Get the transferer's channel */
	current.chan1 = p->owner;

	/* Find the other part of the bridge (2) - transferee */
	current.chan2 = ast_bridged_channel(current.chan1);
	
	if (sipdebug && option_debug > 2)
		ast_log(LOG_DEBUG, "SIP %s transfer: Transferer channel %s, transferee channel %s\n", p->refer->attendedtransfer ? "attended" : "blind", current.chan1->name, current.chan2 ? current.chan2->name : "<none>");

	if (!current.chan2 && !p->refer->attendedtransfer) {
		/* No bridged channel, propably IVR or echo or similar... */
		/* Guess we should masquerade or something here */
		/* Until we figure it out, refuse transfer of such calls */
		if (sipdebug && option_debug > 2)
			ast_log(LOG_DEBUG,"Refused SIP transfer on non-bridged channel.\n");
		p->refer->status = REFER_FAILED;
		append_history(p, "Xfer", "Refer failed. Non-bridged channel.");
		transmit_response(p, "603 Declined", req);
		return -1;
	}

	if (current.chan2) {
		if (sipdebug && option_debug > 3)
			ast_log(LOG_DEBUG, "Got SIP transfer, applying to bridged peer '%s'\n", current.chan2->name);

		ast_queue_control(current.chan1, AST_CONTROL_UNHOLD);
	}

	ast_set_flag(&p->flags[0], SIP_GOTREFER);	

	/* Attended transfer: Find all call legs and bridge transferee with target*/
	if (p->refer->attendedtransfer) {
		if ((res = local_attended_transfer(p, &current, req, seqno)))
			return res;	/* We're done with the transfer */
		/* Fall through for remote transfers that we did not find locally */
		if (sipdebug && option_debug > 3)
			ast_log(LOG_DEBUG, "SIP attended transfer: Still not our call - generating INVITE with replaces\n");
		/* Fallthrough if we can't find the call leg internally */
	}


	/* Parking a call */
	if (p->refer->localtransfer && !strcmp(p->refer->refer_to, ast_parking_ext())) {
		/* Must release c's lock now, because it will not longer be accessible after the transfer! */
		*nounlock = 1;
		ast_channel_unlock(current.chan1);
		copy_request(&current.req, req);
		ast_clear_flag(&p->flags[0], SIP_GOTREFER);	
		p->refer->status = REFER_200OK;
		append_history(p, "Xfer", "REFER to call parking.");
		if (sipdebug && option_debug > 3)
			ast_log(LOG_DEBUG, "SIP transfer to parking: trying to park %s. Parked by %s\n", current.chan2->name, current.chan1->name);
		sip_park(current.chan2, current.chan1, req, seqno);
		return res;
	} 

	/* Blind transfers and remote attended xfers */
	transmit_response(p, "202 Accepted", req);

	if (current.chan1 && current.chan2) {
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "chan1->name: %s\n", current.chan1->name);
		pbx_builtin_setvar_helper(current.chan1, "BLINDTRANSFER", current.chan2->name);
	}
	if (current.chan2) {
		pbx_builtin_setvar_helper(current.chan2, "BLINDTRANSFER", current.chan1->name);
		pbx_builtin_setvar_helper(current.chan2, "SIPDOMAIN", p->refer->refer_to_domain);
		pbx_builtin_setvar_helper(current.chan2, "SIPTRANSFER", "yes");
		/* One for the new channel */
		pbx_builtin_setvar_helper(current.chan2, "_SIPTRANSFER", "yes");
		if (p->refer->referred_by)
			pbx_builtin_setvar_helper(current.chan2, "_SIPTRANSFER_REFERER", p->refer->referred_by);
		if (p->refer->referred_by)
		/* Attended transfer to remote host, prepare headers for the INVITE */
		pbx_builtin_setvar_helper(current.chan2, "_SIPTRANSFER_REFERER", p->refer->referred_by);
	}
	/* Generate an URI-encoded string */
	if (p->refer->replaces_callid && !ast_strlen_zero(p->refer->replaces_callid)) {
		char tempheader[BUFSIZ];
		char tempheader2[BUFSIZ];
		snprintf(tempheader, sizeof(tempheader), "%s%s%s%s%s", p->refer->replaces_callid, 
				p->refer->replaces_callid_totag ? ";to-tag=" : "", 
				p->refer->replaces_callid_totag, 
				p->refer->replaces_callid_fromtag ? ";from-tag=" : "",
				p->refer->replaces_callid_fromtag);

		/* Convert it to URL encoding, also convert reserved strings */
		ast_uri_encode(tempheader, tempheader2, sizeof(tempheader2), 1);

		if (current.chan2)
			pbx_builtin_setvar_helper(current.chan2, "_SIPTRANSFER_REPLACES", tempheader2);
	}
	/* Must release lock now, because it will not longer
    	   be accessible after the transfer! */
	*nounlock = 1;
	ast_channel_unlock(current.chan1);
	ast_channel_unlock(current.chan2);

	/* Connect the call */

	/* FAKE ringing if not attended transfer */
	if (!p->refer->attendedtransfer)
		transmit_notify_with_sipfrag(p, seqno, "183 Ringing", FALSE);
		
	/* For blind transfer, this will lead to a new call */
	/* For attended transfer to remote host, this will lead to
   	   a new SIP call with a replaces header, if the dial plan allows it 
  	*/
	if (!current.chan2) {
		/* We have no bridge, so we're talking with Asterisk somehow */
		/* We need to masquerade this call */
		/* What to do to fix this situation:
		   * Set up the new call in a new channel 
		   * Let the new channel masq into this channel
		   Please add that code here :-)
		*/
		transmit_response(p, "202 Accepted", req);
		p->refer->status = REFER_FAILED;
		transmit_notify_with_sipfrag(p, seqno, "503 Service Unavailable (can't handle one-legged xfers)", TRUE);
		ast_clear_flag(&p->flags[0], SIP_GOTREFER);	
		append_history(p, "Xfer", "Refer failed (only bridged calls).");
		return -1;
	}
	ast_set_flag(&p->flags[0], SIP_DEFER_BYE_ON_TRANSFER);	/* Delay hangup */

	/* For blind transfers, move the call to the new extensions. For attended transfers on multiple
	   servers - generate an INVITE with Replaces. Either way, let the dial plan decided  */
	res = ast_async_goto(current.chan2, p->refer->refer_to_context, p->refer->refer_to, 1);

	if (!res) {
		/* Success  - we have a new channel */
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "%s transfer succeeded. Telling transferer.\n", p->refer->attendedtransfer? "Attended" : "Blind");
		transmit_notify_with_sipfrag(p, seqno, "200 Ok", TRUE);
		if (p->refer->localtransfer)
			p->refer->status = REFER_200OK;
		if (p->owner)
			p->owner->hangupcause = AST_CAUSE_NORMAL_CLEARING;
		append_history(p, "Xfer", "Refer succeeded.");
		ast_clear_flag(&p->flags[0], SIP_GOTREFER);	
		/* Do not hangup call, the other side do that when we say 200 OK */
		/* We could possibly implement a timer here, auto congestion */
		res = 0;
	} else {
		ast_clear_flag(&p->flags[0], SIP_DEFER_BYE_ON_TRANSFER);	/* Don't delay hangup */
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "%s transfer failed. Resuming original call.\n", p->refer->attendedtransfer? "Attended" : "Blind");
		append_history(p, "Xfer", "Refer failed.");
		/* Failure of some kind */
		p->refer->status = REFER_FAILED;
		transmit_notify_with_sipfrag(p, seqno, "503 Service Unavailable", TRUE);
		ast_clear_flag(&p->flags[0], SIP_GOTREFER);	
		res = -1;
	}
	return res;
}

