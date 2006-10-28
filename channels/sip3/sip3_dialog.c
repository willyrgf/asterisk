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
#include "sip3.h"
#include "sip3funcs.h"

/*! \page chan_sip3_dialogs Chan_sip3: The dialog list
	\par The dialog list
	The dialog list contains all active dialogs in various states.
	A dialog can be 
	- an active call
	- a call in hangup state - waiting for cleanup
	- a subscription
	- an inbound or outbound registration

	We will implement dialog states soon
	\ref enum dialogstate

*/

/*! \brief Protect the SIP dialog list (of sip_dialog's) */
AST_MUTEX_DEFINE_STATIC(dialoglock);

/*! \brief Lock list of active SIP dialogs */
void dialoglist_lock(void)
{
	ast_mutex_lock(&dialoglock);
}

/*! \brief Unlock list of active SIP dialogs */
void dialoglist_unlock(void)
{
	ast_mutex_unlock(&dialoglock);
}


/*! \brief Kill a SIP dialog (called by scheduler) */
static int __sip_autodestruct(void *data)
{
	struct sip_dialog *p = data;

	/* If this is a subscription, tell the phone that we got a timeout */
	if (p->subscribed) {
		p->subscribed = TIMEOUT;
		transmit_state_notify(p, AST_EXTENSION_DEACTIVATED, 1);	/* Send last notification */
		p->subscribed = NONE;
		append_history(p, "Subscribestatus", "timeout");
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "Re-scheduled destruction of SIP subsription %s\n", p->callid ? p->callid : "<unknown>");
		return 10000;	/* Reschedule this destruction so that we know that it's gone */
	}

	/* Reset schedule ID */
	p->autokillid = -1;

	if (option_debug)
		ast_log(LOG_DEBUG, "Auto destroying SIP dialog '%s'\n", p->callid);
	append_history(p, "AutoDestroy", "%s", p->callid);
	if (p->owner) {
		ast_log(LOG_WARNING, "Autodestruct on dialog '%s' with owner in place (Method: %s)\n", p->callid, sip_method2txt(p->method));
		ast_queue_hangup(p->owner);
	} else if (p->refer)
		transmit_request_with_auth(p, SIP_BYE, 0, XMIT_RELIABLE, 1);
	else 
		sip_destroy(p);
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

	p->branch = ast_random();	
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
		if (p->vrtp) {
			ast_rtp_settos(p->vrtp, global.tos_video);
			ast_rtp_setdtmf(p->vrtp, 0);
			ast_rtp_setdtmfcompensate(p->vrtp, 0);
		}
		if (p->udptl)
			ast_udptl_settos(p->udptl, global.tos_audio);
		p->rtptimeout = global.rtptimeout;
		p->rtpholdtimeout = global.rtpholdtimeout;
		p->rtpkeepalive = global.rtpkeepalive;
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
	build_via(p);
	if (!callid)
		build_callid_pvt(p);
	else
		ast_string_field_set(p, callid, callid);
	/* Assign default music on hold class */
	ast_string_field_set(p, mohinterpret, global.default_mohinterpret);
	ast_string_field_set(p, mohsuggest, global.default_mohsuggest);
	p->capability = global.capability;
	p->allowtransfer = global.allowtransfer;
	if ((ast_test_flag(&p->flags[0], SIP_DTMF) == SIP_DTMF_RFC2833) ||
	    (ast_test_flag(&p->flags[0], SIP_DTMF) == SIP_DTMF_AUTO))
		p->noncodeccapability |= AST_RTP_DTMF;
	if (p->udptl) {
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

	/* Add to active dialog list */
	dialoglist_lock();
	p->next = dialoglist;
	dialoglist = p;
	dialoglist_unlock();
	if (option_debug)
		ast_log(LOG_DEBUG, "Allocating new SIP dialog for %s - %s (%s)\n", callid ? callid : "(No Call-ID)", sip_method2txt(intended_method), p->rtp ? "With RTP" : "No RTP");
	return p;
}

