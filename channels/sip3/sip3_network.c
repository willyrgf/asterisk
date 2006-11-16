/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 * and Edvina AB, Sollentuna, Sweden (chan_sip3 changes/additions)
 *
 * Mark Spencer <markster@digium.com>
 *
 *
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
 * \brief Various SIP network interface functions
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
#include "asterisk/app.h"
#include "asterisk/dsp.h"
#include "asterisk/features.h"
#include "asterisk/acl.h"
#include "asterisk/srv.h"
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
#include "sip3funcs.h"			/* Moved functions */

struct sip_network sipnet;		/* Socket and networking data */

/* Network interface stuff */

/*! \brief Protect the monitoring thread, so only one process can kill or start it, and not
   when it's doing something critical. */
AST_MUTEX_DEFINE_STATIC(netlock);

/* External variables from chan_sip3.so */
extern struct sip_globals global;

/*! \brief Lock netlock */
void sipnet_lock(void)
{
	ast_mutex_lock(&netlock);
}

/*! \brief Unlock netlock */
void sipnet_unlock(void)
{
	ast_mutex_unlock(&netlock);
}

/*! \brief clear IP interfaces */
void reset_ip_interface(struct sip_network *sipnet)
{
	/* Reset IP addresses  */
	memset(&sipnet->bindaddr, 0, sizeof(sipnet->bindaddr));
	memset(&sipnet->localaddr, 0, sizeof(sipnet->localaddr));
	memset(&sipnet->externip, 0, sizeof(sipnet->externip));

	sipnet->outboundproxyip.sin_port = htons(STANDARD_SIP_PORT);
	sipnet->outboundproxyip.sin_family = AF_INET;	/* Type of address: IPv4 */
	memset(&sipnet->outboundproxyip, 0, sizeof(sipnet->outboundproxyip));

	sipnet_ourport_set(DEFAULT_LISTEN_SIP_PORT);
	sipnet->externhost[0] = '\0';			/* External host name (for behind NAT DynDNS support) */
	sipnet->externexpire = 0;			/* Expiration for DNS re-issuing */
	sipnet->externrefresh = 10;

}

/*! \brief Initialize IP socket on configured address - the bind address.
	\todo Needs to be converted to netsock */
int sipsock_init(struct sip_network *sipnet, struct sockaddr_in *old_bindaddr)
{
	if (ast_find_ourip(&sipnet->__ourip, sipnet->bindaddr)) {
		ast_log(LOG_WARNING, "Unable to get own IP address, SIP disabled\n");
		return -1;
	}
	if (!ntohs(sipnet->bindaddr.sin_port))
		sipnet->bindaddr.sin_port = ntohs(DEFAULT_LISTEN_SIP_PORT);
	sipnet->bindaddr.sin_family = AF_INET;
	sipnet_lock();
	if (sipsocket_initialized() && (memcmp(old_bindaddr, &sipnet->bindaddr, sizeof(struct sockaddr_in)))) {
		close(sipnet->sipsock);
		sipnet->sipsock = -1;
	}
	if (!sipsocket_initialized()) 
		sipsocket_open();	/* Open socket, bind to address and set TOS option */
	sipnet_unlock();
	return 0;
}

/*! \brief Read data from SIP socket
\note sipsock_read locks the owner channel while we are processing the SIP message
\return 1 on error, 0 on success
\note Successful messages is connected to SIP call and forwarded to handle_request() 
*/
int sipsock_read(int *id, int fd, short events, void *ignore)
{
	struct sip_request *req;
	struct sockaddr_in sin = { 0, };
	struct sip_dialog *p;
	int res;
	socklen_t len;
	int nounlock;
	int recount = 0;
	unsigned int lockretry = 100;

	if (!(req = ast_calloc(1, sizeof(*req))))
		return AST_FAILURE;

	len = sizeof(sin);
	res = recvfrom(sipnet.sipsock, req->data, sizeof(req->data) - 1, 0, (struct sockaddr *)&sin, &len);
	if (res < 0) {
#if !defined(__FreeBSD__)
		if (errno == EAGAIN)
			ast_log(LOG_NOTICE, "SIP: Received packet with bad UDP checksum\n");
		else 
#endif
		if (errno != ECONNREFUSED)
			ast_log(LOG_WARNING, "Recv error: %s\n", strerror(errno));
		free(req);
		return 1;
	}
	if(sip_debug_test_addr(&sin))	/* Set the debug flag early on packet level */
		ast_set_flag(req, SIP_PKT_DEBUG);
	if (res == sizeof(req->data)) {
		if (option_debug)
			ast_log(LOG_DEBUG, "Received packet exceeds buffer. Data is possibly lost\n");
		req->data[sizeof(req->data) - 1] = '\0';
	} else
		req->data[res] = '\0';
	req->len = lws2sws(req->data, res);	/* Fix multiline headers */
	if (ast_test_flag(req, SIP_PKT_DEBUG))
		ast_verbose("\n<-- SIP read from %s:%d: \n%s\n", ast_inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), req->data);

	parse_request(req);
	req->method = find_sip_method(req->rlPart1);
	if (ast_test_flag(req, SIP_PKT_DEBUG)) {
		ast_verbose("--- (%d headers %d lines)%s ---\n", req->headers, req->lines, (req->headers + req->lines == 0) ? " Nat keepalive" : "");
	}

	if (req->headers < 2) {
		/* Must have at least two headers */
		free(req);
		return AST_FAILURE;
	}


	/* Process request, with netlock held */
retrylock:
	sipnet_lock();

	/* Find the active SIP dialog or create a new one */
	p = match_or_create_dialog(req, &sin, req->method);	/* returns p locked */
	if (p == NULL) {
		if (option_debug)
			ast_log(LOG_DEBUG, "Invalid SIP message - rejected , no callid, len %d\n", req->len);
	} else {
		/* Go ahead and lock the owner if it has one -- we may need it */
		/* becaues this is deadlock-prone, we need to try and unlock if failed */
		if (p->owner && ast_channel_trylock(p->owner)) {
			if (option_debug)
				ast_log(LOG_DEBUG, "Failed to grab owner channel lock, trying again. (SIP call %s)\n", p->callid);
			dialog_lock(p, FALSE);
			sipnet_unlock();
			/* Sleep for a very short amount of time */
			usleep(1);
			if (--lockretry)
				goto retrylock;
		}
		p->recv = sin;

		if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY)) /* This is a request or response, note what it was for */
			append_history(p, "Rx", "%s / %s / %s", req->data, get_header(req, "CSeq"), req->rlPart2);

		if (!lockretry) {
			ast_log(LOG_ERROR, "We could NOT get the channel lock for %s! \n", p->owner->name ? p->owner->name : "- no channel name ??? - ");
			ast_log(LOG_ERROR, "SIP transaction failed: %s \n", p->callid);
			transmit_response(p, "503 Server error", req);	/* We must respond according to RFC 3261 sec 12.2 */
					/* XXX We could add retry-after to make sure they come back */
			append_history(p, "LockFail", "Owner lock failed, transaction failed.");
			return 1;
		}
		nounlock = 0;
		if (handle_request(p, req, &sin, &recount, &nounlock) == -1) {
			/* Request failed */
			if (option_debug)
				ast_log(LOG_DEBUG, "SIP message could not be handled, bad request: %-70.70s\n", p->callid[0] ? p->callid : "<no callid>");
		}
		
		if (p->owner && !nounlock)
			ast_channel_unlock(p->owner);
		dialog_lock(p, FALSE);
	}
	sipnet_unlock();
	if (recount)
		ast_update_use_count();
	
	/* If this packet is not connected to a dialog, then free it. If it is connected,
		then let the dialog destroy it later */
	if (!ast_test_flag(req, SIP_PKT_CONNECTED))
		free(req);

	return 1;
}

/*! \brief Check if network socket is open */
int sipsocket_initialized(void)
{
	if (sipnet.sipsock < 0)
		return FALSE;
	return TRUE;
}

/*! \brief Open network socket, bind to address and set options (TOS) */
int sipsocket_open(void)
{
	const int reuseFlag = 1;

	sipnet.sipsock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sipnet.sipsock < 0) {
		ast_log(LOG_WARNING, "Unable to create SIP socket: %s\n", strerror(errno));
		return FALSE;
	} 
	/* Allow SIP clients on the same host to access us: */
	setsockopt(sipnet.sipsock, SOL_SOCKET, SO_REUSEADDR,
				   (const char*)&reuseFlag,
				   sizeof reuseFlag);
	
	ast_enable_packet_fragmentation(sipnet.sipsock);

	if (bind(sipnet.sipsock, (struct sockaddr *)&sipnet.bindaddr, sizeof(sipnet.bindaddr)) < 0) {
		ast_log(LOG_WARNING, "Failed to bind to %s:%d: %s\n",
			ast_inet_ntoa(sipnet.bindaddr.sin_addr), ntohs(sipnet.bindaddr.sin_port),
			strerror(errno));
		close(sipnet.sipsock);
		sipnet.sipsock = -1;
		return FALSE;
	} else {
		if (option_verbose > 1) { 
			ast_verbose(VERBOSE_PREFIX_2 "SIP Listening on %s:%d\n", 
				ast_inet_ntoa(sipnet.bindaddr.sin_addr), ntohs(sipnet.bindaddr.sin_port));
			ast_verbose(VERBOSE_PREFIX_2 "Using SIP TOS: %s\n", ast_tos2str(global.tos_sip));
		}
		if (setsockopt(sipnet.sipsock, IPPROTO_IP, IP_TOS, &global.tos_sip, sizeof(global.tos_sip))) 
			ast_log(LOG_WARNING, "Unable to set SIP TOS to %s\n", ast_tos2str(global.tos_sip));
	}
	return TRUE;
}

/*! \brief read our port number */
int sipnet_ourport(void)
{
	return(sipnet.ourport);
}

/*! \brief Set our port number */
void sipnet_ourport_set(int port)
{
	sipnet.ourport = port;
}

/*! \brief Transmit SIP message */
static int __sip_xmit(struct sip_dialog *p, struct sip_request *req)
{
	int res;
	const struct sockaddr_in *dst = sip_real_dst(p);

	/* XXX in the future, we need to make sure we follow the current flow for this dialog  - TCP, UDP */
	res = sendto(sipnet.sipsock, req->data, req->len, 0, (const struct sockaddr *)dst, sizeof(struct sockaddr_in));

	if (res != req->len)
		ast_log(LOG_WARNING, "sip_xmit of %p (len %d) to %s:%d returned %d: %s\n", req->data, req->len, ast_inet_ntoa(dst->sin_addr), ntohs(dst->sin_port), res, strerror(errno));
	return res;
}

/*! \brief Retransmit SIP message if no answer (Called from scheduler) */
/* XXX This should be moved to transaction handler */
static int retrans_pkt(void *data)
{
	struct sip_request *pkt = data, *prev, *cur = NULL;
	int reschedule = DEFAULT_RETRANS;

	/* Lock channel PVT */
	dialog_lock(pkt->dialog, TRUE);

	if (pkt->retrans < MAX_RETRANS) {
		pkt->retrans++;
 		if (!pkt->timer_t1) {	/* Re-schedule using timer_a and timer_t1 */
			if (sipdebug && option_debug > 3)
 				ast_log(LOG_DEBUG, "SIP TIMER: Not rescheduling id #%d:%s (Method %d) (No timer T1)\n", pkt->retransid, sip_method2txt(pkt->method), pkt->method);
		} else {
 			int siptimer_a;

 			if (sipdebug && option_debug > 3)
 				ast_log(LOG_DEBUG, "SIP TIMER: Rescheduling retransmission #%d (%d) %s - %d\n", pkt->retransid, pkt->retrans, sip_method2txt(pkt->method), pkt->method);
 			if (!pkt->timer_a)
 				pkt->timer_a = 2 ;
 			else
 				pkt->timer_a = 2 * pkt->timer_a;
 
 			/* For non-invites, a maximum of 4 secs */
 			siptimer_a = pkt->timer_t1 * pkt->timer_a;	/* Double each time */
 			if (pkt->method != SIP_INVITE && siptimer_a > 4000)
 				siptimer_a = 4000;
 		
 			/* Reschedule re-transmit */
			reschedule = siptimer_a;
 			if (option_debug > 3)
 				ast_log(LOG_DEBUG, "** SIP timers: Rescheduling retransmission %d to %d ms (t1 %d ms (Retrans id #%d)) \n", pkt->retrans +1, siptimer_a, pkt->timer_t1, pkt->retransid);
 		} 

		if (sip_debug_test_pvt(pkt->dialog)) {
			const struct sockaddr_in *dst = sip_real_dst(pkt->dialog);
			ast_verbose("Retransmitting #%d (%s) to %s:%d:\n%s\n---\n",
				pkt->retrans, sip_nat_mode(pkt->dialog),
				ast_inet_ntoa(dst->sin_addr),
				ntohs(dst->sin_port), pkt->data);
		}

		append_history(pkt->dialog, "ReTx", "%d %s", reschedule, pkt->data);
		__sip_xmit(pkt->dialog, pkt);
		dialog_lock(pkt->dialog, FALSE);
		return  reschedule;
	} 
	/* Too many retries */
	if (pkt->dialog && pkt->method != SIP_OPTIONS) {
		if (ast_test_flag(pkt, SIP_PKT_FATAL) || sipdebug)	/* Tell us if it's critical or if we're debugging */
			ast_log(LOG_WARNING, "Maximum retries exceeded on transmission %s for seqno %d (%s %s)\n", pkt->dialog->callid, pkt->seqno, (ast_test_flag(pkt, SIP_PKT_FATAL)) ? "Critical" : "Non-critical", (ast_test_flag(pkt, SIP_PKT_RESPONSE)) ? "Response" : "Request");
	} else {
		if ((pkt->method == SIP_OPTIONS) && sipdebug)
			ast_log(LOG_WARNING, "Cancelling retransmit of OPTIONs (call id %s) \n", pkt->dialog->callid);
	}
	append_history(pkt->dialog, "MaxRetries", "%s", (ast_test_flag(pkt, SIP_PKT_FATAL)) ? "(Critical)" : "(Non-critical)");
 		
	pkt->retransid = -1;

	if (ast_test_flag(pkt, SIP_PKT_FATAL)) {
		while(pkt->dialog->owner && ast_channel_trylock(pkt->dialog->owner)) {
			dialog_lock(pkt->dialog, FALSE);
			usleep(1);
			dialog_lock(pkt->dialog, TRUE);
		}
		if (pkt->dialog->owner) {
			ast_set_flag(&pkt->dialog->flags[0], SIP_ALREADYGONE);
			ast_log(LOG_WARNING, "Hanging up call %s - no reply to our critical packet.\n", pkt->dialog->callid);
			ast_queue_hangup(pkt->dialog->owner);
			ast_channel_unlock(pkt->dialog->owner);
		} else {
			/* If no channel owner, destroy now 
				...unless it's a SIP options packet, where
				we want the peerpoke expiry routine handle this.
			*/
			if (pkt->method != SIP_OPTIONS)
				ast_set_flag(&pkt->dialog->flags[0], SIP_NEEDDESTROY);	
		}
	}
	/* In any case, go ahead and remove the packet */
	for (prev = NULL, cur = pkt->dialog->packets; cur; prev = cur, cur = cur->next) {
		if (cur == pkt)
			break;
	}
	if (cur) {
		if (prev)
			prev->next = cur->next;
		else
			pkt->dialog->packets = cur->next;
		dialog_lock(pkt->dialog, FALSE);
		free(cur);
		pkt = NULL;
	} else
		ast_log(LOG_WARNING, "Weird, couldn't find packet dialog!\n");
	if (pkt)
		dialog_lock(pkt->dialog, FALSE);
	return 0;
}

/*! \brief Transmit packet with retransmits 
	\note the packet is stored in the PVT until we have a reply...
	\return 0 on success, -1 on failure to allocate packet 
*/
static enum sip_result __sip_reliable_xmit(struct sip_dialog *dialog, 
	int seqno, int resp, struct sip_request *req, int fatal)
{
	int siptimer_a = DEFAULT_RETRANS;
	enum sip_result res= AST_FAILURE;

	ast_set_flag(req, SIP_PKT_CONNECTED);	/* Stop sipsock_read from free'ing this request */
	req->next = dialog->packets;
	req->dialog = dialog;
	req->seqno = seqno;
	if (resp)
		ast_set_flag(req, SIP_PKT_RESPONSE);
	req->timer_t1 = dialog->timer_t1;	/* Set SIP timer T1 */
	/* If this is critical for the success of this transaction, mark it FATAL
		the dialog will fail if this is not accepted */
	if (fatal)
		ast_set_flag(req, SIP_PKT_FATAL);
	if (req->timer_t1)
		siptimer_a = req->timer_t1 * 2;

	/* Schedule retransmission */
	req->retransid = ast_sched_add_variable(sched, siptimer_a, retrans_pkt, req, 1);

	if (option_debug > 3 && sipdebug)
		ast_log(LOG_DEBUG, "*** SIP TIMER: Initalizing retransmit timer on packet: Id  #%d\n", req->retransid);
	/* XXX Are we locked? Any chance of messing up here? */
	req->next = dialog->packets;
	dialog->packets = req;

	/* Send packet */
	if (!__sip_xmit(req->dialog, req))
		res = AST_FAILURE;
	else
		res = AST_SUCCESS;


	if (req->method == SIP_INVITE) {
		/* Note this is a pending invite */
		dialog->pendinginvite = seqno;
	}
	return res;
}

/*! \brief Transmit response on SIP request*/
int send_response(struct sip_dialog *p, struct sip_request *req, enum xmittype reliable, int seqno)
{
	int res;

	add_blank(req);
	if (sip_debug_test_pvt(p)) {
		const struct sockaddr_in *dst = sip_real_dst(p);

		ast_verbose("%sTransmitting (%s) to %s:%d:\n%s\n---\n",
			reliable ? "Reliably " : "", sip_nat_mode(p),
			ast_inet_ntoa(dst->sin_addr),
			ntohs(dst->sin_port), req->data);
	}
	if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY)) {
		struct sip_request tmp;
		parse_copy(&tmp, req);
		append_history(p, reliable ? "TxRespRel" : "TxResp", "%s / %s - %s", tmp.data, get_header(&tmp, "CSeq"), 
			(tmp.method == SIP_RESPONSE || tmp.method == SIP_UNKNOWN) ? tmp.rlPart2 : sip_method2txt(tmp.method));
	}
	res = (reliable) ?
		__sip_reliable_xmit(p, seqno, 1, req, (reliable == XMIT_CRITICAL)) :
		__sip_xmit(p, req);
	if (res > 0)
		return 0;
	return res;
}

/*! \brief Send SIP Request to the other part of the dialogue */
int send_request(struct sip_dialog *p, struct sip_request *req, enum xmittype reliable, int seqno)
{
	int res;

	add_blank(req);
	if (sip_debug_test_pvt(p)) {
		if (ast_test_flag(&p->flags[0], SIP_NAT_ROUTE))
			ast_verbose("%sTransmitting (NAT) to %s:%d:\n%s\n---\n", reliable ? "Reliably " : "", ast_inet_ntoa(p->recv.sin_addr), ntohs(p->recv.sin_port), req->data);
		else
			ast_verbose("%sTransmitting (no NAT) to %s:%d:\n%s\n---\n", reliable ? "Reliably " : "", ast_inet_ntoa(p->sa.sin_addr), ntohs(p->sa.sin_port), req->data);
	}
	if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY)) {
		struct sip_request tmp;
		parse_copy(&tmp, req);
		append_history(p, reliable ? "TxReqRel" : "TxReq", "%s / %s - %s", tmp.data, get_header(&tmp, "CSeq"), sip_method2txt(tmp.method));
	}
	res = (reliable) ?
		__sip_reliable_xmit(p, seqno, 0, req, (reliable > 1)) :
		__sip_xmit(p, req);
	return res;
}

/*! \brief The real destination address for a write */
const struct sockaddr_in *sip_real_dst(const struct sip_dialog *p)
{
	return ast_test_flag(&p->flags[0], SIP_NAT) & SIP_NAT_ROUTE ? &p->recv : &p->sa;
}


/*! \brief See if we pass debug IP filter */
inline int sip_debug_test_addr(const struct sockaddr_in *addr) 
{
	if (!sipdebug)
		return 0;
	if (sipnet.debugaddr.sin_addr.s_addr) {
		if (((ntohs(sipnet.debugaddr.sin_port) != 0)
			&& (sipnet.debugaddr.sin_port != addr->sin_port))
			|| (sipnet.debugaddr.sin_addr.s_addr != addr->sin_addr.s_addr))
			return 0;
	}
	return 1;
}

/*! \brief Test PVT for debugging output */
inline int sip_debug_test_pvt(struct sip_dialog *p)
{
	if (!sipdebug)
		return 0;
	return sip_debug_test_addr(sip_real_dst(p));
}

/*! \brief NAT fix - decide which IP address to use for ASterisk server?
 *
 * Using the localaddr structure built up with localnet statements in sip.conf
 * apply it to their address to see if we need to substitute our
 * externip or can get away with our internal bindaddr
 */
enum sip_result sip_ouraddrfor(struct in_addr *them, struct in_addr *us)
{
	struct sockaddr_in theirs, ours;

	/* Get our local information */
	ast_ouraddrfor(them, us);
	theirs.sin_addr = *them;
	ours.sin_addr = *us;

	if (sipnet.localaddr && sipnet.externip.sin_addr.s_addr &&
	    ast_apply_ha(sipnet.localaddr, &theirs) &&
	    !ast_apply_ha(sipnet.localaddr, &ours)) {
		if (sipnet.externexpire && time(NULL) >= sipnet.externexpire) {
			struct ast_hostent ahp;
			struct hostent *hp;

			sipnet.externexpire = time(NULL) + sipnet.externrefresh;
			if ((hp = ast_gethostbyname(sipnet.externhost, &ahp))) {
				memcpy(&sipnet.externip.sin_addr, hp->h_addr, sizeof(sipnet.externip.sin_addr));
			} else
				ast_log(LOG_NOTICE, "Warning: Re-lookup of '%s' failed!\n", sipnet.externhost);
		}
		*us = sipnet.externip.sin_addr;
		if (option_debug) {
			ast_log(LOG_DEBUG, "Target address %s is not local, substituting externip\n", 
				ast_inet_ntoa(*(struct in_addr *)&them->s_addr));
		}
	} else if (sipnet.bindaddr.sin_addr.s_addr)
		*us = sipnet.bindaddr.sin_addr;
	return AST_SUCCESS;
}
