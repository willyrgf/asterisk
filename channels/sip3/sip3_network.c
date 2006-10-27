/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
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

/*! \brief Read data from SIP socket
\note sipsock_read locks the owner channel while we are processing the SIP message
\return 1 on error, 0 on success
\note Successful messages is connected to SIP call and forwarded to handle_request() 
*/
int sipsock_read(int *id, int fd, short events, void *ignore)
{
	struct sip_request req;
	struct sockaddr_in sin = { 0, };
	struct sip_dialog *p;
	int res;
	socklen_t len;
	int nounlock;
	int recount = 0;
	unsigned int lockretry = 100;

	len = sizeof(sin);
	memset(&req, 0, sizeof(req));
	res = recvfrom(sipnet.sipsock, req.data, sizeof(req.data) - 1, 0, (struct sockaddr *)&sin, &len);
	if (res < 0) {
#if !defined(__FreeBSD__)
		if (errno == EAGAIN)
			ast_log(LOG_NOTICE, "SIP: Received packet with bad UDP checksum\n");
		else 
#endif
		if (errno != ECONNREFUSED)
			ast_log(LOG_WARNING, "Recv error: %s\n", strerror(errno));
		return 1;
	}
	if (option_debug && res == sizeof(req.data)) {
		ast_log(LOG_DEBUG, "Received packet exceeds buffer. Data is possibly lost\n");
		req.data[sizeof(req.data) - 1] = '\0';
	} else
		req.data[res] = '\0';
	req.len = res;
	if(sip_debug_test_addr(&sin))	/* Set the debug flag early on packet level */
		ast_set_flag(&req, SIP_PKT_DEBUG);
	req.len = lws2sws(req.data, req.len);	/* Fix multiline headers */
	if (ast_test_flag(&req, SIP_PKT_DEBUG))
		ast_verbose("\n<-- SIP read from %s:%d: \n%s\n", ast_inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), req.data);

	parse_request(&req);
	req.method = find_sip_method(req.rlPart1);
	if (ast_test_flag(&req, SIP_PKT_DEBUG)) {
		ast_verbose("--- (%d headers %d lines)%s ---\n", req.headers, req.lines, (req.headers + req.lines == 0) ? " Nat keepalive" : "");
	}

	if (req.headers < 2) {
		/* Must have at least two headers */
		return 1;
	}


	/* Process request, with netlock held */
retrylock:
	sipnet_lock();

	/* Find the active SIP dialog or create a new one */
	p = find_call(&req, &sin, req.method);	/* returns p locked */
	if (p == NULL) {
		if (option_debug)
			ast_log(LOG_DEBUG, "Invalid SIP message - rejected , no callid, len %d\n", req.len);
	} else {
		/* Go ahead and lock the owner if it has one -- we may need it */
		/* becaues this is deadlock-prone, we need to try and unlock if failed */
		if (p->owner && ast_channel_trylock(p->owner)) {
			if (option_debug)
				ast_log(LOG_DEBUG, "Failed to grab owner channel lock, trying again. (SIP call %s)\n", p->callid);
			ast_mutex_unlock(&p->lock);
			sipnet_unlock();
			/* Sleep for a very short amount of time */
			usleep(1);
			if (--lockretry)
				goto retrylock;
		}
		p->recv = sin;

		if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY)) /* This is a request or response, note what it was for */
			append_history(p, "Rx", "%s / %s / %s", req.data, get_header(&req, "CSeq"), req.rlPart2);

		if (!lockretry) {
			ast_log(LOG_ERROR, "We could NOT get the channel lock for %s! \n", p->owner->name ? p->owner->name : "- no channel name ??? - ");
			ast_log(LOG_ERROR, "SIP transaction failed: %s \n", p->callid);
			transmit_response(p, "503 Server error", &req);	/* We must respond according to RFC 3261 sec 12.2 */
					/* XXX We could add retry-after to make sure they come back */
			append_history(p, "LockFail", "Owner lock failed, transaction failed.");
			return 1;
		}
		nounlock = 0;
		if (handle_request(p, &req, &sin, &recount, &nounlock) == -1) {
			/* Request failed */
			if (option_debug)
				ast_log(LOG_DEBUG, "SIP message could not be handled, bad request: %-70.70s\n", p->callid[0] ? p->callid : "<no callid>");
		}
		
		if (p->owner && !nounlock)
			ast_channel_unlock(p->owner);
		ast_mutex_unlock(&p->lock);
	}
	sipnet_unlock();
	if (recount)
		ast_update_use_count();

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
static int __sip_xmit(struct sip_dialog *p, char *data, int len)
{
	int res;
	const struct sockaddr_in *dst = sip_real_dst(p);
	res = sendto(sipnet.sipsock, data, len, 0, (const struct sockaddr *)dst, sizeof(struct sockaddr_in));

	if (res != len)
		ast_log(LOG_WARNING, "sip_xmit of %p (len %d) to %s:%d returned %d: %s\n", data, len, ast_inet_ntoa(dst->sin_addr), ntohs(dst->sin_port), res, strerror(errno));
	return res;
}

/*! \brief Retransmit SIP message if no answer (Called from scheduler) */
/* XXX This should be moved to transaction handler */
static int retrans_pkt(void *data)
{
	struct sip_pkt *pkt = data, *prev, *cur = NULL;
	int reschedule = DEFAULT_RETRANS;

	/* Lock channel PVT */
	ast_mutex_lock(&pkt->owner->lock);

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

		if (sip_debug_test_pvt(pkt->owner)) {
			const struct sockaddr_in *dst = sip_real_dst(pkt->owner);
			ast_verbose("Retransmitting #%d (%s) to %s:%d:\n%s\n---\n",
				pkt->retrans, sip_nat_mode(pkt->owner),
				ast_inet_ntoa(dst->sin_addr),
				ntohs(dst->sin_port), pkt->data);
		}

		append_history(pkt->owner, "ReTx", "%d %s", reschedule, pkt->data);
		__sip_xmit(pkt->owner, pkt->data, pkt->packetlen);
		ast_mutex_unlock(&pkt->owner->lock);
		return  reschedule;
	} 
	/* Too many retries */
	if (pkt->owner && pkt->method != SIP_OPTIONS) {
		if (ast_test_flag(pkt, FLAG_FATAL) || sipdebug)	/* Tell us if it's critical or if we're debugging */
			ast_log(LOG_WARNING, "Maximum retries exceeded on transmission %s for seqno %d (%s %s)\n", pkt->owner->callid, pkt->seqno, (ast_test_flag(pkt, FLAG_FATAL)) ? "Critical" : "Non-critical", (ast_test_flag(pkt, FLAG_RESPONSE)) ? "Response" : "Request");
	} else {
		if ((pkt->method == SIP_OPTIONS) && sipdebug)
			ast_log(LOG_WARNING, "Cancelling retransmit of OPTIONs (call id %s) \n", pkt->owner->callid);
	}
	append_history(pkt->owner, "MaxRetries", "%s", (ast_test_flag(pkt, FLAG_FATAL)) ? "(Critical)" : "(Non-critical)");
 		
	pkt->retransid = -1;

	if (ast_test_flag(pkt, FLAG_FATAL)) {
		while(pkt->owner->owner && ast_channel_trylock(pkt->owner->owner)) {
			ast_mutex_unlock(&pkt->owner->lock);	/* SIP_PVT, not channel */
			usleep(1);
			ast_mutex_lock(&pkt->owner->lock);
		}
		if (pkt->owner->owner) {
			ast_set_flag(&pkt->owner->flags[0], SIP_ALREADYGONE);
			ast_log(LOG_WARNING, "Hanging up call %s - no reply to our critical packet.\n", pkt->owner->callid);
			ast_queue_hangup(pkt->owner->owner);
			ast_channel_unlock(pkt->owner->owner);
		} else {
			/* If no channel owner, destroy now */
			ast_set_flag(&pkt->owner->flags[0], SIP_NEEDDESTROY);	
		}
	}
	/* In any case, go ahead and remove the packet */
	for (prev = NULL, cur = pkt->owner->packets; cur; prev = cur, cur = cur->next) {
		if (cur == pkt)
			break;
	}
	if (cur) {
		if (prev)
			prev->next = cur->next;
		else
			pkt->owner->packets = cur->next;
		ast_mutex_unlock(&pkt->owner->lock);
		free(cur);
		pkt = NULL;
	} else
		ast_log(LOG_WARNING, "Weird, couldn't find packet owner!\n");
	if (pkt)
		ast_mutex_unlock(&pkt->owner->lock);
	return 0;
}

/*! \brief Transmit packet with retransmits 
	\return 0 on success, -1 on failure to allocate packet 
*/
static enum sip_result __sip_reliable_xmit(struct sip_dialog *p, int seqno, int resp, char *data, int len, int fatal, int sipmethod)
{
	struct sip_pkt *pkt;
	int siptimer_a = DEFAULT_RETRANS;

	if (!(pkt = ast_calloc(1, sizeof(*pkt) + len + 1)))
		return AST_FAILURE;
	memcpy(pkt->data, data, len);
	pkt->method = sipmethod;
	pkt->packetlen = len;
	pkt->next = p->packets;
	pkt->owner = p;
	pkt->seqno = seqno;
	pkt->flags = resp;
	pkt->data[len] = '\0';
	pkt->timer_t1 = p->timer_t1;	/* Set SIP timer T1 */
	if (fatal)
		ast_set_flag(pkt, FLAG_FATAL);
	if (pkt->timer_t1)
		siptimer_a = pkt->timer_t1 * 2;

	/* Schedule retransmission */
	pkt->retransid = ast_sched_add_variable(sched, siptimer_a, retrans_pkt, pkt, 1);
	if (option_debug > 3 && sipdebug)
		ast_log(LOG_DEBUG, "*** SIP TIMER: Initalizing retransmit timer on packet: Id  #%d\n", pkt->retransid);
	pkt->next = p->packets;
	p->packets = pkt;

	__sip_xmit(pkt->owner, pkt->data, pkt->packetlen);	/* Send packet */
	if (sipmethod == SIP_INVITE) {
		/* Note this is a pending invite */
		p->pendinginvite = seqno;
	}
	return AST_SUCCESS;
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
		__sip_reliable_xmit(p, seqno, 1, req->data, req->len, (reliable == XMIT_CRITICAL), req->method) :
		__sip_xmit(p, req->data, req->len);
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
		__sip_reliable_xmit(p, seqno, 0, req->data, req->len, (reliable > 1), req->method) :
		__sip_xmit(p, req->data, req->len);
	return res;
}
