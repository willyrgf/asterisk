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
#include "sip3core.h"

struct sip_network sipnet;		/* Socket and networking data */

/* Network interface stuff */

/*! \brief Protect the monitoring thread, so only one process can kill or start it, and not
   when it's doing something critical. */
AST_MUTEX_DEFINE_STATIC(netlock);

/* External variables from chan_sip3.so */
extern struct sip_globals global;

/*! \brief Lock netlock */
static void sipnet_lock()
{
	ast_mutex_lock(&netlock);
}

/*! \brief Unlock netlock */
static void sipnet_unlock()
{
	ast_mutex_unlock(&netlock);
}

/*! \brief Read data from SIP socket
\note sipsock_read locks the owner channel while we are processing the SIP message
\return 1 on error, 0 on success
\note Successful messages is connected to SIP call and forwarded to handle_request() 
*/
static int sipsock_read(int *id, int fd, short events, void *ignore)
{
	struct sip_request req;
	struct sockaddr_in sin = { 0, };
	struct sip_pvt *p;
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

		if (global.recordhistory) /* This is a request or response, note what it was for */
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

static int sipnet_ourport()
{
	return(sipnet.ourport);
}

static void sipnet_ourport_set(int port)
{
	sipnet.ourport = port;
}

