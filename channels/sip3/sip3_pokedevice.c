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
 * \brief SIP qualification subsystem - poking around on the network
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

/*! \brief Poke peer (send qualify to check if peer is alive and well) */
int sip_poke_peer_s(void *data)
{
	struct sip_peer *peer = data;

	peer->pokeexpire = -1;
	sip_poke_peer(peer);
	return 0;
}

/*! \brief Handle qualification responses (OPTIONS) */
void handle_response_peerpoke(struct sip_dialog *p, int resp, struct sip_request *req)
{
	struct sip_peer *peer = p->relatedpeer;
	int statechanged, is_reachable, was_reachable;
	int pingtime = ast_tvdiff_ms(ast_tvnow(), peer->ps);

	/*
	 * Compute the response time to a ping (goes in peer->lastms.)
	 * -1 means did not respond, 0 means unknown,
	 * 1..maxms is a valid response, >maxms means late response.
	 */
	if (pingtime < 1)	/* zero = unknown, so round up to 1 */
		pingtime = 1;

	/* Now determine new state and whether it has changed.
	 * Use some helper variables to simplify the writing
	 * of the expressions.
	 */
	was_reachable = peer->lastms > 0 && peer->lastms <= peer->maxms;
	is_reachable = pingtime <= peer->maxms;
	statechanged = peer->lastms == 0 /* yes, unknown before */
		|| was_reachable != is_reachable;

	peer->lastms = pingtime;
	peer->call = NULL;
	if (statechanged) {
		const char *s = is_reachable ? "Reachable" : "Lagged";

		ast_log(LOG_NOTICE, "Peer '%s' is now %s. (%dms / %dms)\n",
			peer->name, s, pingtime, peer->maxms);
		ast_device_state_changed("SIP/%s", peer->name);
		manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
			"Peer: SIP/%s\r\nPeerStatus: %s\r\nTime: %d\r\n",
			peer->name, s, pingtime);
	}

	if (peer->pokeexpire > -1)
		ast_sched_del(sched, peer->pokeexpire);

	/* Try again eventually */
	peer->pokeexpire = ast_sched_add(sched,
		is_reachable ? global.default_qualifycheck_ok: global.default_qualifycheck_notok,
		sip_poke_peer_s, peer);

	dialogstatechange(p, DIALOG_STATE_TERMINATED);
	ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
}

/*! \brief React to lack of answer to Qualify poke */
int sip_poke_noanswer(void *data)
{
	struct sip_peer *peer = data;
	
	peer->pokeexpire = -1;
	if (peer->lastms > -1) {
		ast_log(LOG_NOTICE, "Peer '%s' is now UNREACHABLE!  Last qualify: %d\n", peer->name, peer->lastms);
		manager_event(EVENT_FLAG_SYSTEM, "PeerStatus", "Peer: SIP/%s\r\nPeerStatus: Unreachable\r\nTime: %d\r\n", peer->name, -1);
	}
	if (peer->call)
		sip_destroy(peer->call);
	peer->call = NULL;
	peer->lastms = -1;
	ast_device_state_changed("SIP/%s", peer->name);
	/* Try again quickly */
	peer->pokeexpire = ast_sched_add(sched, global.default_qualifycheck_notok, sip_poke_peer_s, peer);
	return 0;
}

/*! \brief Check availability of peer, also keep NAT open
\note	This is done with the interval in qualify= configuration option
	Default is 2 seconds */
int sip_poke_peer(struct sip_peer *peer)
{
	struct sip_dialog *p;

	if (!peer->maxms || !peer->addr.sin_addr.s_addr) {
		/* IF we have no IP, or this isn't to be monitored, return
		  imeediately after clearing things out */
		if (peer->pokeexpire > -1)
			ast_sched_del(sched, peer->pokeexpire);
		peer->lastms = 0;
		peer->pokeexpire = -1;
		peer->call = NULL;
		return 0;
	}
	if (peer->call > 0) {
		if (sipdebug)
			ast_log(LOG_NOTICE, "Still have a QUALIFY dialog active, deleting\n");
		sip_destroy(peer->call);
	}
	if (!(p = peer->call = sip_alloc(NULL, NULL, FALSE, SIP_OPTIONS)))
		return -1;
	
	p->sa = peer->addr;
	p->recv = peer->addr;
	ast_copy_flags(&p->flags[0], &peer->flags[0], SIP_FLAGS_TO_COPY);
	ast_copy_flags(&p->flags[1], &peer->flags[1], SIP_PAGE2_FLAGS_TO_COPY);

	/* Send OPTIONs to peer's fullcontact */
	if (!ast_strlen_zero(peer->fullcontact))
		ast_string_field_set(p, fullcontact, peer->fullcontact);

	if (!ast_strlen_zero(peer->tohost))
		ast_string_field_set(p, tohost, peer->tohost);
	else
		ast_string_field_set(p, tohost, ast_inet_ntoa(peer->addr.sin_addr));

	/* Recalculate our side, and recalculate Call ID */
	if (sip_ouraddrfor(&p->sa.sin_addr, &p->ourip))
		p->ourip = sipnet.__ourip;
	build_via(p, FALSE);
	build_callid_pvt(p);

	if (peer->pokeexpire > -1)
		ast_sched_del(sched, peer->pokeexpire);
	p->relatedpeer = peer;
	ast_set_flag(&p->flags[0], SIP_OUTGOING);
#ifdef VOCAL_DATA_HACK
	ast_copy_string(p->peername, "__VOCAL_DATA_SHOULD_READ_THE_SIP_SPEC__", sizeof(p->peername));
	transmit_invite(p, SIP_INVITE, FALSE, 2);
#else
	transmit_invite(p, SIP_OPTIONS, FALSE, 2);
#endif
	gettimeofday(&peer->ps, NULL);
	peer->pokeexpire = ast_sched_add(sched, DEFAULT_QUALIFY_MAXMS * 2, sip_poke_noanswer, peer);

	return 0;
}

/*! \brief Send a poke to all known peers 
	Space them out 100 ms apart
	XXX We might have a cool algorithm for this or use random - any suggestions?
*/
void sip_poke_all_peers(void)
{
	int ms = 0;
	
	if (!sipcounters.static_peers)	/* No peers, just give up */
		return;

	ASTOBJ_CONTAINER_TRAVERSE(&devicelist, 1, do {
		ASTOBJ_WRLOCK(iterator);
		if (iterator->pokeexpire > -1)
			ast_sched_del(sched, iterator->pokeexpire);
		ms += 100;
		iterator->pokeexpire = ast_sched_add(sched, ms, sip_poke_peer_s, iterator);
		ASTOBJ_UNLOCK(iterator);
	} while (0)
	);
}

