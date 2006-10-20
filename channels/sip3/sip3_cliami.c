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


/*! \brief Display SIP nat mode */
static const char *sip_nat_mode(const struct sip_pvt *p)
{
	return ast_test_flag(&p->flags[0], SIP_NAT) & SIP_NAT_ROUTE ? "NAT" : "no NAT";
}

/*! \brief Convert transfer mode to text string */
static char *transfermode2str(enum transfermodes mode)
{
	if (mode == TRANSFER_OPENFORALL)
		return "open";
	else if (mode == TRANSFER_CLOSED)
		return "closed";
	return "strict";
}

/*! \brief  Convert NAT setting to text string */
static char *nat2str(int nat)
{
	switch(nat) {
	case SIP_NAT_NEVER:
		return "No";
	case SIP_NAT_ROUTE:
		return "Route";
	case SIP_NAT_ALWAYS:
		return "Always";
	case SIP_NAT_RFC3581:
		return "RFC3581";
	default:
		return "Unknown";
	}
}

/*! \brief Convert DTMF mode to printable string */
static const char *dtmfmode2str(int mode)
{
	switch (mode) {
	case SIP_DTMF_RFC2833:
		return "rfc2833";
	case SIP_DTMF_INFO:
		return "info";
	case SIP_DTMF_INBAND:
		return "inband";
	case SIP_DTMF_AUTO:
		return "auto";
	}
	return "<error>";
}

/*! \brief Convert Insecure setting to printable string */
static const char *insecure2str(int port, int invite)
{
	if (port && invite)
		return "port,invite";
	else if (port)
		return "port";
	else if (invite)
		return "invite";
	else
		return "no";
}

/*! \brief Print codec list from preference to CLI/manager */
static void print_codec_to_cli(int fd, struct ast_codec_pref *pref)
{
	int x, codec;

	for(x = 0; x < 32 ; x++) {
		codec = ast_codec_pref_index(pref, x);
		if (!codec)
			break;
		ast_cli(fd, "%s", ast_getformatname(codec));
		ast_cli(fd, ":%d", pref->framing[x]);
		if (x < 31 && ast_codec_pref_index(pref, x + 1))
			ast_cli(fd, ",");
	}
	if (!x)
		ast_cli(fd, "none");
}

/*! \brief Print call group and pickup group */
static void  print_group(int fd, ast_group_t group, int crlf)
{
	char buf[256];
	ast_cli(fd, crlf ? "%s\r\n" : "%s\n", ast_print_group(buf, sizeof(buf), group) );
}

/*! \brief  Report Peer status in character string
 *  \return 0 if peer is unreachable, 1 if peer is online, -1 if unmonitored
 */
static int peer_status(struct sip_peer *peer, char *status, int statuslen)
{
	int res = 0;
	if (peer->maxms) {
		if (peer->lastms < 0) {
			ast_copy_string(status, "UNREACHABLE", statuslen);
		} else if (peer->lastms > peer->maxms) {
			snprintf(status, statuslen, "LAGGED (%d ms)", peer->lastms);
			res = 1;
		} else if (peer->lastms) {
			snprintf(status, statuslen, "OK (%d ms)", peer->lastms);
			res = 1;
		} else {
			ast_copy_string(status, "UNKNOWN", statuslen);
		}
	} else { 
		ast_copy_string(status, "Unmonitored", statuslen);
		/* Checking if port is 0 */
		res = -1;
	}
	return res;
}

/*! \brief  CLI Command to show calls within limits set by call_limit */
static int sip_show_inuse(int fd, int argc, char *argv[])
{
#define FORMAT  "%-25.25s %-15.15s %-15.15s \n"
#define FORMAT2 "%-25.25s %-15.15s %-15.15s \n"
	char ilimits[40];
	char iused[40];
	int showall = FALSE;

	if (argc < 3) 
		return RESULT_SHOWUSAGE;

	if (argc == 4 && !strcmp(argv[3],"all")) 
			showall = TRUE;
	
	ast_cli(fd, FORMAT, "* User name", "In use", "Limit");
	ASTOBJ_CONTAINER_TRAVERSE(&userl, 1, do {
		ASTOBJ_RDLOCK(iterator);
		if (iterator->call_limit)
			snprintf(ilimits, sizeof(ilimits), "%d", iterator->call_limit);
		else 
			ast_copy_string(ilimits, "N/A", sizeof(ilimits));
		snprintf(iused, sizeof(iused), "%d", iterator->inUse);
		if (showall || iterator->call_limit)
			ast_cli(fd, FORMAT2, iterator->name, iused, ilimits);
		ASTOBJ_UNLOCK(iterator);
	} while (0) );

	ast_cli(fd, FORMAT, "* Peer name", "In use", "Limit");

	ASTOBJ_CONTAINER_TRAVERSE(&devicelist, 1, do {
		ASTOBJ_RDLOCK(iterator);
		if (iterator->call_limit)
			snprintf(ilimits, sizeof(ilimits), "%d", iterator->call_limit);
		else 
			ast_copy_string(ilimits, "N/A", sizeof(ilimits));
		snprintf(iused, sizeof(iused), "%d/%d", iterator->inUse, iterator->inRinging);
		if (showall || iterator->call_limit)
			ast_cli(fd, FORMAT2, iterator->name, iused, ilimits);
		ASTOBJ_UNLOCK(iterator);
	} while (0) );

	return RESULT_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

/*! \brief  CLI Command 'SIP Show Users' */
static int sip_show_users(int fd, int argc, char *argv[])
{
	regex_t regexbuf;
	int havepattern = FALSE;

#define FORMAT  "%-25.25s  %-15.15s  %-15.15s  %-15.15s  %-5.5s%-10.10s\n"

	switch (argc) {
	case 5:
		if (!strcasecmp(argv[3], "like")) {
			if (regcomp(&regexbuf, argv[4], REG_EXTENDED | REG_NOSUB))
				return RESULT_SHOWUSAGE;
			havepattern = TRUE;
		} else
			return RESULT_SHOWUSAGE;
	case 3:
		break;
	default:
		return RESULT_SHOWUSAGE;
	}

	ast_cli(fd, FORMAT, "Username", "Secret", "Accountcode", "Def.Context", "ACL", "NAT");
	ASTOBJ_CONTAINER_TRAVERSE(&userl, 1, do {
		ASTOBJ_RDLOCK(iterator);

		if (havepattern && regexec(&regexbuf, iterator->name, 0, NULL, 0)) {
			ASTOBJ_UNLOCK(iterator);
			continue;
		}

		ast_cli(fd, FORMAT, iterator->name, 
			iterator->secret, 
			iterator->accountcode,
			iterator->context,
			iterator->ha ? "Yes" : "No",
			nat2str(ast_test_flag(&iterator->flags[0], SIP_NAT)));
		ASTOBJ_UNLOCK(iterator);
	} while (0)
	);

	if (havepattern)
		regfree(&regexbuf);

	return RESULT_SUCCESS;
#undef FORMAT
}

static char mandescr_show_peers[] = 
"Description: Lists SIP peers in text format with details on current status.\n"
"Variables: \n"
"  ActionID: <id>	Action ID for this transaction. Will be returned.\n";

/*! \brief  Show SIP peers in the manager API */
/*    Inspired from chan_iax2 */
static int manager_sip_show_peers( struct mansession *s, struct message *m )
{
	char *id = astman_get_header(m,"ActionID");
	char *a[] = { "sip3", "show", "peers" };
	char idtext[256] = "";
	int total = 0;

	if (!ast_strlen_zero(id))
		snprintf(idtext, sizeof(idtext), "ActionID: %s\r\n", id);

	astman_send_ack(s, m, "Peer status list will follow");
	/* List the peers in separate manager events */
	_sip_show_peers(-1, &total, s, m, 3, a);
	/* Send final confirmation */
	astman_append(s,
	"Event: PeerlistComplete\r\n"
	"ListItems: %d\r\n"
	"%s"
	"\r\n", total, idtext);
	return 0;
}

/*! \brief  CLI Show Peers command */
static int sip_show_peers(int fd, int argc, char *argv[])
{
	return _sip_show_peers(fd, NULL, NULL, NULL, argc, argv);
}

/*! \brief  _sip_show_peers: Execute sip show peers command */
static int _sip_show_peers(int fd, int *total, struct mansession *s, struct message *m, int argc, char *argv[])
{
	regex_t regexbuf;
	int havepattern = FALSE;

#define FORMAT2 "%-25.25s  %-15.15s %-3.3s %-3.3s %-3.3s %-8s %-10s %-10s\n"
#define FORMAT  "%-25.25s  %-15.15s %-3.3s %-3.3s %-3.3s %-8d %-10s %-10s\n"

	char name[256];
	int total_peers = 0;
	int peers_mon_online = 0;
	int peers_mon_offline = 0;
	int peers_unmon_offline = 0;
	int peers_unmon_online = 0;
	char *id;
	char idtext[256] = "";
	int realtimepeers;

	realtimepeers = ast_check_realtime("sippeers");

	if (s) {	/* Manager - get ActionID */
		id = astman_get_header(m,"ActionID");
		if (!ast_strlen_zero(id))
			snprintf(idtext, sizeof(idtext), "ActionID: %s\r\n", id);
	}

	switch (argc) {
	case 5:
		if (!strcasecmp(argv[3], "like")) {
			if (regcomp(&regexbuf, argv[4], REG_EXTENDED | REG_NOSUB))
				return RESULT_SHOWUSAGE;
			havepattern = TRUE;
		} else
			return RESULT_SHOWUSAGE;
	case 3:
		break;
	default:
		return RESULT_SHOWUSAGE;
	}

	if (!s) /* Normal list */
		ast_cli(fd, FORMAT2, "Name/username", "Host", "Dyn", "Nat", "ACL", "Port", "Status", (realtimepeers ? "Realtime" : ""));
	
	ASTOBJ_CONTAINER_TRAVERSE(&devicelist, 1, do {
		char status[20] = "";
		char srch[2000];
		char pstatus;
		
		ASTOBJ_RDLOCK(iterator);

		if (havepattern && regexec(&regexbuf, iterator->name, 0, NULL, 0)) {
			ASTOBJ_UNLOCK(iterator);
			continue;
		}

		if (!ast_strlen_zero(iterator->username) && !s)
			snprintf(name, sizeof(name), "%s/%s", iterator->name, iterator->username);
		else
			ast_copy_string(name, iterator->name, sizeof(name));
		
		pstatus = peer_status(iterator, status, sizeof(status));
		if (pstatus == 1)
			peers_mon_online++;
		else if (pstatus == 0)
			peers_mon_offline++;
		else {
			if (iterator->addr.sin_port == 0)
				peers_unmon_offline++;
			else
				peers_unmon_online++;
		}

		snprintf(srch, sizeof(srch), FORMAT, name,
			iterator->addr.sin_addr.s_addr ? ast_inet_ntoa(iterator->addr.sin_addr) : "(Unspecified)",
			ast_test_flag(&iterator->flags[1], SIP_PAGE2_DYNAMIC) ? " D " : "   ", 	/* Dynamic or not? */
			ast_test_flag(&iterator->flags[0], SIP_NAT_ROUTE) ? " N " : "   ",	/* NAT=yes? */
			iterator->ha ? " A " : "   ", 	/* permit/deny */
			ntohs(iterator->addr.sin_port), status,
			realtimepeers ? (ast_test_flag(&iterator->flags[0], SIP_REALTIME) ? "Cached RT":"") : "");

		if (!s)  {/* Normal CLI list */
			ast_cli(fd, FORMAT, name, 
			iterator->addr.sin_addr.s_addr ? ast_inet_ntoa(iterator->addr.sin_addr) : "(Unspecified)",
			ast_test_flag(&iterator->flags[1], SIP_PAGE2_DYNAMIC) ? " D " : "   ", 	/* Dynamic or not? */
			ast_test_flag(&iterator->flags[0], SIP_NAT_ROUTE) ? " N " : "   ",	/* NAT=yes? */
			iterator->ha ? " A " : "   ",       /* permit/deny */
			
			ntohs(iterator->addr.sin_port), status,
			realtimepeers ? (ast_test_flag(&iterator->flags[0], SIP_REALTIME) ? "Cached RT":"") : "");
		} else {	/* Manager format */
			/* The names here need to be the same as other channels */
			astman_append(s, 
			"Event: PeerEntry\r\n%s"
			"Channeltype: SIP\r\n"
			"ObjectName: %s\r\n"
			"ChanObjectType: peer\r\n"	/* "peer" or "user" */
			"IPaddress: %s\r\n"
			"IPport: %d\r\n"
			"Dynamic: %s\r\n"
			"Natsupport: %s\r\n"
			"VideoSupport: %s\r\n"
			"ACL: %s\r\n"
			"Status: %s\r\n"
			"RealtimeDevice: %s\r\n\r\n", 
			idtext,
			iterator->name, 
			iterator->addr.sin_addr.s_addr ? ast_inet_ntoa(iterator->addr.sin_addr) : "-none-",
			ntohs(iterator->addr.sin_port), 
			ast_test_flag(&iterator->flags[1], SIP_PAGE2_DYNAMIC) ? "yes" : "no", 	/* Dynamic or not? */
			ast_test_flag(&iterator->flags[0], SIP_NAT_ROUTE) ? "yes" : "no",	/* NAT=yes? */
			ast_test_flag(&iterator->flags[1], SIP_PAGE2_VIDEOSUPPORT) ? "yes" : "no",	/* VIDEOSUPPORT=yes? */
			iterator->ha ? "yes" : "no",       /* permit/deny */
			status,
			realtimepeers ? (ast_test_flag(&iterator->flags[0], SIP_REALTIME) ? "yes":"no") : "no");
		}

		ASTOBJ_UNLOCK(iterator);

		total_peers++;
	} while(0) );
	
	if (!s)
		ast_cli(fd, "%d sip peers [Monitored: %d online, %d offline Unmonitored: %d online, %d offline]\n",
		        total_peers, peers_mon_online, peers_mon_offline, peers_unmon_online, peers_unmon_offline);

	if (havepattern)
		regfree(&regexbuf);

	if (total)
		*total = total_peers;
	

	return RESULT_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

/*! \brief List all allocated SIP Objects (realtime or static) */
static int sip_show_objects(int fd, int argc, char *argv[])
{
	char tmp[256];
	if (argc != 3)
		return RESULT_SHOWUSAGE;
	ast_cli(fd, "-= User objects: %d static, %d realtime =-\n\n", sipcounters.static_users, sipcounters.realtime_users);
	ASTOBJ_CONTAINER_DUMP(fd, tmp, sizeof(tmp), &userl);
	ast_cli(fd, "-= Peer objects: %d static, %d realtime, %d autocreate =-\n\n", sipcounters.static_peers, sipcounters.realtime_peers, sipcounters.autocreated_peers);
	ASTOBJ_CONTAINER_DUMP(fd, tmp, sizeof(tmp), &devicelist);
	ast_cli(fd, "-= Registry objects: %d =-\n\n", sipcounters.registry_objects);
	ASTOBJ_CONTAINER_DUMP(fd, tmp, sizeof(tmp), &regl);
	return RESULT_SUCCESS;
}

static char mandescr_show_peer[] = 
"Description: Show one SIP peer with details on current status.\n"
"Variables: \n"
"  Peer: <name>           The peer name you want to check.\n"
"  ActionID: <id>	  Optional action ID for this AMI transaction.\n";

/*! \brief Show SIP peers in the manager API  */
static int manager_sip_show_peer( struct mansession *s, struct message *m)
{
	char *id = astman_get_header(m,"ActionID");
	char *a[4];
	char *peer;
	int ret;

	peer = astman_get_header(m,"Peer");
	if (ast_strlen_zero(peer)) {
		astman_send_error(s, m, "Peer: <name> missing.\n");
		return 0;
	}
	a[0] = "sip3";
	a[1] = "show";
	a[2] = "peer";
	a[3] = peer;

	if (!ast_strlen_zero(id))
		astman_append(s, "ActionID: %s\r\n",id);
	ret = _sip_show_peer(1, -1, s, m, 4, a );
	astman_append(s, "\r\n\r\n" );
	return ret;
}

/*! \brief Show one peer in detail */
static int sip_show_peer(int fd, int argc, char *argv[])
{
	return _sip_show_peer(0, fd, NULL, NULL, argc, argv);
}

/*! \brief Show one peer in detail (main function) */
static int _sip_show_peer(int type, int fd, struct mansession *s, struct message *m, int argc, char *argv[])
{
	char status[30] = "";
	char cbuf[256];
	struct sip_peer *peer;
	char codec_buf[512];
	struct ast_codec_pref *pref;
	struct ast_variable *v;
	struct sip_auth *auth;
	int x = 0, codec = 0, load_realtime;
	int realtimepeers;

	realtimepeers = ast_check_realtime("sippeers");

	if (argc < 4)
		return RESULT_SHOWUSAGE;

	load_realtime = (argc == 5 && !strcmp(argv[4], "load")) ? TRUE : FALSE;
	peer = find_peer(argv[3], NULL, load_realtime);
	if (s) { 	/* Manager */
		if (peer)
			astman_append(s, "Response: Success\r\n");
		else {
			snprintf (cbuf, sizeof(cbuf), "Peer %s not found.\n", argv[3]);
			astman_send_error(s, m, cbuf);
			return 0;
		}
	}
	if (peer && type==0 ) { /* Normal listing */
		ast_cli(fd,"\n\n");
		ast_cli(fd, "  * Name       : %s\n", peer->name);
		if (realtimepeers) {	/* Realtime is enabled */
			ast_cli(fd, "  Realtime peer: %s\n", ast_test_flag(&peer->flags[0], SIP_REALTIME) ? "Yes, cached" : "No");
		}
		ast_cli(fd, "  Secret       : %s\n", ast_strlen_zero(peer->secret)?"<Not set>":"<Set>");
		ast_cli(fd, "  MD5Secret    : %s\n", ast_strlen_zero(peer->md5secret)?"<Not set>":"<Set>");
		for (auth = peer->auth; auth; auth = auth->next) {
			ast_cli(fd, "  Realm-auth   : Realm %-15.15s User %-10.20s ", auth->realm, auth->username);
			ast_cli(fd, "%s\n", !ast_strlen_zero(auth->secret)?"<Secret set>":(!ast_strlen_zero(auth->md5secret)?"<MD5secret set>" : "<Not set>"));
		}
		ast_cli(fd, "  Context      : %s\n", peer->context);
		ast_cli(fd, "  Subscr.Cont. : %s\n", S_OR(peer->subscribecontext, "<Not set>") );
		ast_cli(fd, "  Language     : %s\n", peer->language);
		if (!ast_strlen_zero(peer->accountcode))
			ast_cli(fd, "  Accountcode  : %s\n", peer->accountcode);
		ast_cli(fd, "  AMA flags    : %s\n", ast_cdr_flags2str(peer->amaflags));
		ast_cli(fd, "  Transfer mode: %s\n", transfermode2str(peer->allowtransfer));
		ast_cli(fd, "  CallingPres  : %s\n", ast_describe_caller_presentation(peer->callingpres));
		if (!ast_strlen_zero(peer->fromuser))
			ast_cli(fd, "  FromUser     : %s\n", peer->fromuser);
		if (!ast_strlen_zero(peer->fromdomain))
			ast_cli(fd, "  FromDomain   : %s\n", peer->fromdomain);
		ast_cli(fd, "  Callgroup    : ");
		print_group(fd, peer->callgroup, 0);
		ast_cli(fd, "  Pickupgroup  : ");
		print_group(fd, peer->pickupgroup, 0);
		ast_cli(fd, "  Mailbox      : %s\n", peer->mailbox);
		ast_cli(fd, "  VM Extension : %s\n", peer->vmexten);
		ast_cli(fd, "  LastMsgsSent : %d\n", peer->lastmsgssent);
		ast_cli(fd, "  Call limit   : %d\n", peer->call_limit);
		ast_cli(fd, "  Dynamic      : %s\n", (ast_test_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC)?"Yes":"No"));
		ast_cli(fd, "  Callerid     : %s\n", ast_callerid_merge(cbuf, sizeof(cbuf), peer->cid_name, peer->cid_num, "<unspecified>"));
		ast_cli(fd, "  MaxCallBR    : %d kbps\n", peer->maxcallbitrate);
		ast_cli(fd, "  Expire       : %ld\n", ast_sched_when(sched, peer->expire));
		ast_cli(fd, "  Insecure     : %s\n", insecure2str(ast_test_flag(&peer->flags[0], SIP_INSECURE_PORT), ast_test_flag(&peer->flags[0], SIP_INSECURE_INVITE)));
		ast_cli(fd, "  Nat          : %s\n", nat2str(ast_test_flag(&peer->flags[0], SIP_NAT)));
		ast_cli(fd, "  ACL          : %s\n", (peer->ha?"Yes":"No"));
		ast_cli(fd, "  T38 pt UDPTL : %s\n", ast_test_flag(&peer->flags[1], SIP_PAGE2_T38SUPPORT_UDPTL)?"Yes":"No");
		ast_cli(fd, "  T38 pt RTP   : %s\n", ast_test_flag(&peer->flags[1], SIP_PAGE2_T38SUPPORT_RTP)?"Yes":"No");
		ast_cli(fd, "  T38 pt TCP   : %s\n", ast_test_flag(&peer->flags[1], SIP_PAGE2_T38SUPPORT_TCP)?"Yes":"No");
		ast_cli(fd, "  CanReinvite  : %s\n", ast_test_flag(&peer->flags[0], SIP_CAN_REINVITE)?"Yes":"No");
		ast_cli(fd, "  PromiscRedir : %s\n", ast_test_flag(&peer->flags[0], SIP_PROMISCREDIR)?"Yes":"No");
		ast_cli(fd, "  User=Phone   : %s\n", ast_test_flag(&peer->flags[0], SIP_USEREQPHONE)?"Yes":"No");
		ast_cli(fd, "  Video Support: %s\n", ast_test_flag(&peer->flags[1], SIP_PAGE2_VIDEOSUPPORT)?"Yes":"No");
		ast_cli(fd, "  Trust RPID   : %s\n", ast_test_flag(&peer->flags[0], SIP_TRUSTRPID) ? "Yes" : "No");
		ast_cli(fd, "  Send RPID    : %s\n", ast_test_flag(&peer->flags[0], SIP_SENDRPID) ? "Yes" : "No");
		ast_cli(fd, "  Subscriptions: %s\n", ast_test_flag(&peer->flags[1], SIP_PAGE2_ALLOWSUBSCRIBE) ? "Yes" : "No");
		ast_cli(fd, "  Overlap dial : %s\n", ast_test_flag(&peer->flags[1], SIP_PAGE2_ALLOWOVERLAP) ? "Yes" : "No");

		/* - is enumerated */
		ast_cli(fd, "  DTMFmode     : %s\n", dtmfmode2str(ast_test_flag(&peer->flags[0], SIP_DTMF)));
		ast_cli(fd, "  LastMsg      : %d\n", peer->lastmsg);
		ast_cli(fd, "  ToHost       : %s\n", peer->tohost);
		ast_cli(fd, "  Addr->IP     : %s Port %d\n",  peer->addr.sin_addr.s_addr ? ast_inet_ntoa(peer->addr.sin_addr) : "(Unspecified)", ntohs(peer->addr.sin_port));
		ast_cli(fd, "  Defaddr->IP  : %s Port %d\n", ast_inet_ntoa(peer->defaddr.sin_addr), ntohs(peer->defaddr.sin_port));
		if (!ast_strlen_zero(global.regcontext))
			ast_cli(fd, "  Reg. exten   : %s\n", peer->regexten);
		ast_cli(fd, "  Def. Username: %s\n", peer->username);
		ast_cli(fd, "  SIP Options  : ");
		if (peer->sipoptions) {
			sip_options_print(peer->sipoptions, fd);
		} else
			ast_cli(fd, "(none)");

		ast_cli(fd, "\n");
		ast_cli(fd, "  Codecs       : ");
		ast_getformatname_multiple(codec_buf, sizeof(codec_buf) -1, peer->capability);
		ast_cli(fd, "%s\n", codec_buf);
		ast_cli(fd, "  Codec Order  : (");
		print_codec_to_cli(fd, &peer->prefs);
		ast_cli(fd, ")\n");

		ast_cli(fd, "  Status       : ");
		peer_status(peer, status, sizeof(status));
		ast_cli(fd, "%s\n",status);
 		ast_cli(fd, "  Useragent    : %s\n", peer->useragent);
 		ast_cli(fd, "  Reg. Contact : %s\n", peer->fullcontact);
		if (peer->chanvars) {
 			ast_cli(fd, "  Variables    :\n");
			for (v = peer->chanvars ; v ; v = v->next)
 				ast_cli(fd, "                 %s = %s\n", v->name, v->value);
		}
		ast_cli(fd,"\n");
		ASTOBJ_UNREF(peer,sip_destroy_device);
	} else  if (peer && type == 1) { /* manager listing */
		char buf[256];
		astman_append(s, "Channeltype: SIP\r\n");
		astman_append(s, "ObjectName: %s\r\n", peer->name);
		astman_append(s, "ChanObjectType: peer\r\n");
		astman_append(s, "SecretExist: %s\r\n", ast_strlen_zero(peer->secret)?"N":"Y");
		astman_append(s, "MD5SecretExist: %s\r\n", ast_strlen_zero(peer->md5secret)?"N":"Y");
		astman_append(s, "Context: %s\r\n", peer->context);
		astman_append(s, "Language: %s\r\n", peer->language);
		if (!ast_strlen_zero(peer->accountcode))
			astman_append(s, "Accountcode: %s\r\n", peer->accountcode);
		astman_append(s, "AMAflags: %s\r\n", ast_cdr_flags2str(peer->amaflags));
		astman_append(s, "CID-CallingPres: %s\r\n", ast_describe_caller_presentation(peer->callingpres));
		if (!ast_strlen_zero(peer->fromuser))
			astman_append(s, "SIP-FromUser: %s\r\n", peer->fromuser);
		if (!ast_strlen_zero(peer->fromdomain))
			astman_append(s, "SIP-FromDomain: %s\r\n", peer->fromdomain);
		astman_append(s, "Callgroup: ");
		astman_append(s, "%s\r\n", ast_print_group(buf, sizeof(buf), peer->callgroup));
		astman_append(s, "Pickupgroup: ");
		astman_append(s, "%s\r\n", ast_print_group(buf, sizeof(buf), peer->pickupgroup));
		astman_append(s, "VoiceMailbox: %s\r\n", peer->mailbox);
		astman_append(s, "TransferMode: %s\r\n", transfermode2str(peer->allowtransfer));
		astman_append(s, "LastMsgsSent: %d\r\n", peer->lastmsgssent);
		astman_append(s, "Call limit: %d\r\n", peer->call_limit);
		astman_append(s, "MaxCallBR: %d kbps\r\n", peer->maxcallbitrate);
		astman_append(s, "Dynamic: %s\r\n", (ast_test_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC)?"Y":"N"));
		astman_append(s, "Callerid: %s\r\n", ast_callerid_merge(cbuf, sizeof(cbuf), peer->cid_name, peer->cid_num, ""));
		astman_append(s, "RegExpire: %ld seconds\r\n", ast_sched_when(sched,peer->expire));
		astman_append(s, "SIP-AuthInsecure: %s\r\n", insecure2str(ast_test_flag(&peer->flags[0], SIP_INSECURE_PORT), ast_test_flag(&peer->flags[0], SIP_INSECURE_INVITE)));
		astman_append(s, "SIP-NatSupport: %s\r\n", nat2str(ast_test_flag(&peer->flags[0], SIP_NAT)));
		astman_append(s, "ACL: %s\r\n", (peer->ha?"Y":"N"));
		astman_append(s, "SIP-CanReinvite: %s\r\n", (ast_test_flag(&peer->flags[0], SIP_CAN_REINVITE)?"Y":"N"));
		astman_append(s, "SIP-PromiscRedir: %s\r\n", (ast_test_flag(&peer->flags[0], SIP_PROMISCREDIR)?"Y":"N"));
		astman_append(s, "SIP-UserPhone: %s\r\n", (ast_test_flag(&peer->flags[0], SIP_USEREQPHONE)?"Y":"N"));
		astman_append(s, "SIP-VideoSupport: %s\r\n", (ast_test_flag(&peer->flags[1], SIP_PAGE2_VIDEOSUPPORT)?"Y":"N"));

		/* - is enumerated */
		astman_append(s, "SIP-DTMFmode: %s\r\n", dtmfmode2str(ast_test_flag(&peer->flags[0], SIP_DTMF)));
		astman_append(s, "SIPLastMsg: %d\r\n", peer->lastmsg);
		astman_append(s, "ToHost: %s\r\n", peer->tohost);
		astman_append(s, "Address-IP: %s\r\nAddress-Port: %d\r\n",  peer->addr.sin_addr.s_addr ? ast_inet_ntoa(peer->addr.sin_addr) : "", ntohs(peer->addr.sin_port));
		astman_append(s, "Default-addr-IP: %s\r\nDefault-addr-port: %d\r\n", ast_inet_ntoa(peer->defaddr.sin_addr), ntohs(peer->defaddr.sin_port));
		astman_append(s, "Default-Username: %s\r\n", peer->username);
		if (!ast_strlen_zero(global.regcontext))
			astman_append(s, "RegExtension: %s\r\n", peer->regexten);
		astman_append(s, "Codecs: ");
		ast_getformatname_multiple(codec_buf, sizeof(codec_buf) -1, peer->capability);
		astman_append(s, "%s\r\n", codec_buf);
		astman_append(s, "CodecOrder: ");
		pref = &peer->prefs;
		for(x = 0; x < 32 ; x++) {
			codec = ast_codec_pref_index(pref,x);
			if (!codec)
				break;
			astman_append(s, "%s", ast_getformatname(codec));
			if (x < 31 && ast_codec_pref_index(pref,x+1))
				astman_append(s, ",");
		}

		astman_append(s, "\r\n");
		astman_append(s, "Status: ");
		peer_status(peer, status, sizeof(status));
		astman_append(s, "%s\r\n", status);
 		astman_append(s, "SIP-Useragent: %s\r\n", peer->useragent);
 		astman_append(s, "Reg-Contact : %s\r\n", peer->fullcontact);
		if (peer->chanvars) {
			for (v = peer->chanvars ; v ; v = v->next) {
 				astman_append(s, "ChanVariable:\n");
 				astman_append(s, " %s,%s\r\n", v->name, v->value);
			}
		}

		ASTOBJ_UNREF(peer,sip_destroy_device);

	} else {
		ast_cli(fd,"Peer %s not found.\n", argv[3]);
		ast_cli(fd,"\n");
	}

	return RESULT_SUCCESS;
}

/*! \brief Show one user in detail */
static int sip_show_user(int fd, int argc, char *argv[])
{
	char cbuf[256];
	struct sip_peer *user;
	struct ast_variable *v;
	int load_realtime;

	if (argc < 4)
		return RESULT_SHOWUSAGE;

	/* Load from realtime storage? */
	load_realtime = (argc == 5 && !strcmp(argv[4], "load")) ? TRUE : FALSE;

	user = find_user(argv[3], load_realtime);
	if (user) {
		ast_cli(fd,"\n\n");
		ast_cli(fd, "  * Name       : %s\n", user->name);
		ast_cli(fd, "  Secret       : %s\n", ast_strlen_zero(user->secret)?"<Not set>":"<Set>");
		ast_cli(fd, "  MD5Secret    : %s\n", ast_strlen_zero(user->md5secret)?"<Not set>":"<Set>");
		ast_cli(fd, "  Context      : %s\n", user->context);
		ast_cli(fd, "  Language     : %s\n", user->language);
		if (!ast_strlen_zero(user->accountcode))
			ast_cli(fd, "  Accountcode  : %s\n", user->accountcode);
		ast_cli(fd, "  AMA flags    : %s\n", ast_cdr_flags2str(user->amaflags));
		ast_cli(fd, "  Transfer mode: %s\n", transfermode2str(user->allowtransfer));
		ast_cli(fd, "  MaxCallBR    : %d kbps\n", user->maxcallbitrate);
		ast_cli(fd, "  CallingPres  : %s\n", ast_describe_caller_presentation(user->callingpres));
		ast_cli(fd, "  Call limit   : %d\n", user->call_limit);
		ast_cli(fd, "  Callgroup    : ");
		print_group(fd, user->callgroup, 0);
		ast_cli(fd, "  Pickupgroup  : ");
		print_group(fd, user->pickupgroup, 0);
		ast_cli(fd, "  Callerid     : %s\n", ast_callerid_merge(cbuf, sizeof(cbuf), user->cid_name, user->cid_num, "<unspecified>"));
		ast_cli(fd, "  ACL          : %s\n", (user->ha?"Yes":"No"));
		ast_cli(fd, "  Codec Order  : (");
		print_codec_to_cli(fd, &user->prefs);
		ast_cli(fd, ")\n");

		if (user->chanvars) {
 			ast_cli(fd, "  Variables    :\n");
			for (v = user->chanvars ; v ; v = v->next)
 				ast_cli(fd, "                 %s = %s\n", v->name, v->value);
		}
		ast_cli(fd,"\n");
		ASTOBJ_UNREF(user,sip_destroy_device);
	} else {
		ast_cli(fd,"User %s not found.\n", argv[3]);
		ast_cli(fd,"\n");
	}

	return RESULT_SUCCESS;
}

/*! \brief  Show SIP Registry (registrations with other SIP proxies */
static int sip_show_registry(int fd, int argc, char *argv[])
{
#define FORMAT2 "%-30.30s  %-12.12s  %8.8s %-20.20s %-25.25s\n"
#define FORMAT  "%-30.30s  %-12.12s  %8d %-20.20s %-25.25s\n"
	char host[80];
	char tmpdat[256];
	struct tm tm;


	if (argc != 3)
		return RESULT_SHOWUSAGE;
	ast_cli(fd, FORMAT2, "Host", "Username", "Refresh", "State", "Reg.Time");
	ASTOBJ_CONTAINER_TRAVERSE(&regl, 1, do {
		ASTOBJ_RDLOCK(iterator);
		snprintf(host, sizeof(host), "%s:%d", iterator->hostname, iterator->portno ? iterator->portno : STANDARD_SIP_PORT);
		if (iterator->regtime) {
			ast_localtime(&iterator->regtime, &tm, NULL);
			strftime(tmpdat, sizeof(tmpdat), "%a, %d %b %Y %T", &tm);
		} else {
			tmpdat[0] = 0;
		}
		ast_cli(fd, FORMAT, host, iterator->username, iterator->refresh, regstate2str(iterator->regstate), tmpdat);
		ASTOBJ_UNLOCK(iterator);
	} while(0));
	return RESULT_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

/*! \brief List global settings for the SIP channel */
static int sip_show_settings(int fd, int argc, char *argv[])
{
	int realtimepeers;
	int realtimeusers;

	realtimepeers = ast_check_realtime("sip3peers");
	realtimeusers = ast_check_realtime("sip3users");

	if (argc != 3)
		return RESULT_SHOWUSAGE;
	ast_cli(fd, "\n\nGlobal Settings:\n");
	ast_cli(fd, "----------------\n");
	ast_cli(fd, "  SIP Port:               %d\n", ntohs(sipnet.bindaddr.sin_port));
	ast_cli(fd, "  Bindaddress:            %s\n", ast_inet_ntoa(sipnet.bindaddr.sin_addr));
	ast_cli(fd, "  Videosupport:           %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_VIDEOSUPPORT) ? "Yes" : "No");
	ast_cli(fd, "  AutoCreatePeer:         %s\n", global.autocreatepeer ? "Yes" : "No");
	ast_cli(fd, "  Allow unknown access:   %s\n", global.allowguest ? "Yes" : "No");
	ast_cli(fd, "  Allow subscriptions:    %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_ALLOWSUBSCRIBE) ? "Yes" : "No");
	ast_cli(fd, "  Allow overlap dialing:  %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_ALLOWOVERLAP) ? "Yes" : "No");
	ast_cli(fd, "  Promsic. redir:         %s\n", ast_test_flag(&global.flags[0], SIP_PROMISCREDIR) ? "Yes" : "No");
	ast_cli(fd, "  SIP domain support:     %s\n", domains_configured() ? "No" : "Yes");
	ast_cli(fd, "  Call to non-local dom.: %s\n", global.allow_external_domains ? "Yes" : "No");
	ast_cli(fd, "  URI user is phone no:   %s\n", ast_test_flag(&global.flags[0], SIP_USEREQPHONE) ? "Yes" : "No");
	ast_cli(fd, "  Our auth realm          %s\n", global.realm);
	ast_cli(fd, "  Realm. auth:            %s\n", authl ? "Yes": "No");
 	ast_cli(fd, "  Always auth rejects:    %s\n", global.alwaysauthreject ? "Yes" : "No");
	ast_cli(fd, "  User Agent:             %s\n", global.useragent);
	ast_cli(fd, "  MWI checking interval:  %d secs\n", global.mwitime);
	ast_cli(fd, "  Reg. context:           %s\n", S_OR(global.regcontext, "(not set)"));
	ast_cli(fd, "  Caller ID:              %s\n", global.default_callerid);
	ast_cli(fd, "  From: Domain:           %s\n", global.default_fromdomain);
	ast_cli(fd, "  Record SIP history:     %s\n", global.recordhistory ? "On" : "Off");
	ast_cli(fd, "  Call Events:            %s\n", global.callevents ? "On" : "Off");
	ast_cli(fd, "  IP ToS SIP:             %s\n", ast_tos2str(global.tos_sip));
	ast_cli(fd, "  IP ToS RTP audio:       %s\n", ast_tos2str(global.tos_audio));
	ast_cli(fd, "  IP ToS RTP video:       %s\n", ast_tos2str(global.tos_video));
	ast_cli(fd, "  IP ToS SIP presence:    %s\n", ast_tos2str(global.tos_presence));
	ast_cli(fd, "  T38 fax pt UDPTL:       %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_T38SUPPORT_UDPTL) ? "Yes" : "No");
	ast_cli(fd, "  T38 fax pt RTP:         %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_T38SUPPORT_RTP) ? "Yes" : "No");
	ast_cli(fd, "  T38 fax pt TCP:         %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_T38SUPPORT_TCP) ? "Yes" : "No");
	ast_cli(fd, "  RFC2833 Compensation:   %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_RFC2833_COMPENSATE) ? "Yes" : "No");
	ast_cli(fd, "  Jitterbuffer enabled:   %s\n", ast_test_flag(&global.jbconf, AST_JB_ENABLED) ? "Yes" : "No");
	ast_cli(fd, "  Jitterbuffer forced:    %s\n", ast_test_flag(&global.jbconf, AST_JB_FORCED) ? "Yes" : "No");
	ast_cli(fd, "  Jitterbuffer max size:  %ld\n", global.jbconf.max_size);
	ast_cli(fd, "  Jitterbuffer resync:    %ld\n", global.jbconf.resync_threshold);
	ast_cli(fd, "  Jitterbuffer impl:      %s\n", global.jbconf.impl);
	ast_cli(fd, "  Jitterbuffer log:       %s\n", ast_test_flag(&global.jbconf, AST_JB_LOG) ? "Yes" : "No");
	if (!realtimepeers && !realtimeusers)
		ast_cli(fd, "  SIP realtime:           Disabled\n" );
	else
		ast_cli(fd, "  SIP realtime:           Enabled\n" );

	ast_cli(fd, "\nGlobal Signalling Settings:\n");
	ast_cli(fd, "---------------------------\n");
	ast_cli(fd, "  Codecs:                 ");
	print_codec_to_cli(fd, &global.default_prefs);
	ast_cli(fd, "\n");
	ast_cli(fd, "  T1 minimum:             %d\n", global.t1min);
	ast_cli(fd, "  Relax DTMF:             %s\n", global.relaxdtmf ? "Yes" : "No");
	ast_cli(fd, "  Compact SIP headers:    %s\n", global.compactheaders ? "Yes" : "No");
	ast_cli(fd, "  RTP Timeout:            %d %s\n", global.rtptimeout, global.rtptimeout ? "" : "(Disabled)" );
	ast_cli(fd, "  RTP Hold Timeout:       %d %s\n", global.rtpholdtimeout, global.rtpholdtimeout ? "" : "(Disabled)");
	ast_cli(fd, "  MWI NOTIFY mime type:   %s\n", global.default_notifymime);
	ast_cli(fd, "  DNS SRV lookup:         %s\n", global.srvlookup ? "Yes" : "No");
	ast_cli(fd, "  Reg. min duration       %d secs\n", expiry.min_expiry);
	ast_cli(fd, "  Reg. max duration:      %d secs\n", expiry.max_expiry);
	ast_cli(fd, "  Reg. default duration:  %d secs\n", expiry.default_expiry);
	ast_cli(fd, "  Outbound reg. timeout:  %d secs\n", global.reg_timeout);
	ast_cli(fd, "  Outbound reg. attempts: %d\n", global.regattempts_max);
	ast_cli(fd, "  Notify ringing state:   %s\n", global.notifyringing ? "Yes" : "No");
	ast_cli(fd, "  SIP Transfer mode:      %s\n", transfermode2str(global.allowtransfer));
	ast_cli(fd, "  Max Call Bitrate:       %d kbps\r\n", global.default_maxcallbitrate);
	ast_cli(fd, "\nDefault Settings:\n");
	ast_cli(fd, "-----------------\n");
	ast_cli(fd, "  Context:                %s\n", global.default_context);
	ast_cli(fd, "  Nat:                    %s\n", nat2str(ast_test_flag(&global.flags[0], SIP_NAT)));
	ast_cli(fd, "  DTMF:                   %s\n", dtmfmode2str(ast_test_flag(&global.flags[0], SIP_DTMF)));
	ast_cli(fd, "  Qualify:                %d\n", global.default_qualify);
	ast_cli(fd, "  Qualify timer OK:       %d sec\n", global.default_qualifycheck_ok);
	ast_cli(fd, "  Qualify timer not OK:   %d sec\n", global.default_qualifycheck_notok);
	ast_cli(fd, "  Use ClientCode:         %s\n", ast_test_flag(&global.flags[0], SIP_USECLIENTCODE) ? "Yes" : "No");
	ast_cli(fd, "  Progress inband:        %s\n", (ast_test_flag(&global.flags[0], SIP_PROG_INBAND) == SIP_PROG_INBAND_NEVER) ? "Never" : (ast_test_flag(&global.flags[0], SIP_PROG_INBAND) == SIP_PROG_INBAND_NO) ? "No" : "Yes" );
	ast_cli(fd, "  Language:               %s\n", S_OR(global.default_language, "(Defaults to English)"));
	ast_cli(fd, "  MOH Interpret:          %s\n", global.default_mohinterpret);
	ast_cli(fd, "  MOH Suggest:            %s\n", global.default_mohsuggest);
	ast_cli(fd, "  Voice Mail Extension:   %s\n", global.default_vmexten);

	
	if (realtimepeers || realtimeusers) {
		ast_cli(fd, "\nRealtime SIP Settings:\n");
		ast_cli(fd, "----------------------\n");
		ast_cli(fd, "  Realtime Peers:         %s\n", realtimepeers ? "Yes" : "No");
		ast_cli(fd, "  Realtime Users:         %s\n", realtimeusers ? "Yes" : "No");
		ast_cli(fd, "  Cache Friends:          %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_RTCACHEFRIENDS) ? "Yes" : "No");
		ast_cli(fd, "  Update:                 %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_RTUPDATE) ? "Yes" : "No");
		ast_cli(fd, "  Ignore Reg. Expire:     %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_IGNOREREGEXPIRE) ? "Yes" : "No");
		ast_cli(fd, "  Save sys. name:         %s\n", ast_test_flag(&global.flags[1], SIP_PAGE2_RTSAVE_SYSNAME) ? "Yes" : "No");
		ast_cli(fd, "  Auto Clear:             %d\n", global.rtautoclear);
	}
	ast_cli(fd, "\n----\n");
	return RESULT_SUCCESS;
}
