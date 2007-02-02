/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2007, Digium, Inc.
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
 * \brief Various SIP configuration functions
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

#include "asterisk/channel.h"
#include "asterisk/cli.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/options.h"
#include "asterisk/lock.h"
#include "asterisk/acl.h"
#include "asterisk/callerid.h"
#include "asterisk/musiconhold.h"
#include "asterisk/manager.h"
#include "asterisk/dsp.h"
#include "asterisk/rtp.h"
#include "asterisk/srv.h"
#include "asterisk/causes.h"
#include "asterisk/utils.h"
#include "asterisk/file.h"
#include "asterisk/astobj.h"
#include "asterisk/dnsmgr.h"
#include "asterisk/linkedlists.h"
#include "asterisk/stringfields.h"
#include "asterisk/monitor.h"
#include "asterisk/localtime.h"
#include "asterisk/compiler.h"
#include "asterisk/version.h"
#include "sip3.h"
#include "sip3funcs.h"

static const char config[] = "sip3.conf";
const char notify_config[] = "sip3_notify.conf";

/*! \brief The configuration matrix */
/*	SIP_CONFOBJ_GENERAL		General section
	SIP_CONFOBJ_PHONE		Phone options
	SIP_CONFOBJ_SERVICE		Service options
	SIP_CONFOBJ_TRUNK		Trunk options
	SIP_CONFOBJ_DOMAIN		Configurations valid for domains 
	SIP_CONFOBJ_LINE		Phone, service and trunk (macro)
*/
static struct sip_config_struct sip_config[] = {
	{ SIP_CONF_NONE,	SIP_CONFCAT_MISC,	"",	0, 
	""},		/*!< Unknown */

	{ SIP_CONF_TYPE,	SIP_CONFCAT_MISC,	"type",	SIP_CONFOBJ_LINE,
	"Declares object type: phone, trunk, service or domain"},

	{ SIP_CONF_AUTOCREATEPEER,	SIP_CONFCAT_MISC,	"autocreatepeer" ,	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN, 
	"Enable this to support automatic creation of peers at registration time" },

	{ SIP_CONF_VMAILBOX,	SIP_CONFCAT_MISC,	"mailbox" ,	SIP_CONFOBJ_PHONE, 
	"One or multiple voicemail box identifiers, separated by &. Used for MWI messages. Syntax \"vmbox@vmcontext\"."},

	{ SIP_CONF_VMEXTEN,	SIP_CONFCAT_MISC,	"vmexten",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_PHONE | SIP_CONFOBJ_DOMAIN, 
	"Voicemailbox callback number that reach voicemailmain() in the dialplan"},

	{ SIP_CONF_DEFCONTEXT,	SIP_CONFCAT_MISC,	"context" ,	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	"Default context for incoming calls."},

	{ SIP_CONF_SUBSCRIBECONTEXT,	SIP_CONFCAT_MISC,	"subscribecontext",	SIP_CONFOBJ_PHONE , 
	"Context to use for subscriptions from this device."},

	{ SIP_CONF_CALLERID,	SIP_CONFCAT_MISC,	"callerid" ,	SIP_CONFOBJ_PHONE , 
	"Caller ID number and name. Syntax: \'Firstname Lastname <extension>\'"},

	{ SIP_CONF_CALLERPRES,	SIP_CONFCAT_MISC,	"callerpres" ,	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_TRUNK, 
	"Caller ID presentation flags."},

	{ SIP_CONF_CDR_ACCOUNTCODE,	SIP_CONFCAT_LINE,	"accountcode" ,	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_TRUNK, 
	"CDR accountcode for calls on this trunk or from this device."},

	{ SIP_CONF_SECRET,	SIP_CONFCAT_LINE,	"secret" ,	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_TRUNK, 
	"Authentication secret for inbound transactions."},

	{ SIP_CONF_REALM,	SIP_CONFCAT_MISC,	"realm" ,	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN, 
	"Authentication REALM for digest authentication" },

	{ SIP_CONF_USERAGENT,	SIP_CONFCAT_MISC,	"useragent" ,	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN, 
	"Useragent for this PBX. Defaults to \"Asterisk <version>\"" },

	{ SIP_CONF_MD5SECRET,	SIP_CONFCAT_LINE,	"md5secret",	SIP_CONFOBJ_PHONE, 
	"MD5 authentication string for authentication. Based on md5(username:realm:secret)"},

	{ SIP_CONF_ACCSECRET,	SIP_CONFCAT_MISC,	"accountsecret",	SIP_CONFOBJ_SERVICE, 
	"Our secret for authentication to service"},

	{ SIP_CONF_CHANVAR,	SIP_CONFCAT_LINE,	"chanvar" ,	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	"Dialplan channel variables set for incoming calls."},

	{ SIP_CONF_PERMIT,	SIP_CONFCAT_NETWORK,	"permit" ,	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	"ACL: IP address access control - access allowed for this IP range"},

	{ SIP_CONF_DENY,		SIP_CONFCAT_NETWORK,	"deny",		SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	"ACL: IP address access control - access denied for this IP range"},

	{ SIP_CONF_CALLGROUP,	SIP_CONFCAT_LINE,	"callgroup" ,	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_DOMAIN, 
	"Groups calls to this device belong to, for pickup (See pickupgroup) 0-63"},

	{ SIP_CONF_PICKUPGROUP,	SIP_CONFCAT_LINE,	"pickupgroup" ,	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_DOMAIN, 
	"Groups this device can pickup calls in. (See callgroup) 0-63"},

	{ SIP_CONF_GROUPVAR,	SIP_CONFCAT_LINE,	"changroup" ,	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_TRUNK | SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_DOMAIN , 
	"Channel group for calls from a device."},

	{ SIP_CONF_BINDADDR,	SIP_CONFCAT_NETWORK,	"bindaddr",	SIP_CONFOBJ_GENERAL, 
	"IP Address to bind SIP channel to"},

	{ SIP_CONF_BINDPORT,	SIP_CONFCAT_NETWORK,	"bindport",	SIP_CONFOBJ_GENERAL, 
	"IP Port to bind SIP channel to"},

	{ SIP_CONF_AUTH,	SIP_CONFCAT_LINE,	"auth",		SIP_CONFOBJ_PHONE | SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_DOMAIN | SIP_CONFOBJ_SERVICE , 
	"Realm based digest authentication. Syntax: \"auth = <username>:<secret>@<Realm>\""},

	{ SIP_CONF_SIPDEBUG,	SIP_CONFCAT_MISC,	"sipdebug",	SIP_CONFOBJ_GENERAL, 
	"Enable SIP debugging by default"},

	{ SIP_CONF_SIPDEBUGLEVEL,	SIP_CONFCAT_MISC,	"sipdebuglevel",	SIP_CONFOBJ_GENERAL, 
	"What to show in SIP debugging (ALL, CALLS, NO-OPTIONS"},

	{ SIP_CONF_HISTORYDUMP,	SIP_CONFCAT_MISC,	"dumphistory",	SIP_CONFOBJ_GENERAL, 
	"Dump SIP history at end of call to DEBUG channel"},

	{ SIP_CONF_HISTORYRECORD,	SIP_CONFCAT_MISC,	"siphistory",	SIP_CONFOBJ_GENERAL, 
	"Enable logging of SIP history for each dialog."},

	{ SIP_CONF_TRUSTRPID,	SIP_CONFCAT_LINE,	"trustrpid",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	"Use information in remote-party-id headers from this device or trunk"},

	{ SIP_CONF_SENDRPID,	SIP_CONFCAT_LINE,	"sendrpid",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN , 
	"Send Remote-Party-ID headers on calls to this device or trunk."},

	{ SIP_CONF_G726NONSTANDARD,	SIP_CONFCAT_MISC,	"g726nonstandard",	SIP_CONFOBJ_GENERAL , 
	""},

	{ SIP_CONF_USECLIENTCODE,	SIP_CONFCAT_MISC,	"useclientcode",	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_DOMAIN, 
	"Support for client code header on SNOM phones"},

	{ SIP_CONF_DTMFMODE,	SIP_CONFCAT_MISC,	"dtmfmode",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN | SIP_CONFOBJ_GENERAL, 
	"DTMF mode used for calls with this device (info, rfc2833, inband, auto)"},

	{ SIP_CONF_NAT,		SIP_CONFCAT_NAT,	"nat",		SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN | SIP_CONFOBJ_GENERAL , 
	"Nat support configuration"},

	{ SIP_CONF_CANREINVITE,	SIP_CONFCAT_NAT,	"canreinvite",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN | SIP_CONFOBJ_GENERAL , 
	"Whether this object supports SIP re-invites"},

	{ SIP_CONF_INSECURE,	SIP_CONFCAT_MISC,	"insecure",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN | SIP_CONFOBJ_GENERAL , 
	""},	/*! \todo Needs to go */

	{ SIP_CONF_PROGRESSINBAND,	SIP_CONFCAT_SIGNAL,	"progressinband",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN , 
	""},

	{ SIP_CONF_PROMISCREDIR,	SIP_CONFCAT_MISC,	"promiscredir",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN , 
	""},

	{ SIP_CONF_VIDEOSUPPORT,	SIP_CONFCAT_MISC,	"videosupport",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN , 
	""},

	{ SIP_CONF_ALLOWGUEST,		SIP_CONFCAT_SIGNAL,	"allowguest",	SIP_CONFOBJ_GENERAL , 
	""},
	{ SIP_CONF_ALLOWOVERLAP,	SIP_CONFCAT_SIGNAL,	"allowoverlap",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	""},
	{ SIP_CONF_ALLOWSUBSCRIBE,	SIP_CONFCAT_SIGNAL,	"allowsubscribe",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	""},
	{ SIP_CONF_ALLOWTRANSFER,	SIP_CONFCAT_SIGNAL,	"allowtransfer",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	""},
	{ SIP_CONF_ALLOWEXTERNALDOMAINS,	SIP_CONFCAT_SIGNAL,	"allowexternaldomains",	SIP_CONFOBJ_GENERAL , 
	""},
	{ SIP_CONF_T38PT_UDPTL,	SIP_CONFCAT_MISC,	"t38pt_udptl",	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN , 
	""},
	{ SIP_CONF_T38PT_TCP,	SIP_CONFCAT_MISC,	"t38pt_tcp",	SIP_CONFOBJ_NONE , 
	""},
	{ SIP_CONF_T38PT_RTP,	SIP_CONFCAT_MISC,	"t38pt_rtp",	SIP_CONFOBJ_NONE , 
	""},
	{ SIP_CONF_RFC2833COMPENSATE,	SIP_CONFCAT_MISC,	"rfc2833compensate",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, "RTP DTMF compensation (yes/no)"},
	{ SIP_CONF_DOMAIN,	SIP_CONFCAT_MISC,	"domain",	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN , 
	""},
	{ SIP_CONF_AUTHUSER,	SIP_CONFCAT_MISC,	"authuser",	SIP_CONFOBJ_SERVICE , 
	""},	/* User to use for authentication */
	{ SIP_CONF_CID_NAME,	SIP_CONFCAT_MISC,	"cid_name",	SIP_CONFOBJ_PHONE , 
	""},
	{ SIP_CONF_CID_NUMBER,	SIP_CONFCAT_MISC,	"cid_number",	SIP_CONFOBJ_PHONE , 
	""},
	{ SIP_CONF_USEREQPHONE,	SIP_CONFCAT_MISC,	"usereqphone",	SIP_CONFOBJ_ALL , 
	""},
	{ SIP_CONF_FROMDOMAIN,	SIP_CONFCAT_MISC,	"fromdomain",	SIP_CONFOBJ_SERVICE,
	"Domain part of From: SIP URI for connections to service"},
	{ SIP_CONF_FROMUSER,	SIP_CONFCAT_MISC,	"fromuser",	SIP_CONFOBJ_SERVICE,
	"User part of From: SIP URI for connections to service"},
	{ SIP_CONF_HOST,	SIP_CONFCAT_MISC,	"host",		SIP_CONFOBJ_PHONE | SIP_CONFOBJ_TRUNK,
	"Domain name, host name or IP address of remote host. \"dynamic\" if phone registers with us."},
	{ SIP_CONF_REGISTRAR,	SIP_CONFCAT_MISC,	"registrar",	SIP_CONFOBJ_SERVICE,
	"Registrar proxy server for service"},
	{ SIP_CONF_PROXY,	SIP_CONFCAT_MISC,	"proxy",	SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_TRUNK,
	"Proxy server for service"},
	{ SIP_CONF_OUTBOUNDPROXY,	SIP_CONFCAT_MISC,	"outboundproxy",	SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_TRUNK,
	"Outbound proxy"},
	{ SIP_CONF_DEFAULTIP,	SIP_CONFCAT_MISC,	"defaultip",	SIP_CONFOBJ_PHONE,
	"Default host name or IP address of phone that is not registred"},
	{ SIP_CONF_DEFAULTUSER,	SIP_CONFCAT_MISC,	"defaultuser",	SIP_CONFOBJ_PHONE,
	"Default user name part of URI to contact not registred device"},
	{ SIP_CONF_DEFAULTPORT,	SIP_CONFCAT_MISC,	"defaultport",	SIP_CONFOBJ_PHONE,
	"Port address to contact not registered device"},
	{ SIP_CONF_PROXYPORT,	SIP_CONFCAT_MISC,	"proxyport",	SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_TRUNK,
	"Proxy port address (disables DNS SRV)"},
	{ SIP_CONF_REGISTRARPORT,	SIP_CONFCAT_MISC,	"registrarport",	SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_TRUNK,
	"Registrar proxy port address"},
	{ SIP_CONF_OBPROXYPORT,	SIP_CONFCAT_MISC,	"outboundproxyport",	SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_TRUNK,
	"Outbound proxy port address"},
	{ SIP_CONF_LANGUAGE,	SIP_CONFCAT_MISC,	"language",	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_TRUNK | SIP_CONFOBJ_SERVICE | SIP_CONFOBJ_DOMAIN,
	"Default language for prompts"},
	{ SIP_CONF_REGEXTEN,	SIP_CONFCAT_MISC,	"regexten",	SIP_CONFOBJ_PHONE,
	"Enable extension at registration from device" },
	{ SIP_CONF_REGCONTEXT,	SIP_CONFCAT_MISC,	"regcontext",	SIP_CONFOBJ_GENERAL,
	"Context for regexten= extensions" },
	{ SIP_CONF_CALL_LIMIT,	SIP_CONFCAT_MISC,	"call-limit",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN,
	"Call limit for device or trunk line"},
	{ SIP_CONF_CALL_LIMIT,	SIP_CONFCAT_MISC,	"call_limit",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN,
	"Call limit for device or trunk line"},
	{ SIP_CONF_CDR_AMAFLAGS,	SIP_CONFCAT_MISC,	"amaflags",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN,
	"CDR AMA flags for incoming calls"},
	{ SIP_CONF_CDR_ACCOUNTCODE,	SIP_CONFCAT_MISC,	"accountcode",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN,
	"CDR accountcode for incoming calls"},
	{ SIP_CONF_MOHINTERPRET,	SIP_CONFCAT_MISC,	"mohinterpret",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN,
	""},
	{ SIP_CONF_MOHSUGGEST,	SIP_CONFCAT_MISC,	"mohsuggest",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN,
	""},
	{ SIP_CONF_MWISUBSCRIBE,	SIP_CONFCAT_MISC,	"subscribemwi",	SIP_CONFOBJ_PHONE | SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN,
	""},
	{ SIP_CONF_MWICHECK,	SIP_CONFCAT_MISC,	"checkmwi",	SIP_CONFOBJ_GENERAL, 
	""},

	{ SIP_CONF_DISALLOW,	SIP_CONFCAT_MISC,	"disallow",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN, 
	""},

	{ SIP_CONF_ALLOW,	SIP_CONFCAT_MISC,	"allow",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN, 
	""},

	{ SIP_CONF_AUTOFRAMING,	SIP_CONFCAT_MISC,	"autoframing",	SIP_CONFOBJ_ALL, 
	""},

	{ SIP_CONF_RTPTIMEOUT,	SIP_CONFCAT_MISC,	"rtptimeout",	SIP_CONFOBJ_ALL, 
	""},

	{ SIP_CONF_RTPHOLDTIMEOUT,	SIP_CONFCAT_MISC,	"rtpholdtimeout",	SIP_CONFOBJ_ALL, 
	""},

	{ SIP_CONF_RTPKEEPALIVE,	SIP_CONFCAT_MISC,	"rtpkeepalive",	SIP_CONFOBJ_ALL, 
	"NAT support: Send RTP keepalives"},

	{ SIP_CONF_SETVAR,	SIP_CONFCAT_MISC,	"setvar",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_DOMAIN, 
	"Configure channel variables to be set in channels created by the phone or on this trunk"},

	{ SIP_CONF_QUALIFY,	SIP_CONFCAT_MISC,	"qualify",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_DOMAIN, 
	""},

	{ SIP_CONF_MAXCALLBITRATE,	SIP_CONFCAT_MISC,	"maxcallbitrate",	SIP_CONFOBJ_ALL, 
	"Maximum bitrate for call (kbps), default 384"},

	{ SIP_CONF_REGISTER,	SIP_CONFCAT_MISC,	"register",	SIP_CONFOBJ_GENERAL | SIP_CONFOBJ_SERVICE, 
	""},	/* ??? NEEDED ANY MORE */

	{ SIP_CONF_RT_CACHEFRIENDS,	SIP_CONFCAT_REALTIME,	"rtcachefriends",	SIP_CONFOBJ_GENERAL, 
	"Realtime - cache realtime friends in memory"},

	{ SIP_CONF_RTSAVESYSTEMNAME,	SIP_CONFCAT_REALTIME,	"rtsavesysname",	SIP_CONFOBJ_GENERAL, 
	"Realtime - save system name in database at registration"},

	{ SIP_CONF_RTUPDATE,	SIP_CONFCAT_REALTIME,	"rtupdate",	SIP_CONFOBJ_GENERAL, 
	"Realtime - update database at registration"},

	{ SIP_CONF_IGNOREREGEXPIRE,	SIP_CONFCAT_REALTIME,	"ignoreregexpire",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_RTAUTOCLEAR,	SIP_CONFCAT_REALTIME,	"rtautoclear",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_MAXFORWARDS,	SIP_CONFCAT_MISC,	"maxforwards",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_T1MIN,	SIP_CONFCAT_MISC,	"t1min",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_T1DEFAULT,	SIP_CONFCAT_MISC,	"t1default",	SIP_CONFOBJ_GENERAL,
	"SIP Timer T1 - roundtrip time for packets. Used in calculations for retransmits."},
	{ SIP_CONF_T2DEFAULT,	SIP_CONFCAT_MISC,	"t2default",	SIP_CONFOBJ_GENERAL,
	"SIP Timer T2 - retransmit intervals for non-INIVTE requests"},
	{ SIP_CONF_T4DEFAULT,	SIP_CONFCAT_MISC,	"t4default",	SIP_CONFOBJ_GENERAL,
	"SIP Timer T4 - maximum time for handling NON-invite retransmits"},
	{ SIP_CONF_TIMER_B,	SIP_CONFCAT_MISC,	"siptimer_b",	SIP_CONFOBJ_GENERAL,
	"SIP Timer B - timeout for INVITE transactions" },
	{ SIP_CONF_TIMER_F,	SIP_CONFCAT_MISC,	"siptimer_f",	SIP_CONFOBJ_GENERAL,
	"SIP Timer F - timeout for non-INVITE transactions" },
	{ SIP_CONF_RELAXDTMF,	SIP_CONFCAT_MISC,	"relaxdtmf",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_COMPACTHEADERS,	SIP_CONFCAT_MISC,	"compactheaders",	SIP_CONFOBJ_LINE | SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_NOTIFYRINGING,	SIP_CONFCAT_MISC,	"notifyringing",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_NOTIFYHOLD,	SIP_CONFCAT_MISC,	"notifymime",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_NOTIFYHOLD,	SIP_CONFCAT_MISC,	"notifyhold",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_CALLEVENTS,	SIP_CONFCAT_MISC,	"callevents",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_ALWAYSAUTHREJECT,	SIP_CONFCAT_MISC,	"alwaysauthreject",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_SRVLOOKUP,	SIP_CONFCAT_MISC,	"srvlookup",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_EXPIRYMAX,		SIP_CONFCAT_MISC,	"maxexpiry",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_EXPIRYMIN,		SIP_CONFCAT_MISC,	"minexpiry",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_EXPIRYDEFAULT,	SIP_CONFCAT_MISC,	"defaultexpiry",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_REGISTERTIMEOUT,	SIP_CONFCAT_MISC,	"registertimeout",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_REGISTERATTEMPTS,	SIP_CONFCAT_MISC,	"registerattempts",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_LOCALNET,		SIP_CONFCAT_NAT,	"localnet",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_EXTERNIP,		SIP_CONFCAT_NAT,	"externip",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_EXTERNPORT,		SIP_CONFCAT_NAT,	"externport",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_EXTERNHOST,		SIP_CONFCAT_NAT,	"externhost",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_EXTERNREFRESH,	SIP_CONFCAT_NAT,	"externrefresh",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_AUTODOMAIN,	SIP_CONFCAT_MISC,	"autodomain",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_TOS_SIP,	SIP_CONFCAT_MISC,	"tos_sip",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_TOS_AUDIO,	SIP_CONFCAT_MISC,	"tos_audio",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_TOS_VIDEO,	SIP_CONFCAT_MISC,	"tos_video",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_TOS_PRESENSE,	SIP_CONFCAT_MISC,	"tos_presense",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_QUALIFY_TIMER_OK,	SIP_CONFCAT_MISC,	"qualify_timer_ok",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_QUALIFY_TIMER_NOT_OK,	SIP_CONFCAT_MISC,	"qualify_timer_not_ok",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_RTFULLCONTACT,	SIP_CONFCAT_REALTIME,	"fullcontact",	SIP_CONFOBJ_PHONE,
	""},
	{ SIP_CONF_RTREGSECONDS,	SIP_CONFCAT_REALTIME,	"regseconds	",	SIP_CONFOBJ_PHONE,
	""},	/* Only realtime */
	{ SIP_CONF_RTNAME,	SIP_CONFCAT_REALTIME,	"name",	SIP_CONFOBJ_PHONE,
	""},
	{ SIP_CONF_JBENABLE,	SIP_CONFCAT_JB,	"jbenable",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_JBFORCE,	SIP_CONFCAT_JB,	"jbforce",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_JBMAXSIZE,	SIP_CONFCAT_JB,	"jbmaxsize",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_JBRESYNC,	SIP_CONFCAT_JB,	"jbresynchtreshold",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_JBIMPL,	SIP_CONFCAT_JB,	"jbimpl",	SIP_CONFOBJ_GENERAL,
	""},
	{ SIP_CONF_JBLOG,	SIP_CONFCAT_JB,	"jblog",	SIP_CONFOBJ_GENERAL,
	""},
};

/*! \brief Global jitterbuffer configuration - by default, jb is disabled */
static struct ast_jb_conf default_jbconf =
{
        .flags = 0,
	.max_size = -1,
	.resync_threshold = -1,
	.impl = ""
};

/*! \brief Remove reference for device. When we reach 0, device is removed from memory */
void device_unref(struct sip_device *device)
{
	if (!device)
		return;

	if (option_debug > 3 && sipdebug)
		ast_log(LOG_DEBUG, "/// Removing reference from device %s - refcount now %d\n", device->name, device->refcount - 1);
	ASTOBJ_UNREF(device, sip_destroy_device);
}

/*! \brief Add reference for device. */
struct sip_device *device_ref(struct sip_device *device)
{
	ASTOBJ_REF(device);
	if (option_debug > 3 && sipdebug)
		ast_log(LOG_DEBUG, "/// Adding reference to device %s - refcount now %d\n", device->name, device->refcount);
	return device;
}

/*! \brief Parse configuration file label, check if it's valid in this 
     object context and return label */
static enum sip_config_options sip_config_parse(char *label, enum sip_config_objects object)
{
	int x;
	if (option_debug > 4)
		ast_log(LOG_DEBUG, "--Checking for configuration option: %s\n", label);
	

	for (x = 0; x < (sizeof(sip_config) / sizeof(struct sip_config_struct)); x++) {
		if (!strcasecmp(sip_config[x].label, label)) {
			if (sip_config[x].valid & object) {
				if (option_debug > 4)
					ast_log(LOG_DEBUG, "--Found valid configuration option: %s\n", label);
				return sip_config[x].option;
			} else
				return SIP_CONF_NOT_VALID_FOR_OBJECT;
		}
	};
	return SIP_CONF_NOT_FOUND;
}

/*! \brief * implement the servar config line */
static struct ast_variable *add_var(const char *buf, struct ast_variable *list)
{
	struct ast_variable *tmpvar = NULL;
	char *varname = ast_strdupa(buf), *varval = NULL;
	
	if ((varval = strchr(varname,'='))) {
		*varval++ = '\0';
		if ((tmpvar = ast_variable_new(varname, varval))) {
			tmpvar->next = list;
			list = tmpvar;
		}
	}
	return list;
}
/*! \brief Destroy disused contexts between reloads
	Only used in reload_config so the code for regcontext doesn't get ugly
*/
static void cleanup_stale_contexts(char *new, char *old)
{
	char *oldcontext, *newcontext, *stalecontext, *stringp, newlist[AST_MAX_CONTEXT];

	while ((oldcontext = strsep(&old, "&"))) {
		stalecontext = '\0';
		ast_copy_string(newlist, new, sizeof(newlist));
		stringp = newlist;
		while ((newcontext = strsep(&stringp, "&"))) {
			if (strcmp(newcontext, oldcontext) == 0) {
				/* This is not the context you're looking for */
				stalecontext = '\0';
				break;
			} else if (strcmp(newcontext, oldcontext)) {
				stalecontext = oldcontext;
			}
			
		}
		if (stalecontext)
			ast_context_destroy(ast_context_find(stalecontext), "SIP");
	}
}

/*!
  \brief Handle flag-type options common to configuration of devices - users and peers
  \param flags array of two struct ast_flags
  \param mask array of two struct ast_flags
  \param v linked list of config variables to process
  \returns non-zero if any config options were handled, zero otherwise
*/
static int handle_common_options(enum sip_config_options option, struct ast_flags *flags, struct ast_flags *mask, struct ast_variable *v)
{
	int error = 0;	/* Number of errors */

	switch (option) {
	case SIP_CONF_TRUSTRPID:
		ast_set_flag(&mask[0], SIP_TRUSTRPID);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_TRUSTRPID);
		break;
	case SIP_CONF_SENDRPID:
		ast_set_flag(&mask[0], SIP_SENDRPID);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_SENDRPID);
		break;
	case SIP_CONF_G726NONSTANDARD:
		ast_set_flag(&mask[0], SIP_G726_NONSTANDARD);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_G726_NONSTANDARD);
		break;
	case SIP_CONF_USECLIENTCODE:
		ast_set_flag(&mask[0], SIP_USECLIENTCODE);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_USECLIENTCODE);
		break;
	case SIP_CONF_DTMFMODE:
		ast_set_flag(&mask[0], SIP_DTMF);
		ast_clear_flag(&flags[0], SIP_DTMF);
		if (!strcasecmp(v->value, "inband"))
			ast_set_flag(&flags[0], SIP_DTMF_INBAND);
		else if (!strcasecmp(v->value, "rfc2833"))
			ast_set_flag(&flags[0], SIP_DTMF_RFC2833);
		else if (!strcasecmp(v->value, "info"))
			ast_set_flag(&flags[0], SIP_DTMF_INFO);
		else if (!strcasecmp(v->value, "auto"))
			ast_set_flag(&flags[0], SIP_DTMF_AUTO);
		else {
			ast_log(LOG_WARNING, "Unknown dtmf mode '%s' on line %d, using rfc2833\n", v->value, v->lineno);
			error++;
			ast_set_flag(&flags[0], SIP_DTMF_RFC2833);
		}
		break;
	case SIP_CONF_NAT:
		ast_set_flag(&mask[0], SIP_NAT);
		ast_clear_flag(&flags[0], SIP_NAT);
		if (!strcasecmp(v->value, "never"))
			ast_set_flag(&flags[0], SIP_NAT_NEVER);
		else if (!strcasecmp(v->value, "route"))
			ast_set_flag(&flags[0], SIP_NAT_ROUTE);
		else if (ast_true(v->value))
			ast_set_flag(&flags[0], SIP_NAT_ALWAYS);
		else
			ast_set_flag(&flags[0], SIP_NAT_RFC3581);
		break;
	case SIP_CONF_CANREINVITE:
		ast_set_flag(&mask[0], SIP_REINVITE);
		ast_clear_flag(&flags[0], SIP_REINVITE);
		if (ast_true(v->value)) {
			ast_set_flag(&flags[0], SIP_CAN_REINVITE | SIP_CAN_REINVITE_NAT);
		} else if (!ast_false(v->value)) {
			char buf[64];
			char *word, *next = buf;

			ast_copy_string(buf, v->value, sizeof(buf));
			while ((word = strsep(&next, ","))) {
				if (!strcasecmp(word, "update")) {
					ast_set_flag(&flags[0], SIP_REINVITE_UPDATE | SIP_CAN_REINVITE);
				} else if (!strcasecmp(word, "nonat")) {
					ast_set_flag(&flags[0], SIP_CAN_REINVITE);
					ast_clear_flag(&flags[0], SIP_CAN_REINVITE_NAT);
				} else {
					ast_log(LOG_WARNING, "Unknown canreinvite mode '%s' on line %d\n", v->value, v->lineno);
					error++;
				}
			}
		}
		break;
	case SIP_CONF_INSECURE:
		ast_set_flag(&mask[0], SIP_INSECURE_PORT | SIP_INSECURE_INVITE);
		ast_clear_flag(&flags[0], SIP_INSECURE_PORT | SIP_INSECURE_INVITE);
		if (!ast_false(v->value)) {
			char buf[64];
			char *word, *next;

			ast_copy_string(buf, v->value, sizeof(buf));
			next = buf;
			while ((word = strsep(&next, ","))) {
				if (!strcasecmp(word, "port"))
					ast_set_flag(&flags[0], SIP_INSECURE_PORT);
				else if (!strcasecmp(word, "invite"))
					ast_set_flag(&flags[0], SIP_INSECURE_INVITE);
				else
					ast_log(LOG_WARNING, "Unknown insecure mode '%s' on line %d\n", v->value, v->lineno);
					error++;
			}
		}
		break;
	case SIP_CONF_PROGRESSINBAND:
		ast_set_flag(&mask[0], SIP_PROG_INBAND);
		ast_clear_flag(&flags[0], SIP_PROG_INBAND);
		if (ast_true(v->value))
			ast_set_flag(&flags[0], SIP_PROG_INBAND_YES);
		else if (strcasecmp(v->value, "never"))
			ast_set_flag(&flags[0], SIP_PROG_INBAND_NO);
		break;
	case SIP_CONF_COMPACTHEADERS:
		ast_set_flag(&mask[1], SIP_PAGE2_COMPACTHEADERS);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_COMPACTHEADERS);
		break;
	case SIP_CONF_PROMISCREDIR:
		ast_set_flag(&mask[0], SIP_PROMISCREDIR);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_PROMISCREDIR);
		break;
	case SIP_CONF_VIDEOSUPPORT:
		ast_set_flag(&mask[1], SIP_PAGE2_VIDEOSUPPORT);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_VIDEOSUPPORT);
		break;
	case SIP_CONF_ALLOWOVERLAP:
		ast_set_flag(&mask[1], SIP_PAGE2_ALLOWOVERLAP);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_ALLOWOVERLAP);
		break;
	case SIP_CONF_ALLOWSUBSCRIBE:
		ast_set_flag(&mask[1], SIP_PAGE2_ALLOWSUBSCRIBE);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_ALLOWSUBSCRIBE);
		break;
	case SIP_CONF_T38PT_UDPTL:
		ast_set_flag(&mask[1], SIP_PAGE2_T38SUPPORT_UDPTL);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_UDPTL);
		break;
	case SIP_CONF_T38PT_RTP:
		ast_set_flag(&mask[1], SIP_PAGE2_T38SUPPORT_RTP);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_RTP);
		break;
	case SIP_CONF_T38PT_TCP:
		ast_set_flag(&mask[1], SIP_PAGE2_T38SUPPORT_TCP);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_TCP);
		break;
	case SIP_CONF_RFC2833COMPENSATE:
		ast_set_flag(&mask[1], SIP_PAGE2_RFC2833_COMPENSATE);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_RFC2833_COMPENSATE);
		break;
	default:
		/* We should not come here, unless it's a source code error.
			Makes the compiler happy to have a default, since
			we're basing the case on an enum.
		*/
		break;
	}

	return error;
}

/*! \brief Set peer defaults before configuring specific configurations */
void set_device_defaults(struct sip_device *device)
{
	if (device->expire == 0) {
		/* Don't reset expire or port time during reload 
		   if we have an active registration 
		*/
		device->expire = -1;
		device->pokeexpire = -1;
		device->addr.sin_port = htons(STANDARD_SIP_PORT);
	}
	ast_copy_flags(&device->flags[0], &global.flags[0], SIP_FLAGS_TO_COPY);
	ast_copy_flags(&device->flags[1], &global.flags[1], SIP_PAGE2_FLAGS_TO_COPY);

	ast_string_field_set(&device->extra, context, global.default_context);
	ast_string_field_set(&device->extra, subscribecontext, global.default_subscribecontext);
	strcpy(device->language, global.default_language);
	strcpy(device->extra.mohinterpret, global.default_mohinterpret);
	strcpy(device->extra.mohsuggest, global.default_mohsuggest);
	device->addr.sin_family = AF_INET;
	device->defaddr.sin_family = AF_INET;
	device->capability = global.capability;
	device->rtptimer.rtptimeout = global.rtptimer.rtptimeout;
	device->rtptimer.rtpholdtimeout = global.rtptimer.rtpholdtimeout;
	device->rtptimer.rtpkeepalive = global.rtptimer.rtpkeepalive;
	device->maxcallbitrate = global.default_maxcallbitrate;
	ast_string_field_set(device, secret, "");
	ast_string_field_set(device, md5secret, "");
	ast_string_field_set(device, extra.fromdomain, "");
	ast_string_field_set(device, extra.fromuser, "");
	ast_string_field_set(device, extra.regexten, "");
	device->extra.cid_num[0] = '\0';
	device->extra.cid_name[0] = '\0';
	device->callgroup = 0;
	device->pickupgroup = 0;
	device->allowtransfer = global.allowtransfer;
	device->maxms = global.default_qualify;
	device->prefs = global.default_prefs;
	ast_string_field_set(device, mailbox.vmexten, global.default_vmexten);
	ast_string_field_set(device, mailbox.mailbox, "");
}

/*! \brief Set Caller ID for phone or service */
static void set_device_cid(struct sip_device *device, enum sip_config_options option, struct ast_variable *v)
{
	switch (option) {
	case SIP_CONF_CID_NAME:
		ast_copy_string(device->extra.cid_name, v->value, sizeof(device->extra.cid_name));
		break;
	case SIP_CONF_CID_NUMBER:
		ast_copy_string(device->extra.cid_num, v->value, sizeof(device->extra.cid_num));
		break;
	default: 
		ast_callerid_split(v->value, device->extra.cid_name, sizeof(device->extra.cid_name), device->extra.cid_num, sizeof(device->extra.cid_num));
		break;
	}
}

/*! \brief Configure Host= setting for device */
static void set_device_host(struct sip_device *device, struct ast_variable *v, int found, enum sip_config_objects object)
{
	
	if (option_debug > 4)
		ast_log(LOG_DEBUG, "--Configuring device %s - Host config value %s\n", device->name, v->value);
	if (object == SIP_CONFOBJ_PHONE && !strcasecmp(v->value, "dynamic")) {
		if (option_debug > 4)
			ast_log(LOG_DEBUG, "--Dynamic host enabled (sip device registering with us)\n");
		/* They'll register with us */
		ast_set_flag(&device->flags[1], SIP_PAGE2_DYNAMIC);
		if (!found) {
			/* Initialize stuff if we're not found, otherwise we keep going with what we had */
			memset(&device->addr.sin_addr, 0, 4);
			if (device->addr.sin_port) {
				/* If we've already got a port, make it the default rather than absolute */
				device->defaddr.sin_port = device->addr.sin_port;
				device->addr.sin_port = 0;
			}
		}
	} else {
		/* Non-dynamic.  Make sure we become that way if we're not */
		if (device->expire > -1)
			ast_sched_del(sched, device->expire);
		device->expire = -1;
		ast_clear_flag(&device->flags[1], SIP_PAGE2_DYNAMIC);
		ast_copy_string(device->extra.tohost, v->value, sizeof(device->extra.tohost));
		if (!device->addr.sin_port)
				device->addr.sin_port = htons(STANDARD_SIP_PORT);
	}
}

/*! \brief Add ACL entry (permit/deny) to device */
static int set_device_acl(struct sip_device *device, struct ast_variable *v)
{
	int ha_error = 0;

	device->ha = ast_append_ha(v->name, v->value, device->ha, &ha_error);
	return ha_error;
}


/*! \brief Build peer from configuration (file or realtime static/dynamic) */
static struct sip_device *build_device(const char *name, struct ast_variable *v, struct ast_variable *alt, int realtime)
{
	struct sip_device *device = NULL;
	struct ast_ha *oldha = NULL;
	int found = 0;
	int firstpass = 1;
	int format = 0;		/* Ama flags */
	time_t regseconds = 0;
	struct ast_flags peerflags[2] = {{(0)}};
	struct ast_flags mask[2] = {{(0)}};
	int register_lineno = 0;
	int error = 0;

	if (!realtime)
		/* Note we do NOT use find_peer here, to avoid realtime recursion */
		/* We also use a case-sensitive comparison (unlike find_peer) so
		   that case changes made to the peer name will be properly handled
		   during reload
		*/
		device = ASTOBJ_CONTAINER_FIND_UNLINK_FULL(&devicelist, name, name, 0, 0, strcmp);

	if (device) {
		/* Already in the list, remove it and it will be added back (or FREE'd)  */
		found++;
		if (!(device->objflags & ASTOBJ_FLAG_MARKED))
			firstpass = 0;
 	} else {
		if (!(device = ast_calloc(1, sizeof(*device))))
			return NULL;

		if (ast_string_field_init(device, 512)) {	/* Initialize string field buffer */
			free(device);
			return NULL;
		}
		if (ast_string_field_init(&device->mailbox, 512)) {	/* Initialize string field buffer */
			free(device);
			return NULL;
		}
		if (ast_string_field_init(&device->extra, 512)) {	/* Initialize string field buffer */
			free(device);
			return NULL;
		}

		if (realtime)
			sipcounters.realtime_peers++;
		else
			sipcounters.static_peers++;
		ASTOBJ_INIT(device);
	}
	device->type &= SIP_PEER;

	/* Note that our peer HAS had its reference count incrased */

	if (firstpass) {
		device->mailbox.lastmsgssent = -1;
		oldha = device->ha;
		device->ha = NULL;
		set_device_defaults(device);	/* Set peer defaults */
	}
	if (!found && name)
		ast_copy_string(device->name, name, sizeof(device->name));

	/* If we have channel variables, remove them (reload) */
	if (device->chanvars) {
		ast_variables_destroy(device->chanvars);
		device->chanvars = NULL;
		/* XXX should unregister ? */
	}
	for (; v || ((v = alt) && !(alt=NULL)); v = v->next) {
		enum sip_config_options option = sip_config_parse(v->name, SIP_CONFOBJ_PHONE);
		switch (option) {
		case SIP_CONF_TYPE:
			/* Ignore this, it's already parsed */
			break;
		case SIP_CONF_TRUSTRPID:
		case SIP_CONF_SENDRPID:
		case SIP_CONF_G726NONSTANDARD:
		case SIP_CONF_USECLIENTCODE:
		case SIP_CONF_DTMFMODE:
		case SIP_CONF_NAT:
		case SIP_CONF_CANREINVITE:
		case SIP_CONF_INSECURE:
		case SIP_CONF_PROGRESSINBAND:
		case SIP_CONF_PROMISCREDIR:
		case SIP_CONF_VIDEOSUPPORT:
		case SIP_CONF_ALLOWOVERLAP:
		case SIP_CONF_ALLOWSUBSCRIBE:
		case SIP_CONF_T38PT_UDPTL:
		case SIP_CONF_RFC2833COMPENSATE:
		case SIP_CONF_COMPACTHEADERS:
			error += handle_common_options(option, &peerflags[0], &mask[0], v);
			break;
		case SIP_CONF_ALLOW:
			error += ast_parse_allow_disallow(&device->prefs, &device->capability, v->value, 1);
			break;
		case SIP_CONF_ALLOWTRANSFER:
			device->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
			break;
		case SIP_CONF_AUTH:
			device->auth = add_realm_authentication(device->auth, v->value, v->lineno);
			break;
		case SIP_CONF_AUTHUSER:
			ast_string_field_set(device, authuser, v->value);
			break;
		case SIP_CONF_AUTOFRAMING:
			device->autoframing = ast_true(v->value);
			break;
		case SIP_CONF_CALLERID:
		case SIP_CONF_CID_NAME:
		case SIP_CONF_CID_NUMBER:
			set_device_cid(device, option, v);
			break;
		case SIP_CONF_CALLERPRES:
			device->callingpres = ast_parse_caller_presentation(v->value);
			if (device->callingpres == -1)
				device->callingpres = atoi(v->value);
			break;
		case SIP_CONF_CALLGROUP:
			device->callgroup = ast_get_group(v->value);
			break;
		case SIP_CONF_CALL_LIMIT:
			device->call_limit = atoi(v->value);
			if (device->call_limit < 0)
				device->call_limit = 0;
			break;
		case SIP_CONF_CDR_ACCOUNTCODE:
			ast_copy_string(device->extra.accountcode, v->value, sizeof(device->extra.accountcode));
			break;
		case SIP_CONF_CDR_AMAFLAGS:
			format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Invalid AMA Flags for peer: %s at line %d\n", v->value, v->lineno);
				error++;
			} else 
				device->extra.amaflags = format;
			break;
		case SIP_CONF_CHANVAR:
			break;
		case SIP_CONF_DEFAULTIP:
			if (ast_get_ip(&device->defaddr, v->value))  {
				ast_log(LOG_WARNING, "Default IP ignored, bad/unparseable value: %s\n", v->value);
				error++;
			}
			break;
		case SIP_CONF_DEFAULTUSER:
			ast_string_field_set(device, defaultuser, v->value);
			break;
		case SIP_CONF_DEFAULTPORT:
			device->defaddr.sin_port = htons(atoi(v->value));
			break;
		case SIP_CONF_DEFCONTEXT:
			ast_string_field_set(&device->extra, context, v->value);
			break;
		case SIP_CONF_DENY:
			if(set_device_acl(device, v) != 0) {
				ast_log(LOG_WARNING, "Bad DENY setting in sip.conf line %d : %s\n", v->lineno, v->value);
				error++;
			}
			break;
		case SIP_CONF_DISALLOW:
			error += ast_parse_allow_disallow(&device->prefs, &device->capability, v->value, FALSE);
			break;
		case SIP_CONF_DOMAIN:
			ast_copy_string(device->domain, v->value, sizeof(device->domain));
			break;
		case SIP_CONF_GROUPDESC:
			break;
		case SIP_CONF_GROUPVAR:
			break;
		case SIP_CONF_HOST:
			set_device_host(device, v, found, SIP_CONFOBJ_PHONE);
			break;
		case SIP_CONF_LANGUAGE:
			ast_copy_string(device->language, v->value, sizeof(device->language));
			break;
		case SIP_CONF_LOCALNET:
			break;
		case SIP_CONF_MAXCALLBITRATE:
			device->maxcallbitrate = atoi(v->value);
			if (device->maxcallbitrate < 0) {
				device->maxcallbitrate = global.default_maxcallbitrate;
				ast_log(LOG_WARNING, "Max call bitrate setting of device '%s' out of bonds (line %d)\n", device->name, v->lineno);
				error++;
			}
			break;
		case SIP_CONF_EXPIRYMAX:
			break;
		case SIP_CONF_MD5SECRET:
			ast_string_field_set(device, md5secret, v->value);
			break;
		case SIP_CONF_MOHINTERPRET:
			ast_copy_string(device->extra.mohinterpret, v->value, sizeof(device->extra.mohinterpret));
			break;
		case SIP_CONF_MOHSUGGEST:
			ast_copy_string(device->extra.mohsuggest, v->value, sizeof(device->extra.mohsuggest));
			break;
		case SIP_CONF_OUTBOUNDPROXY:
			break;
		case SIP_CONF_OBPROXYPORT:
			break;
		case SIP_CONF_PERMIT:
			if(set_device_acl(device, v) != 0) {
				ast_log(LOG_WARNING, "Bad PERMIT setting in sip.conf line %d : %s\n", v->lineno, v->value);
				error++;
			}
			break;
		case SIP_CONF_PICKUPGROUP:
			device->pickupgroup = ast_get_group(v->value);
			break;
		case SIP_CONF_PORT:
			device->addr.sin_port = htons(atoi(v->value));
			break;
		case SIP_CONF_PROXY:
			break;
		case SIP_CONF_PROXYPORT:
			break;
		case SIP_CONF_QUALIFY:
			if (!strcasecmp(v->value, "no")) {
				device->maxms = 0;
			} else if (!strcasecmp(v->value, "yes")) {
				device->maxms = DEFAULT_QUALIFY_MAXMS;
			} else if (sscanf(v->value, "%d", &device->maxms) != 1) {
				ast_log(LOG_WARNING, "Qualification of device '%s' should be 'yes', 'no', or a number of milliseconds at line %d of sip.conf\n", device->name, v->lineno);
				error++;
				device->maxms = 0;
			}
			break;
		case SIP_CONF_REGEXTEN:
			ast_string_field_set(device, extra.regexten, v->value);
			break;
		case SIP_CONF_REGISTER:
			if (ast_true(v->value)) {
				if (realtime) {
					ast_log(LOG_ERROR, "register=yes is not supported for realtime.\n");
				} else {
					ast_set_flag(&device->flags[1], SIP_PAGE2_SERVICE);
					register_lineno = v->lineno;
				}
			} else if (!ast_false(v->value)) {
				ast_log(LOG_ERROR, "Bad value for register= in line %d, device %s\n", v->lineno, device->name);
				error++;
			}
			break;
		case SIP_CONF_REGISTERTIMEOUT:
			break;
		case SIP_CONF_RTAUTOCLEAR:
			break;
		case SIP_CONF_IGNOREREGEXPIRE:
			break;
		case SIP_CONF_RTIPADDR:		/* Realtime only */
			if(realtime && !ast_strlen_zero(v->value)) 
				inet_aton(v->value, &(device->addr.sin_addr));
			break;
		case SIP_CONF_RTNAME:		/* Realtime only */
			if(realtime && !ast_strlen_zero(v->value)) 
				ast_copy_string(device->name, v->value, sizeof(device->name));
			break;
		case SIP_CONF_RTREGSECONDS:	/* REALTIME */
			ast_get_time_t(v->value, &regseconds, 0, NULL);
			break;
		case SIP_CONF_RTPHOLDTIMEOUT:
			if ((sscanf(v->value, "%d", &device->rtptimer.rtpholdtimeout) != 1) || (device->rtptimer.rtpholdtimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP hold time at line %d.  Using default.\n", v->value, v->lineno);
				device->rtptimer.rtpholdtimeout = global.rtptimer.rtpholdtimeout;
				error++;
			}
			break;
		case SIP_CONF_RTPKEEPALIVE:
			if ((sscanf(v->value, "%d", &device->rtptimer.rtpkeepalive) != 1) || (device->rtptimer.rtpkeepalive < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP keepalive time at line %d.  Using default.\n", v->value, v->lineno);
				device->rtptimer.rtpkeepalive = global.rtptimer.rtpkeepalive;
				error++;
			} 
			break;
		case SIP_CONF_RTFULLCONTACT:	/* Realtime only */
			if (realtime) {
				ast_string_field_set(device, fullcontact, v->value);
				ast_set_flag(&device->flags[1], SIP_PAGE2_RT_FROMCONTACT);
			} else {
				ast_log(LOG_WARNING, "'%s' is not a valid configuration option (line %d, device %s).\n", v->value, v->lineno, device->name);
				error++;
			}
			break;
		case SIP_CONF_RTPTIMEOUT:
			if ((sscanf(v->value, "%d", &device->rtptimer.rtptimeout) != 1) || (device->rtptimer.rtptimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP hold time at line %d.  Using default.\n", v->value, v->lineno);
				error++;
				device->rtptimer.rtptimeout = global.rtptimer.rtptimeout;
			}
			break;
		case SIP_CONF_SECRET:
			ast_string_field_set(device, secret, v->value);
			break;
		case SIP_CONF_SETVAR:
			device->chanvars = add_var(v->value, device->chanvars);
			break;
		case SIP_CONF_SUBSCRIBECONTEXT:
			ast_string_field_set(&device->extra, subscribecontext, v->value);
			break;
		case SIP_CONF_MWISUBSCRIBE:
			ast_set2_flag(&device->flags[1], ast_true(v->value), SIP_PAGE2_SUBSCRIBEMWIONLY);
			break;
		case SIP_CONF_T1MIN:
			break;
		case SIP_CONF_T1DEFAULT:
			break;
		case SIP_CONF_USEREQPHONE:
			ast_set2_flag(&device->flags[0], ast_true(v->value), SIP_USEREQPHONE);
			break;
		case SIP_CONF_VMAILBOX:
			ast_string_field_set(device, mailbox.mailbox, v->value);
			sipcounters.peers_with_mwi++;
			break;
		case SIP_CONF_VMEXTEN:
			ast_string_field_set(device, mailbox.vmexten, v->value);
			break;
		case SIP_CONF_NONE:
		case SIP_CONF_NOT_VALID_FOR_OBJECT:
		case SIP_CONF_NOT_FOUND:
			ast_log(LOG_ERROR, "Bad configuration entry in line %d: %s = %s\n", v->lineno, v->name, v->value);
			error++;
			break;
		default:	
			ast_log(LOG_ERROR, "This error message should not happen. Bad config error: %d\n", option);
			break;
		}

/*---------------------
	SERVICE CONFIGS
		} else if (!strcasecmp(v->name, "fromdomain")) {
			ast_string_field_set(device, extra.fromdomain, v->value);
			//ast_copy_string(device->fromdomain, v->value, sizeof(device->fromdomain));
		} else if (!strcasecmp(v->name, "fromuser")) {
			ast_string_field_set(device, extra.fromuser, v->value);
			//ast_copy_string(device->fromuser, v->value, sizeof(device->fromuser));
----------*/
	}
	if (error) 
		ast_log(LOG_WARNING, "Errors found in phone config: %s = %d\n", device->name, error);

	/* Set flags from handle_common_options */
	ast_copy_flags(&device->flags[0], &peerflags[0], mask[0].flags);
	ast_copy_flags(&device->flags[1], &peerflags[1], mask[1].flags);

	/* If not realtime and dynamic - check if we have a current registration */
	if (!found && ast_test_flag(&device->flags[1], SIP_PAGE2_DYNAMIC) && !ast_test_flag(&device->flags[0], SIP_REALTIME))
		reg_source_db(device);
	

	/* If dynamic and realtime, check registration expiry - it might have
		expired already */
	if (!ast_test_flag(&global.flags[1], SIP_PAGE2_IGNOREREGEXPIRE) && ast_test_flag(&device->flags[1], SIP_PAGE2_DYNAMIC) && realtime) {
		time_t nowtime = time(NULL);

		if ((nowtime - regseconds) > 0) {
			destroy_association(device);
			memset(&device->addr, 0, sizeof(device->addr));
			if (option_debug)
				ast_log(LOG_DEBUG, "Bah, we're expired (%d/%d/%d)!\n", (int)(nowtime - regseconds), (int)regseconds, (int)nowtime);
		}
	}

	/* If we have an allowsubscribe, enable it */
	if (ast_test_flag(&device->flags[1], SIP_PAGE2_ALLOWSUBSCRIBE))
		global.allowsubscribe = TRUE;	/* No global ban any more */

	ASTOBJ_UNMARK(device);
	/* Delete the old ACL list */
	ast_free_ha(oldha);

	/* Start registration if needed */
	if (ast_test_flag(&device->flags[1], SIP_PAGE2_SERVICE)) {
		sip_register(NULL, register_lineno, device);	/* XXX How do we handle this at reload?? */
	} else if (device->registry) {
		/* We have a registry entry for a peer that no longer wished to be registered */
		ASTOBJ_UNREF(device->registry,sip_registry_destroy);
		device->registry = NULL;
	}
	return device;
}

/*! \brief  realtime_peer: Get peer from realtime storage
 * Checks the "sippeers" realtime family from extconfig.conf 
 * \todo Consider adding check of port address when matching here to follow the same
 * 	algorithm as for static peers. Will we break anything by adding that?
*/
struct sip_device *realtime_peer(const char *newpeername, struct sockaddr_in *sin)
{
	struct sip_device *peer;
	struct ast_variable *var = NULL;
	struct ast_variable *tmp;
	char ipaddr[INET_ADDRSTRLEN];

	/* First check on peer name */
	if (newpeername) 
		var = ast_load_realtime("sippeers", "name", newpeername, NULL);
	else if (sin) {	/* Then check on IP address for dynamic peers */
		ast_copy_string(ipaddr, ast_inet_ntoa(sin->sin_addr), sizeof(ipaddr));
		var = ast_load_realtime("sippeers", "host", ipaddr, NULL);	/* First check for fixed IP hosts */
		if (!var)
			var = ast_load_realtime("sippeers", "ipaddr", ipaddr, NULL);	/* Then check for registred hosts */
	}

	if (!var)
		return NULL;

	for (tmp = var; tmp; tmp = tmp->next) {
		/* If this is type=user, then skip this object. */
		if (!strcasecmp(tmp->name, "type") &&
		    !strcasecmp(tmp->value, "user")) {
			ast_variables_destroy(var);
			return NULL;
		} else if (!newpeername && !strcasecmp(tmp->name, "name")) {
			newpeername = tmp->value;
		}
	}
	
	if (!newpeername) {	/* Did not find peer in realtime */
		ast_log(LOG_WARNING, "Cannot Determine peer name ip=%s\n", ipaddr);
		ast_variables_destroy(var);
		return NULL;
	}

	/* Peer found in realtime, now build it in memory */
	peer = build_device(newpeername, var, NULL, !ast_test_flag(&global.flags[1], SIP_PAGE2_RTCACHEFRIENDS));
	if (!peer) {
		ast_variables_destroy(var);
		return NULL;
	}

	if (ast_test_flag(&global.flags[1], SIP_PAGE2_RTCACHEFRIENDS)) {
		/* Cache peer */
		ast_copy_flags(&peer->flags[1],&global.flags[1], SIP_PAGE2_RTAUTOCLEAR|SIP_PAGE2_RTCACHEFRIENDS);
		if (ast_test_flag(&global.flags[1], SIP_PAGE2_RTAUTOCLEAR)) {
			if (peer->expire > -1) {
				ast_sched_del(sched, peer->expire);
			}
			peer->expire = ast_sched_add(sched, (global.rtautoclear) * 1000, expire_register, (void *)peer);
		}
		ASTOBJ_CONTAINER_LINK(&devicelist,peer);
	} else {
		ast_set_flag(&peer->flags[0], SIP_REALTIME);
	}
	ast_variables_destroy(var);

	return peer;
}

/*! \brief Reset settings of global settings structure */
static void reset_global_settings(struct sip_globals *global)
{
	ast_clear_flag(&global->flags[0], AST_FLAGS_ALL);
	ast_clear_flag(&global->flags[1], AST_FLAGS_ALL);
	memset(&global->default_prefs, 0 , sizeof(global->default_prefs));
	global->srvlookup = TRUE;
	/*! \brief Codecs that we support by default: */
	global->capability = AST_FORMAT_ULAW | AST_FORMAT_ALAW | AST_FORMAT_GSM | AST_FORMAT_H263;
	//global->dtmf_capability = AST_RTP_DTMF;
	/*!< This is default: NO MMR and JBIG trancoding, NO fill bit removal, transferredTCF TCF, UDP FEC, Version 0 and 9600 max fax rate */
	global->t38_capability = T38FAX_VERSION_0 | T38FAX_RATE_2400 | T38FAX_RATE_4800 | T38FAX_RATE_7200 | T38FAX_RATE_9600;

	global->maxforwards = DEFAULT_MAX_FORWARDS;
	global->tos_sip = DEFAULT_TOS_SIP;
	global->tos_audio = DEFAULT_TOS_AUDIO;
	global->tos_video = DEFAULT_TOS_VIDEO;
	global->tos_presense = DEFAULT_TOS_SIP;	/* Initialize to SIP type of service */
	global->allow_external_domains = DEFAULT_ALLOW_EXT_DOM;				/* Allow external invites */
	global->regcontext[0] = '\0';
	global->notifyringing = DEFAULT_NOTIFYRINGING;
	global->alwaysauthreject = 0;
	global->allowsubscribe = FALSE;
	snprintf(global->useragent, sizeof(global->useragent), "%s %s", DEFAULT_USERAGENT, ASTERISK_VERSION);
	ast_copy_string(global->default_notifymime, DEFAULT_NOTIFYMIME, sizeof(global->default_notifymime));
	if (ast_strlen_zero(ast_config_AST_SYSTEM_NAME))
		ast_copy_string(global->realm, DEFAULT_REALM, sizeof(global->realm));
	else
		ast_copy_string(global->realm, ast_config_AST_SYSTEM_NAME, sizeof(global->realm));
	ast_copy_string(global->default_callerid, DEFAULT_CALLERID, sizeof(global->default_callerid));
	global->compactheaders = DEFAULT_COMPACTHEADERS;
	global->reg_timeout = DEFAULT_REGISTRATION_TIMEOUT;
	global->regattempts_max = 0;
	global->mwitime = DEFAULT_MWITIME;
	global->autocreatepeer = DEFAULT_AUTOCREATEPEER;
	global->allowguest = DEFAULT_ALLOWGUEST;
	global->rtptimer.rtptimeout = 0;
	global->rtptimer.rtpholdtimeout = 0;
	global->rtptimer.rtpkeepalive = 0;
	global->autoframing = 0;
	global->default_subscribecontext[0] = '\0';
	global->default_language[0] = '\0';
	global->default_fromdomain[0] = '\0';
	global->default_qualify = DEFAULT_QUALIFY;
	global->default_qualifycheck_ok = DEFAULT_QUALIFY_FREQ_OK;	/*!< Default qualify time when status is ok */
	global->default_qualifycheck_notok = DEFAULT_QUALIFY_FREQ_NOTOK;	/*!< Default qualify time when statusis not ok */
	global->default_maxcallbitrate = DEFAULT_MAX_CALL_BITRATE;
	ast_copy_string(global->default_mohinterpret, DEFAULT_MOHINTERPRET, sizeof(global->default_mohinterpret));
	ast_copy_string(global->default_mohsuggest, DEFAULT_MOHSUGGEST, sizeof(global->default_mohsuggest));
	ast_copy_string(global->default_vmexten, DEFAULT_VMEXTEN, sizeof(global->default_vmexten));
	ast_set_flag(&global->flags[0], SIP_DTMF_RFC2833);			/*!< Default DTMF setting: RFC2833 */
	ast_set_flag(&global->flags[0], SIP_NAT_RFC3581);			/*!< NAT support if requested by device with rport */
	ast_set_flag(&global->flags[0], SIP_CAN_REINVITE);			/*!< Allow re-invites */

	/* Debugging settings, always default to off */
	global->dumphistory = FALSE;
	global->recordhistory = FALSE;
	ast_clear_flag(&global->flags[1], SIP_PAGE2_DEBUG_CONFIG);


	global->allowtransfer = TRANSFER_OPENFORALL;	/* Merrily accept all transfers by default */
	global->rtautoclear = 120;
	ast_set_flag(&global->flags[1], SIP_PAGE2_ALLOWSUBSCRIBE);	/* Default for peers, users: TRUE */
	ast_set_flag(&global->flags[1], SIP_PAGE2_ALLOWOVERLAP);		/* Default for peers, users: TRUE */
	ast_set_flag(&global->flags[1], SIP_PAGE2_RTUPDATE);

	ast_copy_string(global->default_context, DEFAULT_CONTEXT, sizeof(global->default_context));
	global->relaxdtmf = FALSE;
	global->callevents = FALSE;
	global->t1min = DEFAULT_T1MIN;		
	global->t1default = SIP_TIMER_T1_DEFAULT;		
	global->t2default = SIP_TIMER_T2_DEFAULT;		
	global->t4default = SIP_TIMER_T4_DEFAULT;		
	global->siptimer_b = SIP_TIMER_B_DEFAULT;		
	global->siptimer_f = SIP_TIMER_F_DEFAULT;		
	sipcounters.peers_with_mwi = 0;		/* Reset counter for mwi peers */
}

/*! \brief Re-read SIP.conf config file
\note	This function reloads all config data.
	They will only change configuration data at restart, not at reload.
	SIP debug and recordhistory state will not change
 */
int reload_config(enum channelreloadreason reason)
{
	struct ast_config *cfg;
	struct ast_variable *v;
	struct sip_device *device = (struct sip_device *) NULL;
	struct ast_hostent ahp;
	char *cat, *stringp, *context, *oldregcontext;
	char newcontexts[AST_MAX_CONTEXT], oldcontexts[AST_MAX_CONTEXT];
	struct hostent *hp;
	int format;
	struct ast_flags dummy[2];
	int auto_sip_domains = FALSE;
	struct sockaddr_in old_bindaddr = sipnet.bindaddr;
	int registry_count = 0, peer_count = 0, user_count = 0;
	struct ast_flags debugflag = {0};
	int error = 0;

	cfg = ast_config_load(config);

	/* We *must* have a config file otherwise stop immediately */
	if (!cfg) {
		ast_log(LOG_NOTICE, "Unable to load config %s\n", config);
		return -1;
	}
	
	/* Initialize copy of current global.regcontext for later use in removing stale contexts */
	ast_copy_string(oldcontexts, global.regcontext, sizeof(oldcontexts));
	oldregcontext = oldcontexts;

	/* Clear all flags before setting default values */
	/* Preserve debugging settings for console */
	ast_copy_flags(&debugflag, &global.flags[1], SIP_PAGE2_DEBUG_CONSOLE);
	ast_copy_flags(&global.flags[1], &debugflag, SIP_PAGE2_DEBUG_CONSOLE);
	
	/* Reset channel settings to default before re-configuring */
	reset_ip_interface(&sipnet);		/* Clear IP interfaces */
	reset_global_settings(&global);	/* Reset global global settings */

	expiry.min_expiry = DEFAULT_MIN_EXPIRY;        /*!< Minimum accepted registration time */
	expiry.max_expiry = DEFAULT_MAX_EXPIRY;        /*!< Maximum accepted registration time */
	expiry.default_expiry = DEFAULT_DEFAULT_EXPIRY;
	expiry.expiry = DEFAULT_EXPIRY;					/* Used anywhere??? */


	/* Copy the default jb config over global.jbconf */
	memcpy(&global.jbconf, &default_jbconf, sizeof(struct ast_jb_conf));

	ast_clear_flag(&global.flags[1], SIP_PAGE2_VIDEOSUPPORT);

	/* Read the [general] config section of sip.conf (or from realtime config) */
	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		int i = 0;
		enum sip_config_options option = sip_config_parse(v->name, SIP_CONFOBJ_GENERAL);
		switch(option) {
		case SIP_CONF_TRUSTRPID:
		case SIP_CONF_SENDRPID:
		case SIP_CONF_G726NONSTANDARD:
		case SIP_CONF_USECLIENTCODE:
		case SIP_CONF_DTMFMODE:
		case SIP_CONF_NAT:
		case SIP_CONF_CANREINVITE:
		case SIP_CONF_INSECURE:
		case SIP_CONF_PROGRESSINBAND:
		case SIP_CONF_PROMISCREDIR:
		case SIP_CONF_VIDEOSUPPORT:
		case SIP_CONF_ALLOWOVERLAP:
		case SIP_CONF_ALLOWSUBSCRIBE:
		case SIP_CONF_T38PT_UDPTL:
		case SIP_CONF_RFC2833COMPENSATE:
		case SIP_CONF_COMPACTHEADERS:
			error += handle_common_options(option, &global.flags[0], &dummy[0], v);
			break;
		case SIP_CONF_JBENABLE:
		case SIP_CONF_JBFORCE:
		case SIP_CONF_JBIMPL:
		case SIP_CONF_JBLOG:
		case SIP_CONF_JBMAXSIZE:
		case SIP_CONF_JBRESYNC:
			/* handle jb conf */
			ast_jb_read_conf(&global.jbconf, v->name, v->value);
			break;

		case SIP_CONF_DEFCONTEXT:
			ast_copy_string(global.default_context, v->value, sizeof(global.default_context));
		case SIP_CONF_ALLOWGUEST:
			global.allowguest = ast_true(v->value) ? 1 : 0;
			break;
		case SIP_CONF_REALM:
			ast_copy_string(global.realm, v->value, sizeof(global.realm));
			break;
		case SIP_CONF_USERAGENT:
			ast_copy_string(global.useragent, v->value, sizeof(global.useragent));
			break;
		case SIP_CONF_ALLOWTRANSFER:
			global.allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
			break;
		case SIP_CONF_RT_CACHEFRIENDS:
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_RTCACHEFRIENDS);	
			break;
		case SIP_CONF_RTSAVESYSTEMNAME:
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_RTSAVE_SYSNAME);	
			break;
		case SIP_CONF_RTUPDATE:
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_RTUPDATE);	
			break;
		case SIP_CONF_RTAUTOCLEAR:
			i = atoi(v->value);
			if (i > 0)
				global.rtautoclear = i;
			else {
				i = 0;
				error++;
			}
			ast_set2_flag(&global.flags[1], i || ast_true(v->value), SIP_PAGE2_RTAUTOCLEAR);
			break;
		case SIP_CONF_MAXFORWARDS:
			global.maxforwards = atoi(v->value);
			if (global.maxforwards < 1) {
				ast_log(LOG_WARNING, "Bad setting for maxforwards (%d), resetting to default %d\n", global.maxforwards, DEFAULT_MAX_FORWARDS);
				global.maxforwards = DEFAULT_MAX_FORWARDS;
				error++;
			}
			break;
		case SIP_CONF_IGNOREREGEXPIRE:
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_IGNOREREGEXPIRE);	
			break;
		case SIP_CONF_T1MIN:
			global.t1min = atoi(v->value);
			break;
		case SIP_CONF_T1DEFAULT:
			global.t1default = atoi(v->value);
			break;
		case SIP_CONF_T2DEFAULT:
			global.t2default = atoi(v->value);
			break;
		case SIP_CONF_T4DEFAULT:
			global.t4default = atoi(v->value);
			break;
		case SIP_CONF_TIMER_B:
			global.siptimer_b = atoi(v->value);
			break;
		case SIP_CONF_TIMER_F:
			global.siptimer_f = atoi(v->value);
			break;
		case SIP_CONF_USEREQPHONE:
			ast_set2_flag(&global.flags[0], ast_true(v->value), SIP_USEREQPHONE);	
			break;
		case SIP_CONF_RELAXDTMF:
			global.relaxdtmf = ast_true(v->value);
			break;
		case SIP_CONF_MWICHECK:
			if ((sscanf(v->value, "%d", &global.mwitime) != 1) || (global.mwitime < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid MWI time setting at line %d.  Using default (10).\n", v->value, v->lineno);
				global.mwitime = DEFAULT_MWITIME;
				error++;
			};
			break;
		case SIP_CONF_VMEXTEN:
			ast_copy_string(global.default_vmexten, v->value, sizeof(global.default_vmexten));
			break;
		case SIP_CONF_RTPTIMEOUT:
			if ((sscanf(v->value, "%d", &global.rtptimer.rtptimeout) != 1) || (global.rtptimer.rtptimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP time at line %d.  Disabling RTP timeout.\n", v->value, v->lineno);
				global.rtptimer.rtptimeout = 0;
				error++;
			}
			break;
		case SIP_CONF_RTPHOLDTIMEOUT:
			if ((sscanf(v->value, "%d", &global.rtptimer.rtpholdtimeout) != 1) || (global.rtptimer.rtpholdtimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP hold time at line %d.  Using default.\n", v->value, v->lineno);
				global.rtptimer.rtpholdtimeout = 0;
				error++;
			}
			break;
		case SIP_CONF_RTPKEEPALIVE:
			if ((sscanf(v->value, "%d", &global.rtptimer.rtpkeepalive) != 1) || (global.rtptimer.rtpkeepalive < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP keepalive time at line %d.  Using default.\n", v->value, v->lineno);
				global.rtptimer.rtpkeepalive = 0;
				error++;
			}
			break;
		case SIP_CONF_NOTIFYMIME:
			ast_copy_string(global.default_notifymime, v->value, sizeof(global.default_notifymime));
			break;
		case SIP_CONF_NOTIFYRINGING:
			global.notifyringing = ast_true(v->value);
			break;
		case SIP_CONF_ALWAYSAUTHREJECT:
			global.alwaysauthreject = ast_true(v->value);
			break;
		case SIP_CONF_MOHINTERPRET:
			ast_copy_string(global.default_mohinterpret, v->value, sizeof(global.default_mohinterpret));
			break;
		case SIP_CONF_MOHSUGGEST:
			ast_copy_string(global.default_mohsuggest, v->value, sizeof(global.default_mohsuggest));
			break;
		case SIP_CONF_LANGUAGE:
			ast_copy_string(global.default_language, v->value, sizeof(global.default_language));
			break;
		case SIP_CONF_REGCONTEXT:
			ast_copy_string(newcontexts, v->value, sizeof(newcontexts));
			stringp = newcontexts;
			/* Let's remove any contexts that are no longer defined in regcontext */
			cleanup_stale_contexts(stringp, oldregcontext);
			/* Create contexts if they don't exist already */
			while ((context = strsep(&stringp, "&"))) {
				if (!ast_context_find(context))
					ast_context_create(NULL, context, "SIP");
			}
			ast_copy_string(global.regcontext, v->value, sizeof(global.regcontext));
			break;
		case SIP_CONF_CALLERID:
			ast_copy_string(global.default_callerid, v->value, sizeof(global.default_callerid));
			break;
		case SIP_CONF_FROMDOMAIN:
			ast_copy_string(global.default_fromdomain, v->value, sizeof(global.default_fromdomain));
			break;
		case SIP_CONF_OUTBOUNDPROXY:
			/* Save name for re-resolution */
			ast_copy_string(sipnet.outboundproxy, v->value, sizeof(sipnet.outboundproxy));
			/* Try to resolve name now */
			if (ast_get_ip_or_srv(&sipnet.outboundproxyip, v->value, global.srvlookup ? "_sip._udp" : NULL) < 0) {
				ast_log(LOG_WARNING, "Unable to locate host '%s'\n", v->value);
				error++;
				};
			break;
		case SIP_CONF_OBPROXYPORT:
			/* Port needs to be after IP */
			sscanf(v->value, "%d", &format);
			sipnet.outboundproxyip.sin_port = htons(format);
			break;
		case SIP_CONF_AUTOCREATEPEER:
			global.autocreatepeer = ast_true(v->value);
			break;
		case SIP_CONF_SRVLOOKUP:
			global.srvlookup = ast_true(v->value);
			break;
		case SIP_CONF_EXPIRYMAX:
			expiry.max_expiry = atoi(v->value);
			if (expiry.max_expiry < 1) {
				ast_log(LOG_WARNING, "Bad setting for maxexpiry (%d). Resetting to default %d.\n", expiry.max_expiry, DEFAULT_MAX_EXPIRY);
				expiry.max_expiry = DEFAULT_MAX_EXPIRY;
				error++;
			}
			break;
		case SIP_CONF_EXPIRYMIN:
			expiry.min_expiry = atoi(v->value);
			if (expiry.min_expiry < 1) {
				ast_log(LOG_WARNING, "Bad setting for minexpiry (%d). Resetting to default %d.\n", expiry.min_expiry, DEFAULT_MAX_EXPIRY);
				expiry.min_expiry = DEFAULT_MIN_EXPIRY;
				error++;
			}
			break;
		case SIP_CONF_EXPIRYDEFAULT:
			expiry.default_expiry = atoi(v->value);
			if (expiry.default_expiry < 1) {
				ast_log(LOG_WARNING, "Bad setting for defaultexpiry (%d). Resetting to default %d.\n", expiry.default_expiry, DEFAULT_DEFAULT_EXPIRY);
				expiry.default_expiry = DEFAULT_DEFAULT_EXPIRY;
				error++;
			}
			break;
		case SIP_CONF_SIPDEBUG:
			if (ast_true(v->value))
				ast_set_flag(&global.flags[1], SIP_PAGE2_DEBUG_CONFIG);
			break;
		case SIP_CONF_SIPDEBUGLEVEL:
			if (!strcasecmp(v->value, "ALL")) {
				global.debuglevel = SIPDEBUG_ALL;
			} else if (!strcasecmp(v->value, "CALLS")) {
				global.debuglevel = SIPDEBUG_CALLS;
			} else if (!strcasecmp(v->value, "NO-OPTIONS")) {
				global.debuglevel = SIPDEBUG_NOPOKE;
			} else {
				error++;
				ast_log(LOG_WARNING, "Bad setting for sipdebuglevel (%s). Resetting to default.\n", v->value);
				global.debuglevel = SIPDEBUG_ALL;
			}
			break;
		case SIP_CONF_HISTORYDUMP:
			global.dumphistory = ast_true(v->value);
			break;
		case SIP_CONF_HISTORYRECORD:
			global.recordhistory = ast_true(v->value);
			break;
		case SIP_CONF_REGISTERTIMEOUT:
			global.reg_timeout = atoi(v->value);
			if (global.reg_timeout < 1) {
				ast_log(LOG_WARNING, "Bad setting for registertimeout (%d). Resetting to default %d.\n", global.reg_timeout, DEFAULT_REGISTRATION_TIMEOUT);
				global.reg_timeout = DEFAULT_REGISTRATION_TIMEOUT;
				error++;
			};
			break;
		case SIP_CONF_REGISTERATTEMPTS:
			global.regattempts_max = atoi(v->value);
			if (global.regattempts_max < 1) {
				ast_log(LOG_WARNING, "Bad setting for registerattempts (%d). Resetting to default %d.\n", global.regattempts_max, 0);
				global.regattempts_max = 0;
				error++;
			};
			break;
		case SIP_CONF_BINDADDR:
			if (!(hp = ast_gethostbyname(v->value, &ahp))) {
				ast_log(LOG_WARNING, "Invalid bind address: %s\n", v->value);
				error++;
			} else 
				memcpy(&sipnet.bindaddr.sin_addr, hp->h_addr, sizeof(sipnet.bindaddr.sin_addr));
			break;
		case SIP_CONF_BINDPORT:
			{
				int port;
				if (sscanf(v->value, "%d", &port) == 1) {
					sipnet_ourport_set(&sipnet, port);
					sipnet.bindaddr.sin_port = htons(sipnet_ourport(&sipnet));
				} else {
					ast_log(LOG_WARNING, "Invalid port number '%s' at line %d of %s\n", v->value, v->lineno, config);
					error++;
				}
			}
			break;
		case SIP_CONF_LOCALNET:
			{
				struct ast_ha *na;
				int ha_error = 0;

				na = ast_append_ha("d", v->value, sipnet.localaddr, &ha_error);
				if (ha_error) {	
					ast_log(LOG_WARNING, "Invalid localnet value: %s\n", v->value);
					error++;
				} else
					sipnet.localaddr = na;
			}
			break;
		case SIP_CONF_EXTERNIP:
			if (!(hp = ast_gethostbyname(v->value, &ahp)))  {
				ast_log(LOG_WARNING, "Invalid address for externip keyword: %s\n", v->value);
				error++;
			} else
				memcpy(&sipnet.externip.sin_addr, hp->h_addr, sizeof(sipnet.externip.sin_addr));
			sipnet.externexpire = 0;
			break;
		case SIP_CONF_EXTERNHOST:
			ast_copy_string(sipnet.externhost, v->value, sizeof(sipnet.externhost));
			if (!(hp = ast_gethostbyname(sipnet.externhost, &ahp)))  {
				ast_log(LOG_WARNING, "Invalid address for externhost keyword: %s\n", sipnet.externhost);
				error++;
			} else
				memcpy(&sipnet.externip.sin_addr, hp->h_addr, sizeof(sipnet.externip.sin_addr));
			sipnet.externexpire = time(NULL);
			break;
		case SIP_CONF_EXTERNREFRESH:
			if (sscanf(v->value, "%d", &sipnet.externrefresh) != 1) {
				ast_log(LOG_WARNING, "Invalid externrefresh value '%s', must be an integer > 0 at line %d. Resetting to default %d\n", v->value, v->lineno, DEFAULT_EXTERNREFRESH);
				sipnet.externrefresh = DEFAULT_EXTERNREFRESH;
				error++;
			}
			break;
		case SIP_CONF_ALLOW:
			error += ast_parse_allow_disallow(&global.default_prefs, &global.capability, v->value, TRUE);
			break;
		case SIP_CONF_DISALLOW:
			error += ast_parse_allow_disallow(&global.default_prefs, &global.capability, v->value, FALSE);
			break;
		case SIP_CONF_AUTOFRAMING:
			global.autoframing = ast_true(v->value);
			break;
		case SIP_CONF_ALLOWEXTERNALDOMAINS:
			global.allow_external_domains = ast_true(v->value);
			break;
		case SIP_CONF_AUTODOMAIN:
			auto_sip_domains = ast_true(v->value);
			break;
		case SIP_CONF_DOMAIN:
			{
				char *domain = ast_strdupa(v->value);
				char *context = strchr(domain, ',');

				if (context)
					*context++ = '\0';

				if (option_debug && ast_strlen_zero(context))
					ast_log(LOG_DEBUG, "No context specified at line %d for domain '%s'\n", v->lineno, domain);
				if (ast_strlen_zero(domain)) {
					ast_log(LOG_WARNING, "Empty domain specified at line %d\n", v->lineno);
					error++;
				} else
					add_sip_domain(ast_strip(domain), SIP_DOMAIN_CONFIG, context ? ast_strip(context) : "");
			}
			break;
		case SIP_CONF_REGISTER:
			if (sip_register(v->value, v->lineno, NULL) == 0)
				registry_count++;
			else {
				error++;
			}
			break;
		case SIP_CONF_TOS_SIP:
			if (ast_str2tos(v->value, &global.tos_sip)) {
				ast_log(LOG_WARNING, "Invalid tos_sip value %s at line %d, recommended value is 'cs3'. See doc/ip-tos.txt.\n", v->value, v->lineno);
				error++;
			}
			break;
		case SIP_CONF_TOS_AUDIO:
			if (ast_str2tos(v->value, &global.tos_audio)) {
				ast_log(LOG_WARNING, "Invalid tos_audio value at line %d, recommended value is 'ef'. See doc/ip-tos.txt.\n", v->lineno);
				error++;
			}
			break;
		case SIP_CONF_TOS_VIDEO:
			if (ast_str2tos(v->value, &global.tos_video)) {
				ast_log(LOG_WARNING, "Invalid tos_video value at line %d, recommended value is 'af41'. See doc/ip-tos.txt.\n", v->lineno);
				error++;
			}
			break;
		case SIP_CONF_TOS_PRESENSE:
			if (ast_str2tos(v->value, &global.tos_presense)) {
				ast_log(LOG_WARNING, "Invalid tos_presence value at line %d, recommended value is 'cs3'. See doc/ip-tos.txt.\n", v->lineno);
				error++;
			}
			break;
		case SIP_CONF_QUALIFY:
			if (ast_false(v->value))
				global.default_qualify = 0;
			else if (ast_true(v->value)) {
				global.default_qualify = DEFAULT_QUALIFY_MAXMS;
			} else if (sscanf(v->value, "%d", &global.default_qualify) != 1 ||global.default_qualify < 10) {
				ast_log(LOG_WARNING, "Qualification default should be 'yes', 'no', or a number of milliseconds > 10 at line %d of sip.conf\n", v->lineno);
				error++;
				global.default_qualify = 0;
			}
			break;
		case SIP_CONF_QUALIFY_TIMER_OK:
			{
				int freq;
				if(sscanf(v->value, "%d", &freq) != 1)  {
					if (freq)
						global.default_qualifycheck_ok = freq;
					else {
						error++;
						ast_log(LOG_WARNING, "Bad value for qualify ok timer: %s. Using default value\n", v->value);
					}
				}
			}
			break;
		case SIP_CONF_QUALIFY_TIMER_NOT_OK:
			{
				int freq;
				if(sscanf(v->value, "%d", &freq) != 1)  {
					if (freq)
						global.default_qualifycheck_notok = freq;
					else {
						error++;
						ast_log(LOG_WARNING, "Bad value for qualify not ok timer: %s. Using default value\n", v->value);
					}
				}
			}
			break;
		case SIP_CONF_CALLEVENTS:
			global.callevents = ast_true(v->value);
			break;
		case SIP_CONF_MAXCALLBITRATE:
			global.default_maxcallbitrate = atoi(v->value);
			if (global.default_maxcallbitrate < 0) {
				global.default_maxcallbitrate = DEFAULT_MAX_CALL_BITRATE;
				error++;
				ast_log(LOG_WARNING, "Bad value for max call bitrate: %s, resetting to default %d\n", v->value, DEFAULT_MAX_CALL_BITRATE);
			}
			break;
		case SIP_CONF_NONE:
		case SIP_CONF_NOT_VALID_FOR_OBJECT:
		case SIP_CONF_NOT_FOUND:
			ast_log(LOG_ERROR, "This configuration option is not valid here: %s (line %d)\n", v->name, v->lineno);
			break;
		default:	
			ast_log(LOG_ERROR, "This error message should not happen. Bad config error: %d\n", option);
			break;
		}
	}
	if (error) 
		ast_log(LOG_WARNING, "--- Number of errors found in general config: %d\n", error);

	if (!global.allow_external_domains && domains_configured()) {
		ast_log(LOG_WARNING, "To disallow external domains, you need to configure local SIP domains.\n");
		global.allow_external_domains = 1;
	}
	
	/* Build list of authentication to various SIP realms, i.e. service providers */
 	for (v = ast_variable_browse(cfg, "authentication"); v ; v = v->next) {
 		/* Format for authentication is auth = username:password@realm */
 		if (!strcasecmp(v->name, "auth"))
 			authl = add_realm_authentication(authl, v->value, v->lineno);
 	}
	
	/* Load peers, users and friends */
	cat = NULL;
	while ( (cat = ast_category_browse(cfg, cat)) ) {
		const char *utype;

		/* Skip general section, as well as authentication section */
		if (!strcasecmp(cat, "general") || !strcasecmp(cat, "authentication"))
			continue;
		utype = ast_variable_retrieve(cfg, cat, "type");
		if (!utype) {
			ast_log(LOG_WARNING, "Section '%s' lacks type\n", cat);
			continue;
		} else {
			enum objecttype type;

			if (!strcasecmp(utype, "phone") || !strcasecmp(utype, "peer") )  /* Keep "peer" for a short while */
				type = SIP_PEER;
			else {
				ast_log(LOG_WARNING, "Unknown type '%s' for '%s' in %s\n", utype, cat, "sip.conf");
				continue;
			}
			if (type & SIP_PEER) {
				device = build_device(cat, ast_variable_browse(cfg, cat), NULL, 0);
				if (device) {
					ASTOBJ_CONTAINER_LINK(&devicelist,device);
					device_unref(device);
					peer_count++;
				}
			}
		}
	}

	/* Add default domains - host name, IP address and IP:port */
	/* Only do this if user added any sip domain with "localdomains" */
	/* In order to *not* break backwards compatibility */
	/* 	Some phones address us at IP only, some with additional port number */
	if (auto_sip_domains) {
		char temp[MAXHOSTNAMELEN];

		/* First our default IP address */
		if (sipnet.bindaddr.sin_addr.s_addr)
			add_sip_domain(ast_inet_ntoa(sipnet.bindaddr.sin_addr), SIP_DOMAIN_AUTO, NULL);
		else
			ast_log(LOG_NOTICE, "Can't add wildcard IP address to domain list, please add IP address to domain manually.\n");

		/* Our extern IP address, if configured */
		if (sipnet.externip.sin_addr.s_addr)
			add_sip_domain(ast_inet_ntoa(sipnet.externip.sin_addr), SIP_DOMAIN_AUTO, NULL);

		/* Extern host name (NAT traversal support) */
		if (!ast_strlen_zero(sipnet.externhost))
			add_sip_domain(sipnet.externhost, SIP_DOMAIN_AUTO, NULL);
		
		/* Our host name */
		if (!gethostname(temp, sizeof(temp)))
			add_sip_domain(temp, SIP_DOMAIN_AUTO, NULL);
	}

	/* Release configuration from memory */
	ast_config_destroy(cfg);

	/* Load the list of manual NOTIFY types to support */
	if (notify_types)
		ast_config_destroy(notify_types);
	notify_types = ast_config_load(notify_config);

	/* Done, tell the manager */
	manager_event(EVENT_FLAG_SYSTEM, "ChannelReload", "Channel: SIP\r\nReloadReason: %s\r\nRegistry_Count: %d\r\nPeer_Count: %d\r\nUser_Count: %d\r\n\r\n", channelreloadreason2txt(reason), registry_count, peer_count, user_count);
	if (sipsock_init(&sipnet, &old_bindaddr) == -1) 
		ast_log(LOG_WARNING, "Unable to get own IP address, SIP disabled\n");

	return 0;
}

/*! \brief List configuration options for specific object */
static void sip_listconfighelper(int fd, enum sip_config_objects object)
{
	int i;
	int max = sizeof(sip_config) / sizeof(struct sip_config_struct);
	int count = 0;

	ast_cli(fd,"--------------------------------------------------------------------------------\n");
	for (i=0; i < max; i++) {
		if (sip_config[i].valid & object) {
			ast_cli(fd, "   %-18.18s %-80.80s\n", sip_config[i].label, sip_config[i].desc);
			count++;
		}
	}
	ast_cli(fd, "  * %d configuration options\n", count);
	ast_cli(fd,"\n");
}

/*! \brief List all configuration options in sip.conf */
int sip_listconfigs(int fd)
{
	ast_cli(fd, "\nSIP configuration options help page:\n");
	ast_cli(fd,"\n");
	ast_cli(fd,"Configuration options for the [general] section of sip.conf\n");
	sip_listconfighelper(fd, SIP_CONFOBJ_GENERAL);
	ast_cli(fd,"Configuration options for type=phone\n");
	sip_listconfighelper(fd, SIP_CONFOBJ_PHONE);
	ast_cli(fd,"Configuration options for type=trunk\n");
	sip_listconfighelper(fd, SIP_CONFOBJ_TRUNK);
	ast_cli(fd,"Configuration options for type=service\n");
	sip_listconfighelper(fd, SIP_CONFOBJ_SERVICE);
	ast_cli(fd, "\n---\n");
	return RESULT_SUCCESS;

/*	SIP_CONFOBJ_GENERAL		General section
	SIP_CONFOBJ_PHONE		Phone options
	SIP_CONFOBJ_SERVICE		Service options
	SIP_CONFOBJ_TRUNK		Trunk options
	SIP_CONFOBJ_DOMAIN		Configurations valid for domains 
	SIP_CONFOBJ_LINE		Phone, service and trunk (macro)
*/
}

