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
 * \brief Various SIP parsing functions
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

/*! XXX Note that sip_methods[i].id == i must hold or the code breaks */
const struct cfsip_methods sip_methods[] = {
	{ SIP_UNKNOWN,	 RTP,    "-UNKNOWN-", CAN_NOT_CREATE_DIALOG},
	{ SIP_RESPONSE,	 NO_RTP, "SIP/2.0" , CAN_NOT_CREATE_DIALOG},
	{ SIP_REGISTER,	 NO_RTP, "REGISTER" , CAN_CREATE_DIALOG},
 	{ SIP_OPTIONS,	 NO_RTP, "OPTIONS" , CAN_CREATE_DIALOG},
	{ SIP_NOTIFY,	 NO_RTP, "NOTIFY" , CAN_CREATE_DIALOG},
	{ SIP_INVITE,	 RTP,    "INVITE" , CAN_CREATE_DIALOG},
	{ SIP_ACK,	 NO_RTP, "ACK" , CAN_NOT_CREATE_DIALOG},
	{ SIP_PRACK,	 NO_RTP, "PRACK" , CAN_NOT_CREATE_DIALOG},
	{ SIP_BYE,	 NO_RTP, "BYE" , CAN_NOT_CREATE_DIALOG},
	{ SIP_REFER,	 NO_RTP, "REFER" , CAN_CREATE_DIALOG},
	{ SIP_SUBSCRIBE, NO_RTP, "SUBSCRIBE" , CAN_CREATE_DIALOG},
	{ SIP_MESSAGE,	 NO_RTP, "MESSAGE" , CAN_CREATE_DIALOG},
	{ SIP_UPDATE,	 NO_RTP, "UPDATE" , CAN_NOT_CREATE_DIALOG},
	{ SIP_INFO,	 NO_RTP, "INFO" , CAN_NOT_CREATE_DIALOG},
	{ SIP_CANCEL,	 NO_RTP, "CANCEL" , CAN_NOT_CREATE_DIALOG},
	{ SIP_PUBLISH,	 NO_RTP, "PUBLISH", CAN_CREATE_DIALOG}
};

/*! \brief List of well-known SIP options. If we get this in a require,
   we should check the list and answer accordingly. */
static const struct cfsip_options sip_options[] = {	/* XXX used in 3 places */
	/* RFC3891: Replaces: header for transfer */
	{ SIP_OPT_REPLACES,	SUPPORTED,	"replaces" },	
	/* One version of Polycom firmware has the wrong label */
	{ SIP_OPT_REPLACES,	SUPPORTED,	"replace" },	
	/* RFC3262: PRACK 100% reliability */
	{ SIP_OPT_100REL,	NOT_SUPPORTED,	"100rel" },	
	/* RFC4028: SIP Session Timers */
	{ SIP_OPT_TIMER,	NOT_SUPPORTED,	"timer" },
	/* RFC3959: SIP Early session support */
	{ SIP_OPT_EARLY_SESSION, NOT_SUPPORTED,	"early-session" },
	/* RFC3911: SIP Join header support */
	{ SIP_OPT_JOIN,		NOT_SUPPORTED,	"join" },
	/* RFC3327: Path support */
	{ SIP_OPT_PATH,		NOT_SUPPORTED,	"path" },
	/* RFC3840: Callee preferences */
	{ SIP_OPT_PREF,		NOT_SUPPORTED,	"pref" },
	/* RFC3312: Precondition support */
	{ SIP_OPT_PRECONDITION,	NOT_SUPPORTED,	"precondition" },
	/* RFC3323: Privacy with proxies*/
	{ SIP_OPT_PRIVACY,	NOT_SUPPORTED,	"privacy" },
	/* RFC4092: Usage of the SDP ANAT Semantics in the SIP */
	{ SIP_OPT_SDP_ANAT,	NOT_SUPPORTED,	"sdp-anat" },
	/* RFC3329: Security agreement mechanism */
	{ SIP_OPT_SEC_AGREE,	NOT_SUPPORTED,	"sec_agree" },
	/* SIMPLE events:  draft-ietf-simple-event-list-07.txt */
	{ SIP_OPT_EVENTLIST,	NOT_SUPPORTED,	"eventlist" },
	/* GRUU: Globally Routable User Agent URI's */
	{ SIP_OPT_GRUU,		NOT_SUPPORTED,	"gruu" },
	/* Target-dialog: draft-ietf-sip-target-dialog-03.txt */
	{ SIP_OPT_TARGET_DIALOG,NOT_SUPPORTED,	"tdialog" },
	/* Disable the REFER subscription, RFC 4488 */
	{ SIP_OPT_NOREFERSUB,	NOT_SUPPORTED,	"norefersub" },
	/* ietf-sip-history-info-06.txt */
	{ SIP_OPT_HISTINFO,	NOT_SUPPORTED,	"histinfo" },
	/* ietf-sip-resource-priority-10.txt */
	{ SIP_OPT_RESPRIORITY,	NOT_SUPPORTED,	"resource-priority" },
};

/*! \brief returns true if 'name' (with optional trailing whitespace)
 * matches the sip method 'id'.
 * Strictly speaking, SIP methods are case SENSITIVE, but we do
 * a case-insensitive comparison to be more tolerant.
 * following Jon Postel's rule: Be gentle in what you accept, strict with what you send
 */
static int method_match(enum sipmethod id, const char *name)
{
	int len = strlen(sip_methods[id].text);
	int l_name = name ? strlen(name) : 0;
	/* true if the string is long enough, and ends with whitespace, and matches */
	return (l_name >= len && name[len] < 33 &&
		!strncasecmp(sip_methods[id].text, name, len));
}

/*! \brief  find_sip_method: Find SIP method from header */
static int find_sip_method(const char *msg)
{
	int i, res = 0;
	
	if (ast_strlen_zero(msg))
		return 0;
	for (i = 1; i < (sizeof(sip_methods) / sizeof(sip_methods[0])) && !res; i++) {
		if (method_match(i, msg))
			res = sip_methods[i].id;
	}
	return res;
}

/*! \brief return text string for sip method */
static char *sip_method2txt(int method)
{
	return sip_methods[method].text;
}

/*! \brief Check whether method needs RTP */
static int sip_method_needrtp(int method)
{
	return sip_methods[method].need_rtp;
}

/*! \brief Check if sip option is known to us, avoid x- options (non-standard) */ 
static int sip_option_lookup(const char *optionlabel)
{
	int i;
	for (i=0; i < (sizeof(sip_options) / sizeof(sip_options[0])); i++) {
		if (!strcasecmp(next, sip_options[i].text)) {
			profile |= sip_options[i].id;
			if (option_debug > 2 && sipdebug)
				ast_log(LOG_DEBUG, "Matched SIP option: %s\n", next);
			return i;
		}
	}
	if (option_debug > 2) {
		if (!strncasecmp(next, "x-", 2))
			ast_log(LOG_DEBUG, "Found private SIP option, not supported: %s\n", next);
		else
			ast_log(LOG_DEBUG, "Found no match for SIP option: %s (Please file bug report!)\n", next);
	}
	return -1;
}

/*! \brief Parse supported header in incoming packet */
static unsigned int parse_sip_options(struct sip_pvt *pvt, const char *supported)
{
	char *next, *sep;
	char *temp = ast_strdupa(supported);
	unsigned int profile = 0;
	int i, found;

	if (ast_strlen_zero(supported) )
		return 0;

	if (option_debug > 2 && sipdebug)
		ast_log(LOG_DEBUG, "Begin: parsing SIP \"Supported: %s\"\n", supported);

	for (next = temp; next; next = sep) {
		found = FALSE;
		if ( (sep = strchr(next, ',')) != NULL)
			*sep++ = '\0';
		next = ast_skip_blanks(next);
		if (option_debug > 2 && sipdebug)
			ast_log(LOG_DEBUG, "Got SIP option: -%s-\n", next);
		i = sip_options_lookup(next);
		if (i > 0)
			profile |= sip_options[i].id;
	}

	if (pvt)
		pvt->sipoptions = profile;
	return profile;
}

/*! \brief Return text representation of SIP option */
static char *sip_option2text(int option)
{
	return sip_options[option].text);
}

/*! \brief Print options to cli */
static void sip_options_print(int options, int fd)
{
	int x;
	int lastoption = -1;
	
	for (x=0 ; (x < (sizeof(sip_options) / sizeof(sip_options[0]))); x++) {
		if (sip_options[x].id != lastoption) {
			if (options & sip_options[x].id)
				ast_cli(fd, "%s ", sip_options[x].text);
			lastoption = x;
		}
	}
}



