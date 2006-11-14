/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 * and Edvina AB, Sollentuna, Sweden (chan_sip3 changes/additions)
 *
 * Mark Spencer <markster@digium.com>
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


/*! \brief List of subscription event types for SUBSCRIBE requests */
static const struct cfsubscription_types subscription_types[] = {
	{ NONE,		   "-",        "unknown",	             "unknown" },
 	/* RFC 4235: SIP Dialog event package */
	{ DIALOG_INFO_XML, "dialog",   "application/dialog-info+xml", "dialog-info+xml" },
	{ CPIM_PIDF_XML,   "presence", "application/cpim-pidf+xml",   "cpim-pidf+xml" },  /* RFC 3863 */
	{ PIDF_XML,        "presence", "application/pidf+xml",        "pidf+xml" },       /* RFC 3863 */
	{ XPIDF_XML,       "presence", "application/xpidf+xml",       "xpidf+xml" },       /* Pre-RFC 3863 with MS additions */
	{ MWI_NOTIFICATION,	"message-summary", "application/simple-message-summary", "mwi" } /* RFC 3842: Mailbox notification */
};

/*! \brief Show subscription type in string format */
const char *subscription_type2str(enum subscriptiontype subtype)
{
	int i;

	for (i = 1; (i < (sizeof(subscription_types) / sizeof(subscription_types[0]))); i++) {
		if (subscription_types[i].type == subtype) {
			return subscription_types[i].text;
		}
	}
	return subscription_types[0].text;
}

/*! \brief Find subscription type in array */
const struct cfsubscription_types *find_subscription_type(enum subscriptiontype subtype)
{
	int i;

	for (i = 1; (i < (sizeof(subscription_types) / sizeof(subscription_types[0]))); i++) {
		if (subscription_types[i].type == subtype) {
			return &subscription_types[i];
		}
	}
	return &subscription_types[0];
}

/*! \brief Used in the SUBSCRIBE notification subsystem */
GNURK int transmit_state_notify(struct sip_dialog *p, int state, int full, int timeout)
{
	char tmp[4000], from[256], to[256];
	char *t = tmp, *c, *mfrom, *mto;
	size_t maxbytes = sizeof(tmp);
	struct sip_request req;
	char hint[AST_MAX_EXTENSION];
	char *statestring = "terminated";
	const struct cfsubscription_types *subscriptiontype;
	enum state { NOTIFY_OPEN, NOTIFY_INUSE, NOTIFY_CLOSED } local_state = NOTIFY_OPEN;
	char *pidfstate = "--";
	char *pidfnote= "Ready";

	memset(from, 0, sizeof(from));
	memset(to, 0, sizeof(to));
	memset(tmp, 0, sizeof(tmp));

	switch (state) {
	case (AST_EXTENSION_RINGING | AST_EXTENSION_INUSE):
		statestring = (global.notifyringing) ? "early" : "confirmed";
		local_state = NOTIFY_INUSE;
		pidfstate = "busy";
		pidfnote = "Ringing";
		break;
	case AST_EXTENSION_RINGING:
		statestring = "early";
		local_state = NOTIFY_INUSE;
		pidfstate = "busy";
		pidfnote = "Ringing";
		break;
	case AST_EXTENSION_INUSE:
		statestring = "confirmed";
		local_state = NOTIFY_INUSE;
		pidfstate = "busy";
		pidfnote = "On the phone";
		break;
	case AST_EXTENSION_BUSY:
		statestring = "confirmed";
		local_state = NOTIFY_CLOSED;
		pidfstate = "busy";
		pidfnote = "On the phone";
		break;
	case AST_EXTENSION_UNAVAILABLE:
		statestring = "confirmed";
		local_state = NOTIFY_CLOSED;
		pidfstate = "away";
		pidfnote = "Unavailable";
		break;
	case AST_EXTENSION_ONHOLD:
		break;
	case AST_EXTENSION_NOT_INUSE:
	default:
		/* Default setting */
		break;
	}

	subscriptiontype = find_subscription_type(p->subscribed);
	
	/* Check which device/devices we are watching  and if they are registered */
	if (ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, p->context, p->exten)) {
		/* If they are not registered, we will override notification and show no availability */
		if (ast_device_state(hint) == AST_DEVICE_UNAVAILABLE) {
			local_state = NOTIFY_CLOSED;
			pidfstate = "away";
			pidfnote = "Not online";
		}
	}

	ast_copy_string(from, get_header(&p->initreq, "From"), sizeof(from));
	c = get_in_brackets(from);
	if (strncmp(c, "sip:", 4)) {
		ast_log(LOG_WARNING, "Huh?  Not a SIP header (%s)?\n", c);
		return -1;
	}
	mfrom = strsep(&c, ";");	/* trim ; and beyond */

	ast_copy_string(to, get_header(&p->initreq, "To"), sizeof(to));
	c = get_in_brackets(to);
	if (strncmp(c, "sip:", 4)) {
		ast_log(LOG_WARNING, "Huh?  Not a SIP header (%s)?\n", c);
		return -1;
	}
	mto = strsep(&c, ";");	/* trim ; and beyond */

	reqprep(&req, p, SIP_NOTIFY, 0, TRUE);

	
	add_header(&req, "Event", subscriptiontype->event);
	add_header(&req, "Content-Type", subscriptiontype->mediatype);
	switch(state) {
	case AST_EXTENSION_DEACTIVATED:
		if (timeout)
			add_header(&req, "Subscription-State", "terminated;reason=timeout");
		else {
			add_header(&req, "Subscription-State", "terminated;reason=probation");
			add_header(&req, "Retry-After", "60");
		}
		break;
	case AST_EXTENSION_REMOVED:
		add_header(&req, "Subscription-State", "terminated;reason=noresource");
		break;
	default:
		if (p->expiry)
			add_header(&req, "Subscription-State", "active");
		else	/* Expired */
			add_header(&req, "Subscription-State", "terminated;reason=timeout");
	}
	switch (p->subscribed) {
	case XPIDF_XML:
	case CPIM_PIDF_XML:
		ast_build_string(&t, &maxbytes, "<?xml version=\"1.0\"?>\n");
		ast_build_string(&t, &maxbytes, "<!DOCTYPE presence PUBLIC \"-//IETF//DTD RFCxxxx XPIDF 1.0//EN\" \"xpidf.dtd\">\n");
		ast_build_string(&t, &maxbytes, "<presence>\n");
		ast_build_string(&t, &maxbytes, "<presentity uri=\"%s;method=SUBSCRIBE\" />\n", mfrom);
		ast_build_string(&t, &maxbytes, "<atom id=\"%s\">\n", p->exten);
		ast_build_string(&t, &maxbytes, "<address uri=\"%s;user=ip\" priority=\"0.800000\">\n", mto);
		ast_build_string(&t, &maxbytes, "<status status=\"%s\" />\n", (local_state ==  NOTIFY_OPEN) ? "open" : (local_state == NOTIFY_INUSE) ? "inuse" : "closed");
		ast_build_string(&t, &maxbytes, "<msnsubstatus substatus=\"%s\" />\n", (local_state == NOTIFY_OPEN) ? "online" : (local_state == NOTIFY_INUSE) ? "onthephone" : "offline");
		ast_build_string(&t, &maxbytes, "</address>\n</atom>\n</presence>\n");
		break;
	case PIDF_XML: /* Eyebeam supports this format */
		ast_build_string(&t, &maxbytes, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
		ast_build_string(&t, &maxbytes, "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" \nxmlns:pp=\"urn:ietf:params:xml:ns:pidf:person\"\nxmlns:es=\"urn:ietf:params:xml:ns:pidf:rpid:status:rpid-status\"\nxmlns:ep=\"urn:ietf:params:xml:ns:pidf:rpid:rpid-person\"\nentity=\"%s\">\n", mfrom);
		ast_build_string(&t, &maxbytes, "<pp:person><status>\n");
		if (pidfstate[0] != '-')
			ast_build_string(&t, &maxbytes, "<ep:activities><ep:%s/></ep:activities>\n", pidfstate);
		ast_build_string(&t, &maxbytes, "</status></pp:person>\n");
		ast_build_string(&t, &maxbytes, "<note>%s</note>\n", pidfnote); /* Note */
		ast_build_string(&t, &maxbytes, "<tuple id=\"%s\">\n", p->exten); /* Tuple start */
		ast_build_string(&t, &maxbytes, "<contact priority=\"1\">%s</contact>\n", mto);
		if (pidfstate[0] == 'b') /* Busy? Still open ... */
			ast_build_string(&t, &maxbytes, "<status><basic>open</basic></status>\n");
		else
			ast_build_string(&t, &maxbytes, "<status><basic>%s</basic></status>\n", (local_state != NOTIFY_CLOSED) ? "open" : "closed");
		ast_build_string(&t, &maxbytes, "</tuple>\n</presence>\n");
		break;
	case DIALOG_INFO_XML: /* SNOM subscribes in this format */
		ast_build_string(&t, &maxbytes, "<?xml version=\"1.0\"?>\n");
		ast_build_string(&t, &maxbytes, "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"%d\" state=\"%s\" entity=\"%s\">\n", p->dialogver++, full ? "full":"partial", mto);
		if ((state & AST_EXTENSION_RINGING) && global.notifyringing)
			ast_build_string(&t, &maxbytes, "<dialog id=\"%s\" direction=\"recipient\">\n", p->exten);
		else
			ast_build_string(&t, &maxbytes, "<dialog id=\"%s\">\n", p->exten);
		ast_build_string(&t, &maxbytes, "<state>%s</state>\n", statestring);
		ast_build_string(&t, &maxbytes, "</dialog>\n</dialog-info>\n");
		break;
	case NONE:
	default:
		break;
	}

	if (t > tmp + sizeof(tmp))
		ast_log(LOG_WARNING, "Buffer overflow detected!!  (Please file a bug report)\n");

	add_header_contentLength(&req, strlen(tmp));
	add_line(&req, tmp);

	return send_request(p, &req, XMIT_RELIABLE, p->ocseq);
}

