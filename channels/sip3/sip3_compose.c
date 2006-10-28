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
 * \brief Various SIP functions for composing SIP packets
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
#include "asterisk/acl.h"
#include "asterisk/callerid.h"
#include "asterisk/cli.h"
#include "asterisk/app.h"
#include "asterisk/manager.h"
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
#include "asterisk/linkedlists.h"
#include "asterisk/stringfields.h"
#include "asterisk/monitor.h"
#include "asterisk/localtime.h"
#include "asterisk/compiler.h"
#include "sip3.h"
#include "sip3funcs.h"

/*! \brief Build SIP Call-ID value for a non-REGISTER transaction */
void build_callid_pvt(struct sip_dialog *pvt)
{
	char buf[33];

	const char *host = S_OR(pvt->fromdomain, ast_inet_ntoa(pvt->ourip));
	
	ast_string_field_build(pvt, callid, "%s@%s", generate_random_string(buf, sizeof(buf)), host);

}

/*! \brief Append date to SIP message */
void append_date(struct sip_request *req)
{
	char tmpdat[256];
	struct tm tm;
	time_t t = time(NULL);

	gmtime_r(&t, &tm);
	strftime(tmpdat, sizeof(tmpdat), "%a, %d %b %Y %T GMT", &tm);
	add_header(req, "Date", tmpdat);
}

/*! \brief Add text body to SIP message */
int add_text(struct sip_request *req, const char *text)
{
	/* XXX Convert \n's to \r\n's XXX */
	add_header(req, "Content-Type", "text/plain");
	add_header_contentLength(req, strlen(text));
	add_line(req, text);
	return 0;
}

/*! \brief Add DTMF INFO tone to sip message */
/* Always adds default duration 250 ms, regardless of what came in over the line */
int add_digit(struct sip_request *req, char digit)
{
	char tmp[256];

	snprintf(tmp, sizeof(tmp), "Signal=%c\r\nDuration=250\r\n", digit);
	add_header(req, "Content-Type", "application/dtmf-relay");
	add_header_contentLength(req, strlen(tmp));
	add_line(req, tmp);
	return 0;
}

/*! \brief Prepare SIP response packet */
int respprep(struct sip_request *resp, struct sip_dialog *p, const char *msg, const struct sip_request *req)
{
	char newto[256];
	const char *ot;

	init_resp(resp, msg);
	copy_via_headers(p, resp, req, "Via");
	if (msg[0] == '2')
		copy_all_header(resp, req, "Record-Route");
	copy_header(resp, req, "From");
	ot = get_header(req, "To");
	if (!strcasestr(ot, "tag=") && strncmp(msg, "100", 3)) {
		/* Add the proper tag if we don't have it already.  If they have specified
		   their tag, use it.  Otherwise, use our own tag */
		if (!ast_strlen_zero(p->theirtag) && ast_test_flag(&p->flags[0], SIP_OUTGOING))
			snprintf(newto, sizeof(newto), "%s;tag=%s", ot, p->theirtag);
		else if (p->tag && !ast_test_flag(&p->flags[0], SIP_OUTGOING))
			snprintf(newto, sizeof(newto), "%s;tag=%s", ot, p->tag);
		else
			ast_copy_string(newto, ot, sizeof(newto));
		ot = newto;
	}
	add_header(resp, "To", ot);
	copy_header(resp, req, "Call-ID");
	copy_header(resp, req, "CSeq");
	add_header(resp, "User-Agent", global.useragent);
	add_header(resp, "Allow", ALLOWED_METHODS);
	add_header(resp, "Supported", SUPPORTED_EXTENSIONS);
	if (msg[0] == '2' && (p->method == SIP_SUBSCRIBE || p->method == SIP_REGISTER)) {
		/* For successful registration responses, we also need expiry and
		   contact info */
		char tmp[256];

		snprintf(tmp, sizeof(tmp), "%d", p->expiry);
		add_header(resp, "Expires", tmp);
		if (p->expiry) {	/* Only add contact if we have an expiry time */
			char contact[256];
			snprintf(contact, sizeof(contact), "%s;expires=%d", p->our_contact, p->expiry);
			add_header(resp, "Contact", contact);	/* Not when we unregister */
		}
	} else if (msg[0] != '4' && p->our_contact[0]) {
		add_header(resp, "Contact", p->our_contact);
	}
	return 0;
}

/*! \brief Add route header into request per learned route */
void add_route(struct sip_request *req, struct sip_route *route)
{
	char r[BUFSIZ*2], *p;
	int n, rem = sizeof(r);

	if (!route)
		return;

	p = r;
	for (;route ; route = route->next) {
		n = strlen(route->hop);
		if (rem < n+3) /* we need room for ",<route>" */
			break;
		if (p != r) {	/* add a separator after fist route */
			*p++ = ',';
			--rem;
		}
		*p++ = '<';
		ast_copy_string(p, route->hop, rem); /* cannot fail */
		p += n;
		*p++ = '>';
		rem -= (n+2);
	}
	*p = '\0';
	add_header(req, "Route", r);
}

/*! \brief Add content (not header) to SIP message */
int add_line(struct sip_request *req, const char *line)
{
	if (req->lines == SIP_MAX_LINES)  {
		ast_log(LOG_WARNING, "Out of SIP line space\n");
		return -1;
	}
	if (!req->lines) {
		/* Add extra empty return */
		snprintf(req->data + req->len, sizeof(req->data) - req->len, "\r\n");
		req->len += strlen(req->data + req->len);
	}
	if (req->len >= sizeof(req->data) - 4) {
		ast_log(LOG_WARNING, "Out of space, can't add anymore\n");
		return -1;
	}
	req->line[req->lines] = req->data + req->len;
	snprintf(req->line[req->lines], sizeof(req->data) - req->len, "%s", line);
	req->len += strlen(req->line[req->lines]);
	req->lines++;
	return 0;	
}

/*! \brief Set destination from SIP URI */
static void set_destination(struct sip_dialog *p, char *uri)
{
	char *h, *maddr, hostname[256];
	int port, hn;
	struct hostent *hp;
	struct ast_hostent ahp;
	int debug=sip_debug_test_pvt(p);

	/* Parse uri to h (host) and port - uri is already just the part inside the <> */
	/* general form we are expecting is sip[s]:username[:password]@host[:port][;...] */

	if (debug)
		ast_verbose("set_destination: Parsing <%s> for address/port to send to\n", uri);

	/* Find and parse hostname */
	h = strchr(uri, '@');
	if (h)
		++h;
	else {
		h = uri;
		if (strncmp(h, "sip:", 4) == 0)
			h += 4;
		else if (strncmp(h, "sips:", 5) == 0)
			h += 5;
	}
	hn = strcspn(h, ":;>") + 1;
	if (hn > sizeof(hostname)) 
		hn = sizeof(hostname);
	ast_copy_string(hostname, h, hn);
	/* XXX bug here if string has been trimmed to sizeof(hostname) */
	h += hn - 1;

	/* Is "port" present? if not default to STANDARD_SIP_PORT */
	if (*h == ':') {
		/* Parse port */
		++h;
		port = strtol(h, &h, 10);
	}
	else
		port = STANDARD_SIP_PORT;

	/* Got the hostname:port - but maybe there's a "maddr=" to override address? */
	maddr = strstr(h, "maddr=");
	if (maddr) {
		maddr += 6;
		hn = strspn(maddr, "0123456789.") + 1;
		if (hn > sizeof(hostname))
			hn = sizeof(hostname);
		ast_copy_string(hostname, maddr, hn);
	}
	
	hp = ast_gethostbyname(hostname, &ahp);
	if (hp == NULL)  {
		ast_log(LOG_WARNING, "Can't find address for host '%s'\n", hostname);
		return;
	}
	p->sa.sin_family = AF_INET;
	memcpy(&p->sa.sin_addr, hp->h_addr, sizeof(p->sa.sin_addr));
	p->sa.sin_port = htons(port);
	if (debug)
		ast_verbose("set_destination: set destination to %s, port %d\n", ast_inet_ntoa(p->sa.sin_addr), port);
}


/*! \brief Initialize a SIP request message (not the initial one in a dialog) */
int reqprep(struct sip_request *req, struct sip_dialog *p, int sipmethod, int seqno, int newbranch)
{
	struct sip_request *orig = &p->initreq;
	char stripped[80];
	char tmp[80];
	char newto[256];
	const char *c;
	const char *ot, *of;
	int is_strict = FALSE;		/*!< Strict routing flag */

	memset(req, 0, sizeof(struct sip_request));
	
	snprintf(p->lastmsg, sizeof(p->lastmsg), "Tx: %s", sip_method2txt(sipmethod));
	
	if (!seqno) {
		p->ocseq++;
		seqno = p->ocseq;
	}
	
	if (newbranch) {
		p->branch ^= ast_random();
		build_via(p);
	}

	/* Check for strict or loose router */
	if (p->route && !ast_strlen_zero(p->route->hop) && strstr(p->route->hop,";lr") == NULL) {
		is_strict = TRUE;
		if (sipdebug)
			ast_log(LOG_DEBUG, "Strict routing enforced for session %s\n", p->callid);
	}

	if (sipmethod == SIP_CANCEL)
		c = p->initreq.rlPart2;	/* Use original URI */
	else if (sipmethod == SIP_ACK) {
		/* Use URI from Contact: in 200 OK (if INVITE) 
		(we only have the contacturi on INVITEs) */
		if (!ast_strlen_zero(p->okcontacturi))
			c = is_strict ? p->route->hop : p->okcontacturi;
 		else
 			c = p->initreq.rlPart2;
	} else if (!ast_strlen_zero(p->okcontacturi)) 
		c = is_strict ? p->route->hop : p->okcontacturi; /* Use for BYE or REINVITE */
	else if (!ast_strlen_zero(p->uri)) 
		c = p->uri;
	else {
		char *n;
		/* We have no URI, use To: or From:  header as URI (depending on direction) */
		ast_copy_string(stripped, get_header(orig, (ast_test_flag(&p->flags[0], SIP_OUTGOING)) ? "To" : "From"),
				sizeof(stripped));
		n = get_in_brackets(stripped);
		c = strsep(&n, ";");	/* trim ; and beyond */
	}	
	init_req(req, sipmethod, c);

	snprintf(tmp, sizeof(tmp), "%d %s", seqno, sip_method2txt(sipmethod));

	add_header(req, "Via", p->via);
	if (p->route) {
		set_destination(p, p->route->hop);
		add_route(req, is_strict ? p->route->next : p->route);
	}

	ot = get_header(orig, "To");
	of = get_header(orig, "From");

	/* Add tag *unless* this is a CANCEL, in which case we need to send it exactly
	   as our original request, including tag (or presumably lack thereof) */
	if (!strcasestr(ot, "tag=") && sipmethod != SIP_CANCEL) {
		/* Add the proper tag if we don't have it already.  If they have specified
		   their tag, use it.  Otherwise, use our own tag */
		if (ast_test_flag(&p->flags[0], SIP_OUTGOING) && !ast_strlen_zero(p->theirtag))
			snprintf(newto, sizeof(newto), "%s;tag=%s", ot, p->theirtag);
		else if (!ast_test_flag(&p->flags[0], SIP_OUTGOING))
			snprintf(newto, sizeof(newto), "%s;tag=%s", ot, p->tag);
		else
			snprintf(newto, sizeof(newto), "%s", ot);
		ot = newto;
	}

	if (ast_test_flag(&p->flags[0], SIP_OUTGOING)) {
		add_header(req, "From", of);
		add_header(req, "To", ot);
	} else {
		add_header(req, "From", ot);
		add_header(req, "To", of);
	}
	add_header(req, "Contact", p->our_contact);
	copy_header(req, orig, "Call-ID");
	add_header(req, "CSeq", tmp);

	add_header(req, "User-Agent", global.useragent);
	add_header(req, "Max-Forwards", DEFAULT_MAX_FORWARDS);

	if (!ast_strlen_zero(p->rpid))
		add_header(req, "Remote-Party-ID", p->rpid);

	return 0;
}



