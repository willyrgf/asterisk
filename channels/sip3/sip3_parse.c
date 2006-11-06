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

/*! \brief Get tag from packet 
 *
 * \return Returns the pointer to the provided tag buffer,
 *         or NULL if the tag was not found.
 */
const char *gettag(const char *header, char *tagbuf, int tagbufsize)
{
	const char *thetag;

	if (!tagbuf)
		return NULL;
	tagbuf[0] = '\0'; 	/* reset the buffer */
	thetag = strcasestr(header, ";tag=");
	if (thetag) {
		thetag += 5;
		ast_copy_string(tagbuf, thetag, tagbufsize);
		return strsep(&tagbuf, ";");
	}
	return NULL;
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
static unsigned int parse_sip_options(struct sip_dialog *pvt, const char *supported)
{
	char *next, *sep;
	char *temp;
	unsigned int profile = 0;
	int i, found;

	if (ast_strlen_zero(supported))
		return 0;
	temp = ast_strdupa(supported);

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


/*! \brief Find compressed SIP alias */
const char *find_alias(const char *name, const char *_default)
{
	/*! \brief Structure for conversion between compressed SIP and "normal" SIP */
	static const struct cfalias {
		char * const fullname;
		char * const shortname;
	} aliases[] = {
		{ "Content-Type",	 "c" },
		{ "Content-Encoding",	 "e" },
		{ "From",		 "f" },
		{ "Call-ID",		 "i" },
		{ "Contact",		 "m" },
		{ "Content-Length",	 "l" },
		{ "Subject",		 "s" },
		{ "To",			 "t" },
		{ "Supported",		 "k" },
		{ "Refer-To",		 "r" },
		{ "Referred-By",	 "b" },
		{ "Allow-Events",	 "u" },
		{ "Event",		 "o" },
		{ "Via",		 "v" },
		{ "Accept-Contact",      "a" },
		{ "Reject-Contact",      "j" },
		{ "Request-Disposition", "d" },
		{ "Session-Expires",     "x" },
	};
	int x;

	for (x=0; x<sizeof(aliases) / sizeof(aliases[0]); x++) 
		if (!strcasecmp(aliases[x].fullname, name))
			return aliases[x].shortname;

	return _default;
}

static const char *__get_header(const struct sip_request *req, const char *name, int *start)
{
	int pass;

	/*
	 * Technically you can place arbitrary whitespace both before and after the ':' in
	 * a header, although RFC3261 clearly says you shouldn't before, and place just
	 * one afterwards.  If you shouldn't do it, what absolute idiot decided it was 
	 * a good idea to say you can do it, and if you can do it, why in the hell would.
	 * you say you shouldn't.
	 */
	for (pass = 0; name && pass < 2;pass++) {
		int x, len = strlen(name);
		for (x=*start; x<req->headers; x++) {
			if (!strncasecmp(req->header[x], name, len)) {
				char *r = req->header[x] + len;	/* skip name */
				r = ast_skip_blanks(r);

				if (*r == ':') {
					*start = x+1;
					return ast_skip_blanks(r+1);
				}
			}
		}
		if (pass == 0) /* Try aliases */
			name = find_alias(name, NULL);
	}

	/* Don't return NULL, so get_header is always a valid pointer */
	return "";
}

/*! \brief Get header from SIP request */
const char *get_header(const struct sip_request *req, const char *name)
{
	int start = 0;
	return __get_header(req, name, &start);
}

/*! \brief Copy one header field from one request to another */
int copy_header(struct sip_request *req, const struct sip_request *orig, const char *field)
{
	const char *tmp = get_header(orig, field);

	if (!ast_strlen_zero(tmp)) /* Add what we're responding to */
		return add_header(req, field, tmp);
	ast_log(LOG_NOTICE, "No field '%s' present to copy\n", field);
	return -1;
}

/*! \brief Copy all headers from one request to another */
int copy_all_header(struct sip_request *req, const struct sip_request *orig, const char *field)
{
	int start = 0;
	int copied = 0;
	int res;

	for (;;) {
		const char *tmp = __get_header(orig, field, &start);

		if (ast_strlen_zero(tmp))
			break;
		/* Add what we're responding to */
		res = add_header(req, field, tmp);
		if (res != -1)
			copied++;
		else
			return -1;
		
	}
	return copied ? 0 : -1;
}

/*! \brief Copy SIP VIA Headers from the request to the response
\note	If the client indicates that it wishes to know the port we received from,
	it adds ;rport without an argument to the topmost via header. We need to
	add the port number (from our point of view) to that parameter.
	We always add ;received=<ip address> to the topmost via header.
	Received: RFC 3261, rport RFC 3581 */
int copy_via_headers(struct sip_dialog *p, struct sip_request *req, const struct sip_request *orig, const char *field)
{
	int copied = 0;
	int start = 0;

	for (;;) {
		char new[256];
		const char *oh = __get_header(orig, field, &start);

		if (ast_strlen_zero(oh))
			break;

		if (!copied) {	/* Only check for empty rport in topmost via header */
			char *rport;

			/* Find ;rport;  (empty request) */
			rport = strstr(oh, ";rport");
			if (rport && *(rport+6) == '=') 
				rport = NULL;		/* We already have a parameter to rport */

			if (rport && ((ast_test_flag(&p->flags[0], SIP_NAT) == SIP_NAT_ALWAYS) ||
				(ast_test_flag(&p->flags[0], SIP_NAT) == SIP_NAT_RFC3581) ) }
				/* We need to add received port - rport */
				char tmp[256], *end;

				ast_copy_string(tmp, oh, sizeof(tmp));

				rport = strstr(tmp, ";rport");

				if (rport) {
					end = strchr(rport + 1, ';');
					if (end)
						memmove(rport, end, strlen(end) + 1);
					else
						*rport = '\0';
				}

				/* Add rport to first VIA header if requested */
				/* Whoo hoo!  Now we can indicate port address translation too!  Just
				   another RFC (RFC3581). I'll leave the original comments in for
				   posterity.  */
				snprintf(new, sizeof(new), "%s;received=%s;rport=%d",
					tmp, ast_inet_ntoa(p->recv.sin_addr),
					ntohs(p->recv.sin_port));
			} else {
				/* We should *always* add a received to the topmost via */
				snprintf(new, sizeof(new), "%s;received=%s",
					oh, ast_inet_ntoa(p->recv.sin_addr));
			}
			oh = new;	/* the header to copy */
		}  /* else add the following via headers untouched */
		add_header(req, field, oh);
		copied++;
	}
	if (!copied) {
		ast_log(LOG_NOTICE, "No header field '%s' present to copy\n", field);
		return -1;
	}
	return 0;
}

/*! \brief Locate closing quote in a string, skipping escaped quotes.
 * optionally with a limit on the search.
 * start must be past the first quote.
 */
const char *find_closing_quote(const char *start, const char *lim)
{
        char last_char = '\0';
        const char *s;
        for (s = start; *s && s != lim; last_char = *s++) {
                if (*s == '"' && last_char != '\\')
                        break;
        }
        return s;
}

/*! \brief Pick out text in brackets from character string
	\return pointer to terminated stripped string
	\param tmp input string that will be modified
	Examples:

	"foo" <bar>	valid input, returns bar
	foo		returns the whole string
	< "foo ... >	returns the string between brackets
	< "foo...	bogus (missing closing bracket), returns the whole string
			XXX maybe should still skip the opening bracket
 */
char *get_in_brackets(char *tmp)
{
	const char *parse = tmp;
	char *first_bracket;

	/*
	 * Skip any quoted text until we find the part in brackets.
         * On any error give up and return the full string.
         */
        while ( (first_bracket = strchr(parse, '<')) ) {
                char *first_quote = strchr(parse, '"');

		if (!first_quote || first_quote > first_bracket)
			break; /* no need to look at quoted part */
		/* the bracket is within quotes, so ignore it */
		parse = find_closing_quote(first_quote + 1, NULL);
		if (!*parse) { /* not found, return full string ? */
			/* XXX or be robust and return in-bracket part ? */
			ast_log(LOG_WARNING, "No closing quote found in '%s'\n", tmp);
			break;
		}
		parse++;
	}
	if (first_bracket) {
		char *second_bracket = strchr(first_bracket + 1, '>');
		if (second_bracket) {
			*second_bracket = '\0';
			tmp = first_bracket + 1;
		} else {
			ast_log(LOG_WARNING, "No closing bracket found in '%s'\n", tmp);
		}
	}
	return tmp;
}

/*! \brief  Parse multiline SIP headers into one header */
GNURK int lws2sws(char *msgbuf, int len) 
{
	int h = 0, t = 0; 
	int lws = 0; 

	for (; h < len;) { 
		/* Eliminate all CRs */ 
		if (msgbuf[h] == '\r') { 
			h++; 
			continue; 
		} 
		/* Check for end-of-line */ 
		if (msgbuf[h] == '\n') { 
			/* Check for end-of-message */ 
			if (h + 1 == len) 
				break; 
			/* Check for a continuation line */ 
			if (msgbuf[h + 1] == ' ' || msgbuf[h + 1] == '\t') { 
				/* Merge continuation line */ 
				h++; 
				continue; 
			} 
			/* Propagate LF and start new line */ 
			msgbuf[t++] = msgbuf[h++]; 
			lws = 0;
			continue; 
		} 
		if (msgbuf[h] == ' ' || msgbuf[h] == '\t') { 
			if (lws) { 
				h++; 
				continue; 
			} 
			msgbuf[t++] = msgbuf[h++]; 
			lws = 1; 
			continue; 
		} 
		msgbuf[t++] = msgbuf[h++]; 
		if (lws) 
			lws = 0; 
	} 
	msgbuf[t] = '\0'; 
	return t; 
}

/*! \brief Generate 32 byte random string for callid's etc */
char *generate_random_string(char *buf, size_t size)
{
	long val[4];
	int x;

	for (x=0; x<4; x++)
		val[x] = ast_random();
	snprintf(buf, size, "%08lx%08lx%08lx%08lx", val[0], val[1], val[2], val[3]);

	return buf;
}

/*! \brief Parse first line of incoming SIP request */
int determine_firstline_parts(struct sip_request *req) 
{
	char *e = ast_skip_blanks(req->header[0]);	/* there shouldn't be any */

	if (!*e)
		return -1;
	req->rlPart1 = e;	/* method or protocol */
	e = ast_skip_nonblanks(e);
	if (*e)
		*e++ = '\0';
	/* Get URI or status code */
	e = ast_skip_blanks(e);
	if ( !*e )
		return -1;
	ast_trim_blanks(e);

	if (!strcasecmp(req->rlPart1, "SIP/2.0") ) { /* We have a response */
		if (strlen(e) < 3)	/* status code is 3 digits */
			return -1;
		req->rlPart2 = e;
	} else { /* We have a request */
		if ( *e == '<' ) { /* XXX the spec says it must not be in <> ! */
			ast_log(LOG_WARNING, "bogus uri in <> %s\n", e);
			e++;
			if (!*e)
				return -1; 
		}
		req->rlPart2 = e;	/* URI */
		e = ast_skip_nonblanks(e);
		if (*e)
			*e++ = '\0';
		e = ast_skip_blanks(e);
		if (strcasecmp(e, "SIP/2.0") ) {
			ast_log(LOG_WARNING, "Bad request protocol %s\n", e);
			return -1;
		}
	}
	return 1;
}

/*! \brief Check Contact: URI of SIP message */
void extract_uri(struct sip_dialog *p, struct sip_request *req)
{
	char stripped[256];
	char *c;

	ast_copy_string(stripped, get_header(req, "Contact"), sizeof(stripped));
	c = get_in_brackets(stripped);
	c = strsep(&c, ";");	/* trim ; and beyond */
	if (!ast_strlen_zero(c))
		ast_string_field_set(p, uri, c);
}

/*! \brief Parse 302 Moved temporalily response */
void parse_moved_contact(struct sip_dialog *p, struct sip_request *req)
{
	char tmp[256];
	char *s, *e;
	char *domain;

	ast_copy_string(tmp, get_header(req, "Contact"), sizeof(tmp));
	s = get_in_brackets(tmp);
	s = strsep(&s, ";");	/* strip ; and beyond */
	if (ast_test_flag(&p->flags[0], SIP_PROMISCREDIR)) {
		if (!strncasecmp(s, "sip:", 4))
			s += 4;
		e = strchr(s, '/');
		if (e)
			*e = '\0';
		if (option_debug)
			ast_log(LOG_DEBUG, "Found promiscuous redirection to 'SIP/%s'\n", s);
		if (p->owner)
			ast_string_field_build(p->owner, call_forward, "SIP/%s", s);
	} else {
		e = strchr(tmp, '@');
		if (e) {
			*e++ = '\0';
			domain = e;
		} else {
			/* No username part */
			domain = tmp;
		}
		e = strchr(tmp, '/');
		if (e)
			*e = '\0';
		if (!strncasecmp(s, "sip:", 4))
			s += 4;
		if (option_debug > 1)
			ast_log(LOG_DEBUG, "Received 302 Redirect to extension '%s' (domain %s)\n", s, domain);
		if (p->owner) {
			pbx_builtin_setvar_helper(p->owner, "SIPDOMAIN", domain);
			ast_string_field_set(p->owner, call_forward, s);
		}
	}
}

