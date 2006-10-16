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
 * \brief Various SIP authentication functions
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

#include "sip3core.h"		/* Old functions */
#include "sip3funcs.h"		/* Moved functions */

/*! \brief return the request and response heade for a 401 or 407 code */
void auth_headers(enum sip_auth_type code, char **header, char **respheader)
{
	if (code == WWW_AUTH) {			/* 401 */
		*header = "WWW-Authenticate";
		*respheader = "Authorization";
	} else if (code == PROXY_AUTH) {	/* 407 */
		*header = "Proxy-Authenticate";
		*respheader = "Proxy-Authorization";
	} else {
		ast_verbose("-- wrong response code %d\n", code);
		*header = *respheader = "Invalid";
	}
}

/*! \brief  Check user authorization from peer definition 
	Some actions, like REGISTER and INVITEs from peers require
	authentication (if peer have secret set) 
    \return 0 on success, non-zero on error
*/
enum check_auth_result check_auth(struct sip_pvt *p, struct sip_request *req, const char *username,
					 const char *secret, const char *md5secret, int sipmethod,
					 char *uri, enum xmittype reliable, int ignore)
{
	const char *response = "407 Proxy Authentication Required";
	char *reqheader;
	char *respheader;
	const char *authtoken;
	char a1_hash[256];
	char resp_hash[256]="";
	char tmp[BUFSIZ * 2];                /* Make a large enough buffer */
	char *c;
	int  wrongnonce = FALSE;
	int  good_response;
	const char *usednonce = p->randdata;

	/* table of recognised keywords, and their value in the digest */
	enum keys { K_RESP, K_URI, K_USER, K_NONCE, K_LAST };
	struct x {
		const char *key;
		const char *s;
	} *i, keys[] = {
		[K_RESP] = { "response=", "" },
		[K_URI] = { "uri=", "" },
		[K_USER] = { "username=", "" },
		[K_NONCE] = { "nonce=", "" },
		[K_LAST] = { NULL, NULL}
	};

	/* Always OK if no secret */
	if (ast_strlen_zero(secret) && ast_strlen_zero(md5secret))
		return AUTH_SUCCESSFUL;
	response = "401 Unauthorized";
	auth_headers(WWW_AUTH, &respheader, &reqheader);	
	authtoken =  get_header(req, reqheader);	
	if (ignore && !ast_strlen_zero(p->randdata) && ast_strlen_zero(authtoken)) {
		/* This is a retransmitted invite/register/etc, don't reconstruct authentication
		   information */
		if (!reliable) {
			/* Resend message if this was NOT a reliable delivery.   Otherwise the
			   retransmission should get it */
			transmit_response_with_auth(p, response, req, p->randdata, reliable, respheader, 0);
			/* Schedule auto destroy in 32 seconds (according to RFC 3261) */
			sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT);
		}
		return AUTH_CHALLENGE_SENT;
	} else if (ast_strlen_zero(p->randdata) || ast_strlen_zero(authtoken)) {
		/* We have no auth, so issue challenge and request authentication */
		ast_string_field_build(p, randdata, "%08lx", ast_random());	/* Create nonce for challenge */
		transmit_response_with_auth(p, response, req, p->randdata, reliable, respheader, 0);
		/* Schedule auto destroy in 32 seconds */
		sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT);
		return AUTH_CHALLENGE_SENT;
	} 

	/* --- We have auth, so check it */

	/* Whoever came up with the authentication section of SIP can suck my %&#$&* for not putting
   	   an example in the spec of just what it is you're doing a hash on. */


	/* Make a copy of the response and parse it */
	ast_copy_string(tmp, authtoken, sizeof(tmp));
	c = tmp;

	while(c && *(c = ast_skip_blanks(c)) ) { /* lookup for keys */
		for (i = keys; i->key != NULL; i++) {
			const char *separator = ",";	/* default */

			if (strncasecmp(c, i->key, strlen(i->key)) != 0)
				continue;
			/* Found. Skip keyword, take text in quotes or up to the separator. */
			c += strlen(i->key);
			if (*c == '"') { /* in quotes. Skip first and look for last */
				c++;
				separator = "\"";
			}
			i->s = c;
			strsep(&c, separator);
			break;
		}
		if (i->key == NULL) /* not found, jump after space or comma */
			strsep(&c, " ,");
	}

	/* Verify that digest username matches  the username we auth as */
	if (strcmp(username, keys[K_USER].s)) {
		ast_log(LOG_WARNING, "username mismatch, have <%s>, digest has <%s>\n",
			username, keys[K_USER].s);
		/* Oops, we're trying something here */
		return AUTH_USERNAME_MISMATCH;
	}

	/* Verify nonce from request matches our nonce.  If not, send 401 with new nonce */
	if (strcasecmp(p->randdata, keys[K_NONCE].s)) { /* XXX it was 'n'casecmp ? */
		wrongnonce = TRUE;
		usednonce = keys[K_NONCE].s;
	}

	if (!ast_strlen_zero(md5secret))
		ast_copy_string(a1_hash, md5secret, sizeof(a1_hash));
	else {
		char a1[256];
		snprintf(a1, sizeof(a1), "%s:%s:%s", username, global.realm, secret);
		ast_md5_hash(a1_hash, a1);
	}

	/* compute the expected response to compare with what we received */
	{
		char a2[256];
		char a2_hash[256];
		char resp[256];

		snprintf(a2, sizeof(a2), "%s:%s", sip_method2txt(sipmethod), S_OR(keys[K_URI].s, uri));
		ast_md5_hash(a2_hash, a2);
		snprintf(resp, sizeof(resp), "%s:%s:%s", a1_hash, usednonce, a2_hash);
		ast_md5_hash(resp_hash, resp);
	}

	good_response = keys[K_RESP].s &&
			!strncasecmp(keys[K_RESP].s, resp_hash, strlen(resp_hash));
	if (wrongnonce) {
		ast_string_field_build(p, randdata, "%08lx", ast_random());
		if (good_response) {
			if (sipdebug)
				ast_log(LOG_NOTICE, "Correct auth, but based on stale nonce received from '%s'\n", get_header(req, "To"));
			/* We got working auth token, based on stale nonce . */
			transmit_response_with_auth(p, response, req, p->randdata, reliable, respheader, 1);
		} else {
			/* Everything was wrong, so give the device one more try with a new challenge */
			if (sipdebug)
				ast_log(LOG_NOTICE, "Bad authentication received from '%s'\n", get_header(req, "To"));
			transmit_response_with_auth(p, response, req, p->randdata, reliable, respheader, 0);
		}

		/* Schedule auto destroy in 32 seconds */
		sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT);
		return AUTH_CHALLENGE_SENT;
	} 
	if (good_response)
		return AUTH_SUCCESSFUL;

	/* Ok, we have a bad username/secret pair */
	/* Challenge again, and again, and again */
	transmit_response_with_auth(p, response, req, p->randdata, reliable, respheader, 0);
	sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT);

	return AUTH_CHALLENGE_SENT;
}

