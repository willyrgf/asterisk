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

/* Lets try to scetch a new
	CHAN_SIP3 Authentication scheme

	1) If a user claims to be FROM a domain we host
		- authenticate, always!
	2) If the request is to a URI published in the
		context specified in the [general] section
		or, lacking that, "default"
		- Let them in if the domain belongs
		  to us
	3) If the call is to a service not published
		in the "free context"
		- Authenticate, regardless of domain

We need to separate authentication from From: user names
- account is matched on authentication user in the digest

If policyfromauth = yes, then the From: username part needs
to be equal to the auth user (default yes today)

Each account can have a list of valid From: uri's
	(username@domain)

- Will this work for subscriptions?

This is for devices. Trunks will have separate settings.
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

/*! \brief Authenticate for outbound registration */
int do_register_auth(struct sip_pvt *p, struct sip_request *req, enum sip_auth_type code)
{
	char *header, *respheader;
	char digest[1024];

	p->authtries++;
	auth_headers(code, &header, &respheader);
	memset(digest,0,sizeof(digest));
	if (reply_digest(p, req, header, SIP_REGISTER, digest, sizeof(digest))) {
		/* There's nothing to use for authentication */
 		/* No digest challenge in request */
 		if (sip_debug_test_pvt(p) && p->registry)
 			ast_verbose("No authentication challenge, sending blank registration to domain/host name %s\n", p->registry->hostname);
 			/* No old challenge */
		return -1;
	}
	if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY))
		append_history(p, "RegistryAuth", "Try: %d", p->authtries);
 	if (sip_debug_test_pvt(p) && p->registry)
 		ast_verbose("Responding to challenge, registration to domain/host name %s\n", p->registry->hostname);
	return transmit_register(p->registry, SIP_REGISTER, digest, respheader); 
}

/*! \brief Add authentication on outbound SIP packet */
int do_proxy_auth(struct sip_pvt *p, struct sip_request *req, enum sip_auth_type code, int sipmethod, int init)
{
	char *header, *respheader;
	char digest[1024];

	if (!p->options && !(p->options = ast_calloc(1, sizeof(*p->options))))
		return -2;

	p->authtries++;
	auth_headers(code, &header, &respheader);
	if (option_debug > 1)
		ast_log(LOG_DEBUG, "Auth attempt %d on %s\n", p->authtries, sip_method2txt(sipmethod));
	memset(digest, 0, sizeof(digest));
	if (reply_digest(p, req, header, sipmethod, digest, sizeof(digest) )) {
		/* No way to authenticate */
		return -1;
	}
	/* Now we have a reply digest */
	p->options->auth = digest;
	p->options->authheader = respheader;
	return transmit_invite(p, sipmethod, sipmethod == SIP_INVITE, init); 
}

/*! \brief  reply to authentication for outbound registrations
\return	Returns -1 if we have no auth 
\note	This is used for register= servers in sip.conf, SIP proxies we register
	with  for receiving calls from.  */
int reply_digest(struct sip_pvt *p, struct sip_request *req, char *header, int sipmethod,  char *digest, int digest_len)
{
	char tmp[512];
	char *c;
	char oldnonce[256];

	/* table of recognised keywords, and places where they should be copied */
	const struct x {
		const char *key;
		int field_index;
	} *i, keys[] = {
		{ "realm=", ast_string_field_index(p, realm) },
		{ "nonce=", ast_string_field_index(p, nonce) },
		{ "opaque=", ast_string_field_index(p, opaque) },
		{ "qop=", ast_string_field_index(p, qop) },
		{ "domain=", ast_string_field_index(p, domain) },
		{ NULL, 0 },
	};

	ast_copy_string(tmp, get_header(req, header), sizeof(tmp));
	if (ast_strlen_zero(tmp)) 
		return -1;
	if (strncasecmp(tmp, "Digest ", strlen("Digest "))) {
		ast_log(LOG_WARNING, "missing Digest.\n");
		return -1;
	}
	c = tmp + strlen("Digest ");
	ast_copy_string(oldnonce, p->nonce, sizeof(oldnonce));
	while (c && *(c = ast_skip_blanks(c))) {	/* lookup for keys */
		for (i = keys; i->key != NULL; i++) {
			char *src, *separator;
			if (strncasecmp(c, i->key, strlen(i->key)) != 0)
				continue;
			/* Found. Skip keyword, take text in quotes or up to the separator. */
			c += strlen(i->key);
			if (*c == '"') {
				src = ++c;
				separator = "\"";
			} else {
				src = c;
				separator = ",";
			}
			strsep(&c, separator); /* clear separator and move ptr */
			ast_string_field_index_set(p, i->field_index, src);
			break;
		}
		if (i->key == NULL) /* not found, try ',' */
			strsep(&c, ",");
	}
	/* Reset nonce count */
	if (strcmp(p->nonce, oldnonce)) 
		p->noncecount = 0;

	/* Save auth data for following registrations */
	if (p->registry) {
		struct sip_registry *r = p->registry;

		if (strcmp(r->nonce, p->nonce)) {
			ast_string_field_set(r, realm, p->realm);
			ast_string_field_set(r, nonce, p->nonce);
			ast_string_field_set(r, domain, p->domain);
			ast_string_field_set(r, opaque, p->opaque);
			ast_string_field_set(r, qop, p->qop);
			r->noncecount = 0;
		}
	}
	return build_reply_digest(p, sipmethod, digest, digest_len); 
}

/*! \brief  Build reply digest 
\return	Returns -1 if we have no auth 
\note	Build digest challenge for authentication of peers (for registration) 
	and users (for calls). Also used for authentication of CANCEL and BYE 
*/
int build_reply_digest(struct sip_pvt *p, int method, char* digest, int digest_len)
{
	char a1[256];
	char a2[256];
	char a1_hash[256];
	char a2_hash[256];
	char resp[256];
	char resp_hash[256];
	char uri[256];
	char cnonce[80];
	const char *username;
	const char *secret;
	const char *md5secret;
	struct sip_auth *auth = NULL;	/* Realm authentication */

	if (!ast_strlen_zero(p->domain))
		ast_copy_string(uri, p->domain, sizeof(uri));
	else if (!ast_strlen_zero(p->uri))
		ast_copy_string(uri, p->uri, sizeof(uri));
	else
		snprintf(uri, sizeof(uri), "sip:%s@%s",p->username, ast_inet_ntoa(p->sa.sin_addr));

	snprintf(cnonce, sizeof(cnonce), "%08lx", ast_random());

 	/* Check if we have separate auth credentials */
 	if ((auth = find_realm_authentication(authl, p->realm))) {
		ast_log(LOG_WARNING, "use realm [%s] from peer [%s][%s]\n",
			auth->username, p->peername, p->username);
 		username = auth->username;
 		secret = auth->secret;
 		md5secret = auth->md5secret;
		if (sipdebug)
 			ast_log(LOG_DEBUG,"Using realm %s authentication for call %s\n", p->realm, p->callid);
 	} else {
 		/* No authentication, use peer or register= config */
 		username = p->authname;
 		secret =  p->peersecret;
 		md5secret = p->peermd5secret;
 	}
	if (ast_strlen_zero(username))	/* We have no authentication */
		return -1;

 	/* Calculate SIP digest response */
 	snprintf(a1,sizeof(a1), "%s:%s:%s", username, p->realm, secret);
	snprintf(a2,sizeof(a2), "%s:%s", sip_method2txt(method), uri);
	if (!ast_strlen_zero(md5secret))
		ast_copy_string(a1_hash, md5secret, sizeof(a1_hash));
	else
		ast_md5_hash(a1_hash, a1);
	ast_md5_hash(a2_hash,a2);

	p->noncecount++;
	if (!ast_strlen_zero(p->qop))
		snprintf(resp,sizeof(resp),"%s:%s:%08x:%s:%s:%s", a1_hash, p->nonce, p->noncecount, cnonce, "auth", a2_hash);
	else
		snprintf(resp,sizeof(resp),"%s:%s:%s", a1_hash, p->nonce, a2_hash);
	ast_md5_hash(resp_hash, resp);
	/* XXX We hard code our qop to "auth" for now.  XXX */
	if (!ast_strlen_zero(p->qop))
		snprintf(digest, digest_len, "Digest username=\"%s\", realm=\"%s\", algorithm=MD5, uri=\"%s\", nonce=\"%s\", response=\"%s\", opaque=\"%s\", qop=auth, cnonce=\"%s\", nc=%08x", username, p->realm, uri, p->nonce, resp_hash, p->opaque, cnonce, p->noncecount);
	else
		snprintf(digest, digest_len, "Digest username=\"%s\", realm=\"%s\", algorithm=MD5, uri=\"%s\", nonce=\"%s\", response=\"%s\", opaque=\"%s\"", username, p->realm, uri, p->nonce, resp_hash, p->opaque);

	return 0;
}
