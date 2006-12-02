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
 * \brief Various SIP functions for services, registrations for SIP service with other providers/servers
 * Version 3 of chan_sip
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Olle E. Johansson <oej@edvina.net> (all the chan_sip3 changes)
 *
 * See Also:
 * \arg \ref AstCREDITS
 * \arg \ref Chan_sip3_00index
 *
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

/* Forward declaration */
static int sip_reregister(void *data);

/*! \brief  The register list: Other SIP proxys we register with and place calls to */
struct sip_register_list regl;

/*! \brief Convert registration state status to string */
char *regstate2str(enum sipregistrystate regstate)
{
	switch(regstate) {
	case REG_STATE_FAILED:
		return "Failed";
	case REG_STATE_UNREGISTERED:
		return "Unregistered";
	case REG_STATE_REGSENT:
		return "Request Sent";
	case REG_STATE_AUTHSENT:
		return "Auth. Sent";
	case REG_STATE_REGISTERED:
		return "Registered";
	case REG_STATE_REJECTED:
		return "Rejected";
	case REG_STATE_TIMEOUT:
		return "Timeout";
	case REG_STATE_NOAUTH:
		return "No Authentication";
	default:
		return "Unknown";
	}
}

/*! \brief Build SIP Call-ID value for a REGISTER transaction */
static void build_callid_registry(struct sip_registry *reg, struct in_addr ourip, const char *fromdomain)
{
	char buf[33];

	const char *host = S_OR(fromdomain, ast_inet_ntoa(ourip));

	ast_string_field_build(reg, callid, "%s@%s", generate_random_string(buf, sizeof(buf)), host);
}


/*! \brief Send all known registrations 
	\note We space them out not to congest the network and the server 
*/
void sip_send_all_registers(void)
{
	int ms;
	int regspacing;
	if (!sipcounters.registry_objects)
		return;
	regspacing = expiry.default_expiry * 1000/sipcounters.registry_objects;
	if (regspacing > 100)
		regspacing = 100;
	ms = regspacing;
	ASTOBJ_CONTAINER_TRAVERSE(&regl, 1, do {
		ASTOBJ_WRLOCK(iterator);
		if (iterator->expire > -1)
			ast_sched_del(sched, iterator->expire);
		ms += regspacing;
		iterator->expire = ast_sched_add(sched, ms, sip_reregister, iterator);
		ASTOBJ_UNLOCK(iterator);
	} while (0)
	);
}

/*! \brief Parse register=> line in sip.conf and add to registry */
int sip_register(char *value, int lineno, struct sip_peer *peer)
{
	struct sip_registry *reg;
	char username[256] = "";
	char randomcontact[256];
	char *hostname = NULL, *secret = NULL, *authuser = NULL;
	char *porta = NULL;
	char *contact = NULL;
	char *extension = NULL;
	int portnum = 0;
	
	if (peer != NULL) {	/* Build registration string from peer info */
		/* Need to copy port number as well */
		if (ast_strlen_zero(peer->fromuser))
			snprintf(username, sizeof(username), "%s:%s@%s/%s",
				peer->name, peer->secret, peer->tohost, peer->regexten);
		else
			snprintf(username, sizeof(username), "%s:%s:%s@%s/%s",
				peer->name, peer->secret, peer->fromuser, peer->tohost, peer->regexten);
	} else if (value)
		ast_copy_string(username, value, sizeof(username));
	else
		username[0] = '\0';

	
	/* ------ Parse registration string ----------- */
	/* First split around the last '@' then parse the two components. */
	hostname = strrchr(username, '@'); /* allow @ in the first part */
	if (hostname)
		*hostname++ = '\0';
	if (ast_strlen_zero(username) || ast_strlen_zero(hostname)) {
		ast_log(LOG_WARNING, "Format for registration is user[:secret[:authuser]]@host[:port][/contact] at line %d\n", lineno);
		return -1;
	}
	/* split user[:secret[:authuser]] */
	secret = strchr(username, ':');
	if (secret) {
		*secret++ = '\0';
		authuser = strchr(secret, ':');
		if (authuser)
			*authuser++ = '\0';
	}
	/* split host[:port][/contact] */
	contact = strchr(hostname, '/');
	if (contact)
		*contact++ = '\0';
	if (ast_strlen_zero(contact))
		contact = "s";
	porta = strchr(hostname, ':');
	if (porta) {
		*porta++ = '\0';
		portnum = atoi(porta);
		if (portnum == 0) {
			ast_log(LOG_WARNING, "%s is not a valid port number at line %d\n", porta, lineno);
			return -1;
		}
	}

	/* Allocate data */
	if (!(reg = ast_calloc(1, sizeof(*reg)))) {
		ast_log(LOG_ERROR, "Out of memory. Can't allocate SIP registry entry\n");
		return -1;
	}

	if (ast_string_field_init(reg, 256)) {
		ast_log(LOG_ERROR, "Out of memory. Can't allocate SIP registry strings\n");
		free(reg);
		return -1;
	}

	if (peer) {
		reg->peer = peer;
		peer->registry = reg;
		// xxx?? ASTOBJ_REF(peer);		/* Add reference counter to peer */
	}

	sipcounters.registry_objects++;
	ASTOBJ_INIT(reg);
	if (username)
		ast_string_field_set(reg, username, username);
	if (hostname)
		ast_string_field_set(reg, hostname, hostname);
	if (authuser)
		ast_string_field_set(reg, authuser, authuser);
	if (secret)
		ast_string_field_set(reg, secret, secret);

	if (extension)
		ast_string_field_set(reg, extension, extension);
	/* Build a random contact string for this registration entry */
	generate_random_string(randomcontact, sizeof(randomcontact));
	if (sipdebug)
		ast_string_field_build(reg, contact, "%s-%s-%s-debug", REG_MAGICMARKER, randomcontact, extension);
	else
		ast_string_field_build(reg, contact, "%s-%s", REG_MAGICMARKER, randomcontact);

	reg->expire = -1;
	reg->expiry = expiry.default_expiry;
	reg->timeout =  -1;
	reg->refresh = expiry.default_expiry;
	reg->portno = porta ? atoi(porta) : 0;
	reg->callid_valid = FALSE;
	reg->ocseq = INITIAL_CSEQ;
	ASTOBJ_CONTAINER_LINK(&regl, reg);	/* Add the new registry entry to the list */
	ASTOBJ_UNREF(reg,sip_registry_destroy);
	return 0;
}

/*! \brief Destroy registry object
	Objects created with the register= statement in static configuration */
void sip_registry_destroy(struct sip_registry *reg)
{
	/* Really delete */
	if (option_debug > 2)
		ast_log(LOG_DEBUG, "Destroying registry entry for %s@%s\n", reg->username, reg->hostname);

	if (reg->call) {
		/* Clear registry before destroying to ensure
		   we don't get reentered trying to grab the registry lock */
		reg->call->registry = NULL;
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "Destroying active SIP dialog for registry %s@%s\n", reg->username, reg->hostname);
		sip_destroy(reg->call);
	}
	if (reg->expire > -1)
		ast_sched_del(sched, reg->expire);
	if (reg->timeout > -1)
		ast_sched_del(sched, reg->timeout);
	if (reg->peer)
		reg->peer->registry = NULL;		/* XXX ASTOBJ_UNREF ??? */
	ast_string_field_free_pools(reg);
	sipcounters.registry_objects--;
	free(reg);
	
}

/*! \brief Register with SIP proxy */
static int __sip_do_register(struct sip_registry *r)
{
	int res;

	res = transmit_register(r, SIP_REGISTER, NULL, NULL);
	return res;
}

/*! \brief Update registration with SIP Proxy */
static int sip_reregister(void *data) 
{
	/* if we are here, we know that we need to reregister. */
	struct sip_registry *r= ASTOBJ_REF((struct sip_registry *) data);

	/* if we couldn't get a reference to the registry object, punt */
	if (!r)
		return 0;

	if (r->call && !ast_test_flag(&r->call->flags[0], SIP_NO_HISTORY)) 
		append_history(r->call, "RegistryRenew", "Account: %s@%s", r->username, r->hostname);
	/* Since registry's are only added/removed by the the monitor thread, this
	   may be overkill to reference/dereference at all here */
	if (sipdebug)
		ast_log(LOG_NOTICE, "   -- Re-registration for  %s@%s\n", r->username, r->hostname);

	r->expire = -1;
	__sip_do_register(r);
	ASTOBJ_UNREF(r, sip_registry_destroy);
	return 0;
}

/*! \brief Registration timeout, register again */
static int sip_reg_timeout(void *data)
{

	/* if we are here, our registration timed out, so we'll just do it over */
	struct sip_registry *r = ASTOBJ_REF((struct sip_registry *) data);
	struct sip_dialog *p;
	int res;

	/* if we couldn't get a reference to the registry object, punt */
	if (!r)
		return 0;

	ast_log(LOG_NOTICE, "   -- Registration for '%s@%s' timed out, trying again (Attempt #%d)\n", r->username, r->hostname, r->regattempts); 
	if (r->call) {
		/* Unlink us, destroy old call.  Locking is not relevant here because all this happens
		   in the single SIP manager thread. */
		p = r->call;
		if (p->registry)
			ASTOBJ_UNREF(p->registry, sip_registry_destroy);
		r->call = NULL;
		ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
		/* Pretend to ACK anything just in case */
		__sip_pretend_ack(p); /* XXX we need p locked, not sure we have */
	}
	/* If we have a limit, stop registration and give up */
	if (global.regattempts_max && (r->regattempts > global.regattempts_max)) {
		/* Ok, enough is enough. Don't try any more */
		/* We could add an external notification here... 
			steal it from app_voicemail :-) */
		ast_log(LOG_NOTICE, "   -- Giving up forever trying to register '%s@%s'\n", r->username, r->hostname);
		r->regstate = REG_STATE_FAILED;
	} else {
		r->regstate = REG_STATE_UNREGISTERED;
		r->timeout = -1;
		res = transmit_register(r, SIP_REGISTER, NULL, NULL);
	}
	manager_event(EVENT_FLAG_SYSTEM, "Registry", "ChannelDriver: SIP\r\nUsername: %s\r\nDomain: %s\r\nStatus: %s\r\n", r->username, r->hostname, regstate2str(r->regstate));
	ASTOBJ_UNREF(r, sip_registry_destroy);
	return 0;
}

/*! \brief Transmit register to SIP proxy or UA */
int transmit_register(struct sip_registry *r, int sipmethod, const char *auth, const char *authheader)
{
	struct sip_request req;
	char from[256];
	char to[256];
	char tmp[80];
	char addr[80];
	struct sip_dialog *p;

	/* exit if we are already in process with this registrar ?*/
	if ( r == NULL || ((auth==NULL) && (r->regstate==REG_STATE_REGSENT || r->regstate==REG_STATE_AUTHSENT))) {
		ast_log(LOG_NOTICE, "Strange, trying to register %s@%s when registration already pending\n", r->username, r->hostname);
		return 0;
	}

	if (r->call) {	/* We have a registration */
		if (!auth) {
			ast_log(LOG_WARNING, "Already have a REGISTER going on to %s@%s?? \n", r->username, r->hostname);
			return 0;
		} else {
			p = r->call;
			make_our_tag(p->tag, sizeof(p->tag));	/* create a new local tag for every register attempt */
			ast_string_field_free(p, theirtag);	/* forget their old tag, so we don't match tags when getting response */
		}
	} else {
		/* Build callid for registration if we haven't registered before */
		if (!r->callid_valid) {
			build_callid_registry(r, sipnet.__ourip, global.default_fromdomain);
			r->callid_valid = TRUE;
		}
		/* Allocate SIP packet for registration */
		if (!(p = sip_alloc( r->callid, NULL, 0, SIP_REGISTER))) {
			ast_log(LOG_WARNING, "Unable to allocate registration transaction (memory or socket error)\n");
			return 0;
		}
		if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY))
			append_history(p, "RegistryInit", "Account: %s@%s", r->username, r->hostname);
		/* Find address to hostname */
		if (create_addr(p, r->hostname)) {
			/* we have what we hope is a temporary network error,
			 * probably DNS.  We need to reschedule a registration try */
			sip_destroy(p);
			if (r->timeout > -1) {
				ast_sched_del(sched, r->timeout);
				r->timeout = ast_sched_add(sched, global.reg_timeout*1000, sip_reg_timeout, r);
				ast_log(LOG_WARNING, "Still have a registration timeout for %s@%s (create_addr() error), %d\n", r->username, r->hostname, r->timeout);
			} else {
				r->timeout = ast_sched_add(sched, global.reg_timeout*1000, sip_reg_timeout, r);
				ast_log(LOG_WARNING, "Probably a DNS error for registration to %s@%s, trying REGISTER again (after %d seconds)\n", r->username, r->hostname, global.reg_timeout);
			}
			r->regattempts++;
			return 0;
		}
		/* Copy back Call-ID in case create_addr changed it */
		ast_string_field_set(r, callid, p->callid);
		if (r->portno)
			p->sa.sin_port = htons(r->portno);
		else 	/* Set registry port to the port set from the peer definition/srv or default */
			r->portno = ntohs(p->sa.sin_port);
		ast_set_flag(&p->flags[0], SIP_OUTGOING);	/* Registration is outgoing call */
		r->call=p;			/* Save pointer to SIP packet */
		p->registry = ASTOBJ_REF(r);	/* Add pointer to registry in packet */
		if (!ast_strlen_zero(r->secret))	/* Secret (password) */
			ast_string_field_set(p, peersecret, r->secret);
		if (!ast_strlen_zero(r->md5secret))
			ast_string_field_set(p, peermd5secret, r->md5secret);
		/* User name in this realm  
		- if authuser is set, use that, otherwise use username */
		if (!ast_strlen_zero(r->authuser)) {	
			ast_string_field_set(p, peername, r->authuser);
			ast_string_field_set(p, authname, r->authuser);
		} else if (!ast_strlen_zero(r->username)) {
			ast_string_field_set(p, peername, r->username);
			ast_string_field_set(p, authname, r->username);
			ast_string_field_set(p, fromuser, r->username);
		}
		if (!ast_strlen_zero(r->username))
			ast_string_field_set(p, username, r->username);
		/* Save extension in packet */
	
		/* If we have a peer relationship, fetch som more data from taht peer.
		*/
		if (r->peer) {
			if (!ast_strlen_zero(r->peer->fromdomain))
				ast_string_field_set(p, fromdomain, r->peer->fromdomain);
		}
		ast_string_field_set(p, exten, r->contact);

		/*
		  check which address we should use in our contact header 
		  based on whether the remote host is on the external or
		  internal network so we can register through nat
		 */
		if (sip_ouraddrfor(&p->sa.sin_addr, &p->ourip))
			p->ourip = sipnet.bindaddr.sin_addr;
		build_contact(p);
	}

	/* set up a timeout */
	if (auth == NULL)  {
		if (r->timeout > -1) {
			ast_log(LOG_WARNING, "Still have a registration timeout, #%d - deleting it\n", r->timeout);
			ast_sched_del(sched, r->timeout);
		}
		r->timeout = ast_sched_add(sched, global.reg_timeout * 1000, sip_reg_timeout, r);
		if (option_debug)
			ast_log(LOG_DEBUG, "Scheduled a registration timeout for %s id  #%d \n", r->hostname, r->timeout);
	}

	if (strchr(r->username, '@')) {
		snprintf(from, sizeof(from), "<sip:%s>;tag=%s", r->username, p->tag);
		if (!ast_strlen_zero(p->theirtag))
			snprintf(to, sizeof(to), "<sip:%s>;tag=%s", r->username, p->theirtag);
		else
			snprintf(to, sizeof(to), "<sip:%s>", r->username);
	} else {
		snprintf(from, sizeof(from), "<sip:%s@%s>;tag=%s", r->username, p->tohost, p->tag);
		if (!ast_strlen_zero(p->theirtag))
			snprintf(to, sizeof(to), "<sip:%s@%s>;tag=%s", r->username, p->tohost, p->theirtag);
		else
			snprintf(to, sizeof(to), "<sip:%s@%s>", r->username, p->tohost);
	}
	
	/* Fromdomain is what we are registering to, regardless of actual
	   host name from SRV */
	snprintf(addr, sizeof(addr), "sip:%s", S_OR(p->fromdomain, r->hostname));
	ast_string_field_set(p, uri, addr);

	init_req(&req, sipmethod, addr);

	/* Add to CSEQ */
	snprintf(tmp, sizeof(tmp), "%u %s", ++r->ocseq, sip_method2txt(sipmethod));
	p->ocseq = r->ocseq;
	build_via(p, TRUE);
	add_header(&req, "Via", p->via);
	add_header(&req, "From", from);
	add_header(&req, "To", to);
	add_header(&req, "Call-ID", p->callid);
	add_header(&req, "CSeq", tmp);
	add_header(&req, "User-Agent", global.useragent);
	add_header(&req, "Max-Forwards", DEFAULT_MAX_FORWARDS);

	
	if (auth) 	/* Add auth header */
		add_header(&req, authheader, auth);
	else if (!ast_strlen_zero(r->nonce)) {
		char digest[1024];

		/* We have auth data to reuse, build a digest header! */
		if (sipdebug)
			ast_log(LOG_DEBUG, "   >>> Re-using Auth data for %s@%s\n", r->username, r->hostname);
		ast_string_field_set(p, realm, r->realm);
		ast_string_field_set(p, nonce, r->nonce);
		ast_string_field_set(p, domain, r->domain);
		ast_string_field_set(p, opaque, r->opaque);
		ast_string_field_set(p, qop, r->qop);
		p->noncecount = r->noncecount++;

		memset(digest,0,sizeof(digest));
		if(!build_reply_digest(p, sipmethod, digest, sizeof(digest)))
			add_header(&req, "Authorization", digest);
		else
			ast_log(LOG_NOTICE, "No authorization available for authentication of registration to %s@%s\n", r->username, r->hostname);
	
	}

	snprintf(tmp, sizeof(tmp), "%d", r->expiry);
	add_header(&req, "Expires", tmp);
	add_header(&req, "Contact", p->our_contact);
	add_header(&req, "Event", "registration");
	add_header_contentLength(&req, 0);

	initialize_initreq(p, &req);
	if (sip_debug_test_pvt(p))
		ast_verbose("REGISTER %d headers, %d lines\n", p->initreq.headers, p->initreq.lines);
	r->regstate = auth ? REG_STATE_AUTHSENT : REG_STATE_REGSENT;
	r->regattempts++;	/* Another attempt */
	if (option_debug > 3)
		ast_verbose("REGISTER attempt %d to %s@%s\n", r->regattempts, r->username, r->hostname);
	return send_request(p, &req, XMIT_CRITICAL, p->ocseq);
}

/*! \brief Handle responses on REGISTER to services */
int handle_response_register(struct sip_dialog *p, int resp, char *rest, struct sip_request *req, int seqno)
{
	int expires, expires_ms;
	struct sip_registry *r;
	r=p->registry;

	switch (resp) {
	case 401:	/* Unauthorized */
		if (p->authtries == MAX_AUTHTRIES || do_register_auth(p, req, resp)) {
			ast_log(LOG_NOTICE, "Failed to authenticate on REGISTER to '%s@%s' (Tries %d)\n", p->registry->username, p->registry->hostname, p->authtries);
			ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
			}
		break;
	case 403:	/* Forbidden */
		ast_log(LOG_WARNING, "Forbidden - wrong password on authentication for REGISTER for '%s' to '%s'\n", p->registry->username, p->registry->hostname);
		if (global.regattempts_max)
			p->registry->regattempts = global.regattempts_max+1;
		ast_sched_del(sched, r->timeout);
		ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
		break;
	case 404:	/* Not found */
		ast_log(LOG_WARNING, "Got 404 Not found on SIP register to service %s@%s, giving up\n", p->registry->username,p->registry->hostname);
		if (global.regattempts_max)
			p->registry->regattempts = global.regattempts_max+1;
		ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
		r->call = NULL;
		ast_sched_del(sched, r->timeout);
		break;
	case 407:	/* Proxy auth */
		if (p->authtries == MAX_AUTHTRIES || do_register_auth(p, req, resp)) {
			ast_log(LOG_NOTICE, "Failed to authenticate on REGISTER to '%s' (tries '%d')\n", get_header(&p->initreq, "From"), p->authtries);
			ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
		}
		break;
	case 423:	/* Interval too brief */
		r->expiry = atoi(get_header(req, "Min-Expires"));
		ast_log(LOG_WARNING, "Got 423 Interval too brief for service %s@%s, minimum is %d seconds\n", p->registry->username, p->registry->hostname, r->expiry);
		ast_sched_del(sched, r->timeout);
		r->timeout = -1;
		if (r->call) {
			r->call = NULL;
			ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
		}
		if (r->expiry > expiry.max_expiry) {
			ast_log(LOG_WARNING, "Required expiration time from %s@%s is too high, giving up\n", p->registry->username, p->registry->hostname);
			r->expiry = expiry.default_expiry;
			r->regstate = REG_STATE_REJECTED;
		} else {
			r->regstate = REG_STATE_UNREGISTERED;
			transmit_register(r, SIP_REGISTER, NULL, NULL);
		}
		manager_event(EVENT_FLAG_SYSTEM, "Registry", "Channel: SIP\r\nUsername: %s\r\nDomain: %s\r\nStatus: %s\r\n", r->username, r->hostname, regstate2str(r->regstate));
		break;
	case 479:	/* SER: Not able to process the URI - address is wrong in register*/
		ast_log(LOG_WARNING, "Got error 479 on register to %s@%s, giving up (check config)\n", p->registry->username,p->registry->hostname);
		if (global.regattempts_max)
			p->registry->regattempts = global.regattempts_max+1;
		ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
		r->call = NULL;
		ast_sched_del(sched, r->timeout);
		break;
	case 200:	/* 200 OK */
		p->authtries = 0;
		if (!r) {
			ast_log(LOG_WARNING, "Got 200 OK on REGISTER that isn't a register\n");
			ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	
			return 0;
		}

		r->regstate = REG_STATE_REGISTERED;
		r->regtime = time(NULL);		/* Reset time of last succesful registration */
		manager_event(EVENT_FLAG_SYSTEM, "Registry", "ChannelDriver: SIP\r\nDomain: %s\r\nStatus: %s\r\n", r->hostname, regstate2str(r->regstate));
		r->regattempts = 0;
		if (option_debug)
			ast_log(LOG_DEBUG, "Registration successful\n");
		if (r->timeout > -1) {
			if (option_debug)
				ast_log(LOG_DEBUG, "Cancelling timeout %d\n", r->timeout);
			ast_sched_del(sched, r->timeout);
		}
		r->timeout=-1;
		r->call = NULL;
		p->registry = NULL;
		/* Let this one hang around until we have all the responses */
		sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT);
		/* ast_set_flag(&p->flags[0], SIP_NEEDDESTROY);	*/

		/* set us up for re-registering */
		/* figure out how long we got registered for */
		if (r->expire > -1)
			ast_sched_del(sched, r->expire);
		/* according to section 6.13 of RFC, contact headers override
		   expires headers, so check those first */
		expires = 0;

		/* XXX todo: try to save the extra call */
		if (!ast_strlen_zero(get_header(req, "Contact"))) {
			const char *contact = NULL;
			const char *tmptmp = NULL;
			int start = 0;
			for(;;) {
				contact = __get_header(req, "Contact", &start);
				/* this loop ensures we get a contact header about our register request */
				if(!ast_strlen_zero(contact)) {
					if( (tmptmp=strstr(contact, p->our_contact))) {
						contact=tmptmp;
						break;
					}
				} else
					break;
			}
			tmptmp = strcasestr(contact, "expires=");
			if (tmptmp) {
				if (sscanf(tmptmp + 8, "%d;", &expires) != 1)
					expires = 0;
			}

		}
		if (!expires) 
			expires = atoi(get_header(req, "expires"));
		if (!expires)
			expires = expiry.default_expiry;

		expires_ms = expires * 1000;
		if (expires <= EXPIRY_GUARD_LIMIT)
			expires_ms -= MAX((expires_ms * EXPIRY_GUARD_PCT),EXPIRY_GUARD_MIN);
		else
			expires_ms -= EXPIRY_GUARD_SECS * 1000;
		if (sipdebug)
			ast_log(LOG_NOTICE, "Outbound Registration: Expiry for %s is %d sec (Scheduling reregistration in %d s)\n", r->hostname, expires, expires_ms/1000); 

		r->refresh= (int) expires_ms / 1000;

		/* Schedule re-registration before we expire */
		r->expire = ast_sched_add(sched, expires_ms, sip_reregister, r); 
		ASTOBJ_UNREF(r, sip_registry_destroy);
	}
	return 1;
}


