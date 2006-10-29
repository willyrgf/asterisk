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

#include "asterisk/lock.h"
#include "asterisk/channel.h"
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
#include "asterisk/acl.h"
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
#include "sip3.h"
#include "sip3funcs.h"

static const char config[] = "sip3.conf";
const char notify_config[] = "sip3_notify.conf";

/*! \brief Global jitterbuffer configuration - by default, jb is disabled */
static struct ast_jb_conf default_jbconf =
{
        .flags = 0,
	.max_size = -1,
	.resync_threshold = -1,
	.impl = ""
};

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
static int handle_common_options(struct ast_flags *flags, struct ast_flags *mask, struct ast_variable *v)
{
	int res = 0;

	if (!strcasecmp(v->name, "trustrpid")) {
		ast_set_flag(&mask[0], SIP_TRUSTRPID);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_TRUSTRPID);
		res = 1;
	} else if (!strcasecmp(v->name, "sendrpid")) {
		ast_set_flag(&mask[0], SIP_SENDRPID);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_SENDRPID);
		res = 1;
	} else if (!strcasecmp(v->name, "g726nonstandard")) {
		ast_set_flag(&mask[0], SIP_G726_NONSTANDARD);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_G726_NONSTANDARD);
		res = 1;
	} else if (!strcasecmp(v->name, "useclientcode")) {
		ast_set_flag(&mask[0], SIP_USECLIENTCODE);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_USECLIENTCODE);
		res = 1;
	} else if (!strcasecmp(v->name, "dtmfmode")) {
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
			ast_set_flag(&flags[0], SIP_DTMF_RFC2833);
		}
	} else if (!strcasecmp(v->name, "nat")) {
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
	} else if (!strcasecmp(v->name, "canreinvite")) {
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
				}
			}
		}
	} else if (!strcasecmp(v->name, "insecure")) {
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
			}
		}
	} else if (!strcasecmp(v->name, "progressinband")) {
		ast_set_flag(&mask[0], SIP_PROG_INBAND);
		ast_clear_flag(&flags[0], SIP_PROG_INBAND);
		if (ast_true(v->value))
			ast_set_flag(&flags[0], SIP_PROG_INBAND_YES);
		else if (strcasecmp(v->value, "never"))
			ast_set_flag(&flags[0], SIP_PROG_INBAND_NO);
  	} else if (!strcasecmp(v->name, "allowguest")) {
		global.allowguest = ast_true(v->value) ? 1 : 0;
	} else if (!strcasecmp(v->name, "promiscredir")) {
		ast_set_flag(&mask[0], SIP_PROMISCREDIR);
		ast_set2_flag(&flags[0], ast_true(v->value), SIP_PROMISCREDIR);
		res = 1;
	} else if (!strcasecmp(v->name, "videosupport")) {
		ast_set_flag(&mask[1], SIP_PAGE2_VIDEOSUPPORT);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_VIDEOSUPPORT);
	} else if (!strcasecmp(v->name, "allowoverlap")) {
		ast_set_flag(&mask[1], SIP_PAGE2_ALLOWOVERLAP);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_ALLOWOVERLAP);
	} else if (!strcasecmp(v->name, "allowsubscribe")) {
		ast_set_flag(&mask[1], SIP_PAGE2_ALLOWSUBSCRIBE);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_ALLOWSUBSCRIBE);
	} else if (!strcasecmp(v->name, "t38pt_udptl")) {
		ast_set_flag(&mask[1], SIP_PAGE2_T38SUPPORT_UDPTL);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_UDPTL);
	} else if (!strcasecmp(v->name, "t38pt_rtp")) {
		ast_set_flag(&mask[1], SIP_PAGE2_T38SUPPORT_RTP);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_RTP);
	} else if (!strcasecmp(v->name, "t38pt_tcp")) {
		ast_set_flag(&mask[1], SIP_PAGE2_T38SUPPORT_TCP);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_TCP);
	} else if (!strcasecmp(v->name, "rfc2833compensate")) {
		ast_set_flag(&mask[1], SIP_PAGE2_RFC2833_COMPENSATE);
		ast_set2_flag(&flags[1], ast_true(v->value), SIP_PAGE2_RFC2833_COMPENSATE);
	}

	return res;
}

/*! \brief Set peer defaults before configuring specific configurations */
void set_device_defaults(struct sip_peer *device)
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
	strcpy(device->context, global.default_context);
	strcpy(device->subscribecontext, global.default_subscribecontext);
	strcpy(device->language, global.default_language);
	strcpy(device->mohinterpret, global.default_mohinterpret);
	strcpy(device->mohsuggest, global.default_mohsuggest);
	device->addr.sin_family = AF_INET;
	device->defaddr.sin_family = AF_INET;
	device->capability = global.capability;
	device->rtptimeout = global.rtptimeout;
	device->rtpholdtimeout = global.rtpholdtimeout;
	device->rtpkeepalive = global.rtpkeepalive;
	device->maxcallbitrate = global.default_maxcallbitrate;
	strcpy(device->vmexten, global.default_vmexten);
	device->secret[0] = '\0';
	device->md5secret[0] = '\0';
	device->cid_num[0] = '\0';
	device->cid_name[0] = '\0';
	device->fromdomain[0] = '\0';
	device->fromuser[0] = '\0';
	device->regexten[0] = '\0';
	device->mailbox[0] = '\0';
	device->callgroup = 0;
	device->pickupgroup = 0;
	device->allowtransfer = global.allowtransfer;
	device->maxms = global.default_qualify;
	device->prefs = global.default_prefs;
}

/*! \brief Build peer from configuration (file or realtime static/dynamic) */
static struct sip_peer *build_peer(const char *name, struct ast_variable *v, struct ast_variable *alt, int realtime)
{
	struct sip_peer *peer = NULL;
	struct ast_ha *oldha = NULL;
	int obproxyfound=0;
	int found = 0;
	int firstpass = 1;
	int format = 0;		/* Ama flags */
	time_t regseconds = 0;
	char *varname = NULL, *varval = NULL;
	struct ast_variable *tmpvar = NULL;
	struct ast_flags peerflags[2] = {{(0)}};
	struct ast_flags mask[2] = {{(0)}};


	if (!realtime)
		/* Note we do NOT use find_peer here, to avoid realtime recursion */
		/* We also use a case-sensitive comparison (unlike find_peer) so
		   that case changes made to the peer name will be properly handled
		   during reload
		*/
		peer = ASTOBJ_CONTAINER_FIND_UNLINK_FULL(&devicelist, name, name, 0, 0, strcmp);

	if (peer) {
		/* Already in the list, remove it and it will be added back (or FREE'd)  */
		found++;
		if (!(peer->objflags & ASTOBJ_FLAG_MARKED))
			firstpass = 0;
 	} else {
		if (!(peer = ast_calloc(1, sizeof(*peer))))
			return NULL;

		if (realtime)
			sipcounters.realtime_peers++;
		else
			sipcounters.static_peers++;
		ASTOBJ_INIT(peer);
	}
	peer->type &= SIP_PEER;

	/* Note that our peer HAS had its reference count incrased */

	if (firstpass) {
		peer->lastmsgssent = -1;
		oldha = peer->ha;
		peer->ha = NULL;
		set_device_defaults(peer);	/* Set peer defaults */
	}
	if (!found && name)
			ast_copy_string(peer->name, name, sizeof(peer->name));

	/* If we have channel variables, remove them (reload) */
	if (peer->chanvars) {
		ast_variables_destroy(peer->chanvars);
		peer->chanvars = NULL;
		/* XXX should unregister ? */
	}
	for (; v || ((v = alt) && !(alt=NULL)); v = v->next) {
		if (handle_common_options(&peerflags[0], &mask[0], v))
			continue;
		if (realtime && !strcasecmp(v->name, "regseconds")) {
			ast_get_time_t(v->value, &regseconds, 0, NULL);
		} else if (realtime && !strcasecmp(v->name, "ipaddr") && !ast_strlen_zero(v->value) ) {
			inet_aton(v->value, &(peer->addr.sin_addr));
		} else if (realtime && !strcasecmp(v->name, "name"))
			ast_copy_string(peer->name, v->value, sizeof(peer->name));
		else if (realtime && !strcasecmp(v->name, "fullcontact")) {
			ast_copy_string(peer->fullcontact, v->value, sizeof(peer->fullcontact));
			ast_set_flag(&peer->flags[1], SIP_PAGE2_RT_FROMCONTACT);
		} else if (!strcasecmp(v->name, "secret")) 
			ast_copy_string(peer->secret, v->value, sizeof(peer->secret));
		else if (!strcasecmp(v->name, "md5secret")) 
			ast_copy_string(peer->md5secret, v->value, sizeof(peer->md5secret));
		else if (!strcasecmp(v->name, "auth"))
			peer->auth = add_realm_authentication(peer->auth, v->value, v->lineno);
		else if (!strcasecmp(v->name, "callerid")) {
			ast_callerid_split(v->value, peer->cid_name, sizeof(peer->cid_name), peer->cid_num, sizeof(peer->cid_num));
		} else if (!strcasecmp(v->name, "fullname")) {
			ast_copy_string(peer->cid_name, v->value, sizeof(peer->cid_name));
		} else if (!strcasecmp(v->name, "cid_number")) {
			ast_copy_string(peer->cid_num, v->value, sizeof(peer->cid_num));
		} else if (!strcasecmp(v->name, "context")) {
			ast_copy_string(peer->context, v->value, sizeof(peer->context));
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			ast_copy_string(peer->subscribecontext, v->value, sizeof(peer->subscribecontext));
		} else if (!strcasecmp(v->name, "fromdomain")) {
			ast_copy_string(peer->fromdomain, v->value, sizeof(peer->fromdomain));
		} else if (!strcasecmp(v->name, "usereqphone")) {
			ast_set2_flag(&peer->flags[0], ast_true(v->value), SIP_USEREQPHONE);
		} else if (!strcasecmp(v->name, "fromuser")) {
			ast_copy_string(peer->fromuser, v->value, sizeof(peer->fromuser));
		} else if (!strcasecmp(v->name, "host") || !strcasecmp(v->name, "outboundproxy")) {
			if (!strcasecmp(v->value, "dynamic")) {
				if (!strcasecmp(v->name, "outboundproxy") || obproxyfound) {
					ast_log(LOG_WARNING, "You can't have a dynamic outbound proxy, you big silly head at line %d.\n", v->lineno);
				} else {
					/* They'll register with us */
					ast_set_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC);
					if (!found) {
						/* Initialize stuff iff we're not found, otherwise
						   we keep going with what we had */
						memset(&peer->addr.sin_addr, 0, 4);
						if (peer->addr.sin_port) {
							/* If we've already got a port, make it the default rather than absolute */
							peer->defaddr.sin_port = peer->addr.sin_port;
							peer->addr.sin_port = 0;
						}
					}
				}
			} else {
				/* Non-dynamic.  Make sure we become that way if we're not */
				if (peer->expire > -1)
					ast_sched_del(sched, peer->expire);
				peer->expire = -1;
				ast_clear_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC);
				if (!obproxyfound || !strcasecmp(v->name, "outboundproxy")) {
					if (ast_get_ip_or_srv(&peer->addr, v->value, global.srvlookup ? "_sip._udp" : NULL)) {
						ASTOBJ_UNREF(peer, sip_destroy_device);
						return NULL;
					}
				}
				if (!strcasecmp(v->name, "outboundproxy"))
					obproxyfound=1;
				else {
					ast_copy_string(peer->tohost, v->value, sizeof(peer->tohost));
					if (!peer->addr.sin_port)
						peer->addr.sin_port = htons(STANDARD_SIP_PORT);
				}
			}
		} else if (!strcasecmp(v->name, "defaultip")) {
			if (ast_get_ip(&peer->defaddr, v->value)) {
				ASTOBJ_UNREF(peer, sip_destroy_device);
				return NULL;
			}
		} else if (!strcasecmp(v->name, "permit") || !strcasecmp(v->name, "deny")) {
			peer->ha = ast_append_ha(v->name, v->value, peer->ha);
		} else if (!strcasecmp(v->name, "port")) {
			if (!realtime && ast_test_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC))
				peer->defaddr.sin_port = htons(atoi(v->value));
			else
				peer->addr.sin_port = htons(atoi(v->value));
		} else if (!strcasecmp(v->name, "callingpres")) {
			peer->callingpres = ast_parse_caller_presentation(v->value);
			if (peer->callingpres == -1)
				peer->callingpres = atoi(v->value);
		} else if (!strcasecmp(v->name, "defaultuser")) {
			ast_copy_string(peer->username, v->value, sizeof(peer->username));
		} else if (!strcasecmp(v->name, "language")) {
			ast_copy_string(peer->language, v->value, sizeof(peer->language));
		} else if (!strcasecmp(v->name, "regexten")) {
			ast_copy_string(peer->regexten, v->value, sizeof(peer->regexten));
		} else if (!strcasecmp(v->name, "call-limit")) {
			peer->call_limit = atoi(v->value);
			if (peer->call_limit < 0)
				peer->call_limit = 0;
		} else if (!strcasecmp(v->name, "amaflags")) {
			format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Invalid AMA Flags for peer: %s at line %d\n", v->value, v->lineno);
			} else {
				peer->amaflags = format;
			}
		} else if (!strcasecmp(v->name, "accountcode")) {
			ast_copy_string(peer->accountcode, v->value, sizeof(peer->accountcode));
		} else if (!strcasecmp(v->name, "mohinterpret")
			|| !strcasecmp(v->name, "musicclass") || !strcasecmp(v->name, "musiconhold")) {
			ast_copy_string(peer->mohinterpret, v->value, sizeof(peer->mohinterpret));
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			ast_copy_string(peer->mohsuggest, v->value, sizeof(peer->mohsuggest));
		} else if (!strcasecmp(v->name, "mailbox")) {
			ast_copy_string(peer->mailbox, v->value, sizeof(peer->mailbox));
		} else if (!strcasecmp(v->name, "subscribemwi")) {
			ast_set2_flag(&peer->flags[1], ast_true(v->value), SIP_PAGE2_SUBSCRIBEMWIONLY);
		} else if (!strcasecmp(v->name, "vmexten")) {
			ast_copy_string(peer->vmexten, v->value, sizeof(peer->vmexten));
		} else if (!strcasecmp(v->name, "callgroup")) {
			peer->callgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			peer->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "pickupgroup")) {
			peer->pickupgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 1);
		} else if (!strcasecmp(v->name, "disallow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 0);
		} else if (!strcasecmp(v->name, "autoframing")) {
			peer->autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			if ((sscanf(v->value, "%d", &peer->rtptimeout) != 1) || (peer->rtptimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP hold time at line %d.  Using default.\n", v->value, v->lineno);
				peer->rtptimeout = global.rtptimeout;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			if ((sscanf(v->value, "%d", &peer->rtpholdtimeout) != 1) || (peer->rtpholdtimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP hold time at line %d.  Using default.\n", v->value, v->lineno);
				peer->rtpholdtimeout = global.rtpholdtimeout;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			if ((sscanf(v->value, "%d", &peer->rtpkeepalive) != 1) || (peer->rtpkeepalive < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP keepalive time at line %d.  Using default.\n", v->value, v->lineno);
				peer->rtpkeepalive = global.rtpkeepalive;
			}
		} else if (!strcasecmp(v->name, "setvar")) {
			/* Set peer channel variable */
			varname = ast_strdupa(v->value);
			if ((varval = strchr(varname, '='))) {
				*varval++ = '\0';
				if ((tmpvar = ast_variable_new(varname, varval))) {
					tmpvar->next = peer->chanvars;
					peer->chanvars = tmpvar;
				}
			}
		} else if (!strcasecmp(v->name, "qualify")) {
			if (!strcasecmp(v->value, "no")) {
				peer->maxms = 0;
			} else if (!strcasecmp(v->value, "yes")) {
				peer->maxms = DEFAULT_QUALIFY_MAXMS;
			} else if (sscanf(v->value, "%d", &peer->maxms) != 1) {
				ast_log(LOG_WARNING, "Qualification of peer '%s' should be 'yes', 'no', or a number of milliseconds at line %d of sip.conf\n", peer->name, v->lineno);
				peer->maxms = 0;
			}
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			peer->maxcallbitrate = atoi(v->value);
			if (peer->maxcallbitrate < 0)
				peer->maxcallbitrate = global.default_maxcallbitrate;
		} else if (!strcasecmp(v->name, "t38pt_udptl")) {
			ast_set2_flag(&peer->flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_UDPTL);
		} else if (!strcasecmp(v->name, "t38pt_rtp")) {
			ast_set2_flag(&peer->flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_RTP);
		} else if (!strcasecmp(v->name, "t38pt_tcp")) {
			ast_set2_flag(&peer->flags[1], ast_true(v->value), SIP_PAGE2_T38SUPPORT_TCP);
		}
	}
	if (!ast_test_flag(&global.flags[1], SIP_PAGE2_IGNOREREGEXPIRE) && ast_test_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC) && realtime) {
		time_t nowtime = time(NULL);

		if ((nowtime - regseconds) > 0) {
			destroy_association(peer);
			memset(&peer->addr, 0, sizeof(peer->addr));
			if (option_debug)
				ast_log(LOG_DEBUG, "Bah, we're expired (%d/%d/%d)!\n", (int)(nowtime - regseconds), (int)regseconds, (int)nowtime);
		}
	}
	ast_copy_flags(&peer->flags[0], &peerflags[0], mask[0].flags);
	ast_copy_flags(&peer->flags[1], &peerflags[1], mask[1].flags);
	if (ast_test_flag(&peer->flags[1], SIP_PAGE2_ALLOWSUBSCRIBE))
		global.allowsubscribe = TRUE;	/* No global ban any more */
	if (!found && ast_test_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC) && !ast_test_flag(&peer->flags[0], SIP_REALTIME))
		reg_source_db(peer);
	ASTOBJ_UNMARK(peer);
	ast_free_ha(oldha);
	return peer;
}

/*! \brief  realtime_peer: Get peer from realtime storage
 * Checks the "sippeers" realtime family from extconfig.conf 
 * \todo Consider adding check of port address when matching here to follow the same
 * 	algorithm as for static peers. Will we break anything by adding that?
*/
struct sip_peer *realtime_peer(const char *newpeername, struct sockaddr_in *sin)
{
	struct sip_peer *peer;
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
	peer = build_peer(newpeername, var, NULL, !ast_test_flag(&global.flags[1], SIP_PAGE2_RTCACHEFRIENDS));
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

/*! \brief Re-read SIP.conf config file
\note	This function reloads all config data, except for
	active peers (with registrations). They will only
	change configuration data at restart, not at reload.
	SIP debug and recordhistory state will not change
 */
int reload_config(enum channelreloadreason reason)
{
	struct ast_config *cfg;
	struct ast_variable *v;
	struct sip_peer *device = (struct sip_peer *) NULL;
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
	ast_clear_flag(&global.flags[0], AST_FLAGS_ALL);
	ast_clear_flag(&global.flags[1], AST_FLAGS_ALL);
	ast_copy_flags(&global.flags[1], &debugflag, SIP_PAGE2_DEBUG_CONSOLE);

	/* Reset IP addresses  */
	memset(&sipnet.bindaddr, 0, sizeof(sipnet.bindaddr));
	memset(&sipnet.localaddr, 0, sizeof(sipnet.localaddr));
	memset(&sipnet.externip, 0, sizeof(sipnet.externip));
	memset(&global.default_prefs, 0 , sizeof(global.default_prefs));
	sipnet.outboundproxyip.sin_port = htons(STANDARD_SIP_PORT);
	sipnet.outboundproxyip.sin_family = AF_INET;	/* Type of address: IPv4 */
	sipnet_ourport_set(DEFAULT_LISTEN_SIP_PORT);
	global.srvlookup = TRUE;
	/*! \brief Codecs that we support by default: */
	global.capability = AST_FORMAT_ULAW | AST_FORMAT_ALAW | AST_FORMAT_GSM | AST_FORMAT_H263;
	global.dtmf_capability = AST_RTP_DTMF;
	/*!< This is default: NO MMR and JBIG trancoding, NO fill bit removal, transferredTCF TCF, UDP FEC, Version 0 and 9600 max fax rate */
	global.t38_capability = T38FAX_VERSION_0 | T38FAX_RATE_2400 | T38FAX_RATE_4800 | T38FAX_RATE_7200 | T38FAX_RATE_9600;
	global.tos_sip = DEFAULT_TOS_SIP;
	global.tos_audio = DEFAULT_TOS_AUDIO;
	global.tos_video = DEFAULT_TOS_VIDEO;
	global.tos_presence = DEFAULT_TOS_SIP;	/* Initialize to SIP type of service */
	sipnet.externhost[0] = '\0';			/* External host name (for behind NAT DynDNS support) */
	sipnet.externexpire = 0;			/* Expiration for DNS re-issuing */
	sipnet.externrefresh = 10;
	memset(&sipnet.outboundproxyip, 0, sizeof(sipnet.outboundproxyip));

	/* Reset channel settings to default before re-configuring */
	global.allow_external_domains = DEFAULT_ALLOW_EXT_DOM;				/* Allow external invites */
	global.regcontext[0] = '\0';
	expiry.min_expiry = DEFAULT_MIN_EXPIRY;        /*!< Minimum accepted registration time */
	expiry.max_expiry = DEFAULT_MAX_EXPIRY;        /*!< Maximum accepted registration time */
	expiry.default_expiry = DEFAULT_DEFAULT_EXPIRY;
	expiry.expiry = DEFAULT_EXPIRY;					/* Used anywhere??? */
	global.notifyringing = DEFAULT_NOTIFYRINGING;
	global.alwaysauthreject = 0;
	global.allowsubscribe = FALSE;
	ast_copy_string(global.useragent, DEFAULT_USERAGENT, sizeof(global.useragent));
	ast_copy_string(global.default_notifymime, DEFAULT_NOTIFYMIME, sizeof(global.default_notifymime));
	if (ast_strlen_zero(ast_config_AST_SYSTEM_NAME))
		ast_copy_string(global.realm, DEFAULT_REALM, sizeof(global.realm));
	else
		ast_copy_string(global.realm, ast_config_AST_SYSTEM_NAME, sizeof(global.realm));
	ast_copy_string(global.default_callerid, DEFAULT_CALLERID, sizeof(global.default_callerid));
	global.compactheaders = DEFAULT_COMPACTHEADERS;
	global.reg_timeout = DEFAULT_REGISTRATION_TIMEOUT;
	global.regattempts_max = 0;
	global.mwitime = DEFAULT_MWITIME;
	global.autocreatepeer = DEFAULT_AUTOCREATEPEER;
	global.allowguest = DEFAULT_ALLOWGUEST;
	global.rtptimeout = 0;
	global.rtpholdtimeout = 0;
	global.rtpkeepalive = 0;
	global.autoframing = 0;
	global.allowtransfer = TRANSFER_OPENFORALL;	/* Merrily accept all transfers by default */
	global.rtautoclear = 120;
	ast_set_flag(&global.flags[1], SIP_PAGE2_ALLOWSUBSCRIBE);	/* Default for peers, users: TRUE */
	ast_set_flag(&global.flags[1], SIP_PAGE2_ALLOWOVERLAP);		/* Default for peers, users: TRUE */
	ast_set_flag(&global.flags[1], SIP_PAGE2_RTUPDATE);

	/* Initialize some reasonable defaults at SIP reload (used both for channel and as default for peers and users */
	ast_copy_string(global.default_context, DEFAULT_CONTEXT, sizeof(global.default_context));
	global.default_subscribecontext[0] = '\0';
	global.default_language[0] = '\0';
	global.default_fromdomain[0] = '\0';
	global.default_qualify = DEFAULT_QUALIFY;
	global.default_qualifycheck_ok = DEFAULT_QUALIFY_FREQ_OK;	/*!< Default qualify time when status is ok */
	global.default_qualifycheck_notok = DEFAULT_QUALIFY_FREQ_NOTOK;	/*!< Default qualify time when statusis not ok */
	global.default_maxcallbitrate = DEFAULT_MAX_CALL_BITRATE;
	ast_copy_string(global.default_mohinterpret, DEFAULT_MOHINTERPRET, sizeof(global.default_mohinterpret));
	ast_copy_string(global.default_mohsuggest, DEFAULT_MOHSUGGEST, sizeof(global.default_mohsuggest));
	ast_copy_string(global.default_vmexten, DEFAULT_VMEXTEN, sizeof(global.default_vmexten));
	ast_set_flag(&global.flags[0], SIP_DTMF_RFC2833);			/*!< Default DTMF setting: RFC2833 */
	ast_set_flag(&global.flags[0], SIP_NAT_RFC3581);			/*!< NAT support if requested by device with rport */
	ast_set_flag(&global.flags[0], SIP_CAN_REINVITE);			/*!< Allow re-invites */

	/* Debugging settings, always default to off */
	global.dumphistory = FALSE;
	global.recordhistory = FALSE;
	ast_clear_flag(&global.flags[1], SIP_PAGE2_DEBUG_CONFIG);

	/* Misc settings for the channel */
	global.relaxdtmf = FALSE;
	global.callevents = FALSE;
	global.t1min = DEFAULT_T1MIN;		

	/* Copy the default jb config over global.jbconf */
	memcpy(&global.jbconf, &default_jbconf, sizeof(struct ast_jb_conf));

	ast_clear_flag(&global.flags[1], SIP_PAGE2_VIDEOSUPPORT);

	/* Read the [general] config section of sip.conf (or from realtime config) */
	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (handle_common_options(&global.flags[0], &dummy[0], v))
			continue;
		/* handle jb conf */
		if (!ast_jb_read_conf(&global.jbconf, v->name, v->value))
			continue;

		/* Create the interface list */
		if (!strcasecmp(v->name, "context")) {
			ast_copy_string(global.default_context, v->value, sizeof(global.default_context));
		} else if (!strcasecmp(v->name, "realm")) {
			ast_copy_string(global.realm, v->value, sizeof(global.realm));
		} else if (!strcasecmp(v->name, "useragent")) {
			ast_copy_string(global.useragent, v->value, sizeof(global.useragent));
			if (option_debug)
				ast_log(LOG_DEBUG, "Setting SIP channel User-Agent Name to %s\n", global.useragent);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			global.allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "rtcachefriends")) {
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_RTCACHEFRIENDS);	
		} else if (!strcasecmp(v->name, "rtsavesysname")) {
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_RTSAVE_SYSNAME);	
		} else if (!strcasecmp(v->name, "rtupdate")) {
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_RTUPDATE);	
		} else if (!strcasecmp(v->name, "ignoreregexpire")) {
			ast_set2_flag(&global.flags[1], ast_true(v->value), SIP_PAGE2_IGNOREREGEXPIRE);	
		} else if (!strcasecmp(v->name, "t1min")) {
			global.t1min = atoi(v->value);
		} else if (!strcasecmp(v->name, "rtautoclear")) {
			int i = atoi(v->value);
			if (i > 0)
				global.rtautoclear = i;
			else
				i = 0;
			ast_set2_flag(&global.flags[1], i || ast_true(v->value), SIP_PAGE2_RTAUTOCLEAR);
		} else if (!strcasecmp(v->name, "usereqphone")) {
			ast_set2_flag(&global.flags[0], ast_true(v->value), SIP_USEREQPHONE);	
		} else if (!strcasecmp(v->name, "relaxdtmf")) {
			global.relaxdtmf = ast_true(v->value);
		} else if (!strcasecmp(v->name, "checkmwi")) {
			if ((sscanf(v->value, "%d", &global.mwitime) != 1) || (global.mwitime < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid MWI time setting at line %d.  Using default (10).\n", v->value, v->lineno);
				global.mwitime = DEFAULT_MWITIME;
			}
		} else if (!strcasecmp(v->name, "vmexten")) {
			ast_copy_string(global.default_vmexten, v->value, sizeof(global.default_vmexten));
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			if ((sscanf(v->value, "%d", &global.rtptimeout) != 1) || (global.rtptimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP hold time at line %d.  Using default.\n", v->value, v->lineno);
				global.rtptimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			if ((sscanf(v->value, "%d", &global.rtpholdtimeout) != 1) || (global.rtpholdtimeout < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP hold time at line %d.  Using default.\n", v->value, v->lineno);
				global.rtpholdtimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			if ((sscanf(v->value, "%d", &global.rtpkeepalive) != 1) || (global.rtpkeepalive < 0)) {
				ast_log(LOG_WARNING, "'%s' is not a valid RTP keepalive time at line %d.  Using default.\n", v->value, v->lineno);
				global.rtpkeepalive = 0;
			}
		} else if (!strcasecmp(v->name, "compactheaders")) {
			global.compactheaders = ast_true(v->value);
		} else if (!strcasecmp(v->name, "notifymimetype")) {
			ast_copy_string(global.default_notifymime, v->value, sizeof(global.default_notifymime));
		} else if (!strcasecmp(v->name, "notifyringing")) {
			global.notifyringing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "alwaysauthreject")) {
			global.alwaysauthreject = ast_true(v->value);
		} else if (!strcasecmp(v->name, "mohinterpret") 
			|| !strcasecmp(v->name, "musicclass") || !strcasecmp(v->name, "musiconhold")) {
			ast_copy_string(global.default_mohinterpret, v->value, sizeof(global.default_mohinterpret));
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			ast_copy_string(global.default_mohsuggest, v->value, sizeof(global.default_mohsuggest));
		} else if (!strcasecmp(v->name, "language")) {
			ast_copy_string(global.default_language, v->value, sizeof(global.default_language));
		} else if (!strcasecmp(v->name, "regcontext")) {
			ast_copy_string(newcontexts, v->value, sizeof(newcontexts));
			stringp = newcontexts;
			/* Let's remove any contexts that are no longer defined in regcontext */
			cleanup_stale_contexts(stringp, oldregcontext);
			/* Create contexts if they don't exist already */
			while ((context = strsep(&stringp, "&"))) {
				if (!ast_context_find(context))
					ast_context_create(NULL, context,"SIP");
			}
			ast_copy_string(global.regcontext, v->value, sizeof(global.regcontext));
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_copy_string(global.default_callerid, v->value, sizeof(global.default_callerid));
		} else if (!strcasecmp(v->name, "fromdomain")) {
			ast_copy_string(global.default_fromdomain, v->value, sizeof(global.default_fromdomain));
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			if (ast_get_ip_or_srv(&sipnet.outboundproxyip, v->value, global.srvlookup ? "_sip._udp" : NULL) < 0)
				ast_log(LOG_WARNING, "Unable to locate host '%s'\n", v->value);
		} else if (!strcasecmp(v->name, "outboundproxyport")) {
			/* Port needs to be after IP */
			sscanf(v->value, "%d", &format);
			sipnet.outboundproxyip.sin_port = htons(format);
		} else if (!strcasecmp(v->name, "autocreatepeer")) {
			global.autocreatepeer = ast_true(v->value);
		} else if (!strcasecmp(v->name, "srvlookup")) {
			global.srvlookup = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxexpirey") || !strcasecmp(v->name, "maxexpiry")) {
			expiry.max_expiry = atoi(v->value);
			if (expiry.max_expiry < 1)
				expiry.max_expiry = DEFAULT_MAX_EXPIRY;
		} else if (!strcasecmp(v->name, "minexpirey") || !strcasecmp(v->name, "minexpiry")) {
			expiry.min_expiry = atoi(v->value);
			if (expiry.min_expiry < 1)
				expiry.min_expiry = DEFAULT_MIN_EXPIRY;
		} else if (!strcasecmp(v->name, "defaultexpiry") || !strcasecmp(v->name, "defaultexpirey")) {
			expiry.default_expiry = atoi(v->value);
			if (expiry.default_expiry < 1)
				expiry.default_expiry = DEFAULT_DEFAULT_EXPIRY;
		} else if (!strcasecmp(v->name, "sipdebug")) {
			if (ast_true(v->value))
				ast_set_flag(&global.flags[1], SIP_PAGE2_DEBUG_CONFIG);
		} else if (!strcasecmp(v->name, "dumphistory")) {
			global.dumphistory = ast_true(v->value);
		} else if (!strcasecmp(v->name, "recordhistory")) {
			global.recordhistory = ast_true(v->value);
		} else if (!strcasecmp(v->name, "registertimeout")) {
			global.reg_timeout = atoi(v->value);
			if (global.reg_timeout < 1)
				global.reg_timeout = DEFAULT_REGISTRATION_TIMEOUT;
		} else if (!strcasecmp(v->name, "registerattempts")) {
			global.regattempts_max = atoi(v->value);
		} else if (!strcasecmp(v->name, "bindaddr")) {
			if (!(hp = ast_gethostbyname(v->value, &ahp))) {
				ast_log(LOG_WARNING, "Invalid address: %s\n", v->value);
			} else {
				memcpy(&sipnet.bindaddr.sin_addr, hp->h_addr, sizeof(sipnet.bindaddr.sin_addr));
			}
		} else if (!strcasecmp(v->name, "localnet")) {
			struct ast_ha *na;
			if (!(na = ast_append_ha("d", v->value, sipnet.localaddr)))
				ast_log(LOG_WARNING, "Invalid localnet value: %s\n", v->value);
			else
				sipnet.localaddr = na;
		} else if (!strcasecmp(v->name, "localmask")) {
			ast_log(LOG_WARNING, "Use of localmask is no long supported -- use localnet with mask syntax\n");
		} else if (!strcasecmp(v->name, "externip")) {
			if (!(hp = ast_gethostbyname(v->value, &ahp))) 
				ast_log(LOG_WARNING, "Invalid address for externip keyword: %s\n", v->value);
			else
				memcpy(&sipnet.externip.sin_addr, hp->h_addr, sizeof(sipnet.externip.sin_addr));
			sipnet.externexpire = 0;
		} else if (!strcasecmp(v->name, "externhost")) {
			ast_copy_string(sipnet.externhost, v->value, sizeof(sipnet.externhost));
			if (!(hp = ast_gethostbyname(sipnet.externhost, &ahp))) 
				ast_log(LOG_WARNING, "Invalid address for externhost keyword: %s\n", sipnet.externhost);
			else
				memcpy(&sipnet.externip.sin_addr, hp->h_addr, sizeof(sipnet.externip.sin_addr));
			sipnet.externexpire = time(NULL);
		} else if (!strcasecmp(v->name, "externrefresh")) {
			if (sscanf(v->value, "%d", &sipnet.externrefresh) != 1) {
				ast_log(LOG_WARNING, "Invalid externrefresh value '%s', must be an integer >0 at line %d\n", v->value, v->lineno);
				sipnet.externrefresh = 10;
			}
		} else if (!strcasecmp(v->name, "allow")) {
			ast_parse_allow_disallow(&global.default_prefs, &global.capability, v->value, 1);
		} else if (!strcasecmp(v->name, "disallow")) {
			ast_parse_allow_disallow(&global.default_prefs, &global.capability, v->value, 0);
		} else if (!strcasecmp(v->name, "autoframing")) {
			global.autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "allowexternaldomains")) {
			global.allow_external_domains = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autodomain")) {
			auto_sip_domains = ast_true(v->value);
		} else if (!strcasecmp(v->name, "domain")) {
			char *domain = ast_strdupa(v->value);
			char *context = strchr(domain, ',');

			if (context)
				*context++ = '\0';

			if (option_debug && ast_strlen_zero(context))
				ast_log(LOG_DEBUG, "No context specified at line %d for domain '%s'\n", v->lineno, domain);
			if (ast_strlen_zero(domain))
				ast_log(LOG_WARNING, "Empty domain specified at line %d\n", v->lineno);
			else
				add_sip_domain(ast_strip(domain), SIP_DOMAIN_CONFIG, context ? ast_strip(context) : "");
		} else if (!strcasecmp(v->name, "register")) {
			if (sip_register(v->value, v->lineno) == 0)
				registry_count++;
		} else if (!strcasecmp(v->name, "tos_sip")) {
			if (ast_str2tos(v->value, &global.tos_sip))
				ast_log(LOG_WARNING, "Invalid tos_sip value at line %d, recommended value is 'cs3'. See doc/ip-tos.txt.\n", v->lineno);
		} else if (!strcasecmp(v->name, "tos_audio")) {
			if (ast_str2tos(v->value, &global.tos_audio))
				ast_log(LOG_WARNING, "Invalid tos_audio value at line %d, recommended value is 'ef'. See doc/ip-tos.txt.\n", v->lineno);
		} else if (!strcasecmp(v->name, "tos_video")) {
			if (ast_str2tos(v->value, &global.tos_video))
				ast_log(LOG_WARNING, "Invalid tos_video value at line %d, recommended value is 'af41'. See doc/ip-tos.txt.\n", v->lineno);
		} else if (!strcasecmp(v->name, "tos_presence")) {
			if (ast_str2tos(v->value, &global.tos_presence))
				ast_log(LOG_WARNING, "Invalid tos_presence value at line %d, recommended value is 'cs3'. See doc/ip-tos.txt.\n", v->lineno);
		} else if (!strcasecmp(v->name, "bindport")) {
			int port;
			if (sscanf(v->value, "%d", &port) == 1) {
				sipnet_ourport_set(port);
				sipnet.bindaddr.sin_port = htons(sipnet_ourport());
			} else {
				ast_log(LOG_WARNING, "Invalid port number '%s' at line %d of %s\n", v->value, v->lineno, config);
			}
		} else if (!strcasecmp(v->name, "qualify")) {
			if (!strcasecmp(v->value, "no")) {
				global.default_qualify = 0;
			} else if (!strcasecmp(v->value, "yes")) {
				global.default_qualify = DEFAULT_QUALIFY_MAXMS;
			} else if (sscanf(v->value, "%d", &global.default_qualify) != 1) {
				ast_log(LOG_WARNING, "Qualification default should be 'yes', 'no', or a number of milliseconds at line %d of sip.conf\n", v->lineno);
				global.default_qualify = 0;
			}
		} else if (!strcasecmp(v->name, "qualify-timer-ok")) {
			int freq;
			if(sscanf(v->value, "%d", &freq) != 1) 
				if (freq)
					global.default_qualifycheck_ok = freq;
		} else if (!strcasecmp(v->name, "qualify-timer-notok")) {
			int freq;
			if(sscanf(v->value, "%d", &freq) != 1) 
				if (freq)
					global.default_qualifycheck_notok = freq;
		} else if (!strcasecmp(v->name, "qualify-timer-notok")) {
		} else if (!strcasecmp(v->name, "callevents")) {
			global.callevents = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			global.default_maxcallbitrate = atoi(v->value);
			if (global.default_maxcallbitrate < 0)
				global.default_maxcallbitrate = DEFAULT_MAX_CALL_BITRATE;
		} else if (!strcasecmp(v->name, "t38pt_udptl")) {
			if (ast_true(v->value)) {
				ast_set_flag(&global.flags[1], SIP_PAGE2_T38SUPPORT_UDPTL);
			}
		} else if (!strcasecmp(v->name, "t38pt_rtp")) {
			if (ast_true(v->value)) {
				ast_set_flag(&global.flags[1], SIP_PAGE2_T38SUPPORT_RTP);
			}
		} else if (!strcasecmp(v->name, "t38pt_tcp")) {
			if (ast_true(v->value)) {
				ast_set_flag(&global.flags[1], SIP_PAGE2_T38SUPPORT_TCP);
			}
		} else if (!strcasecmp(v->name, "rfc2833compensate")) {
			if (ast_true(v->value)) {
				ast_set_flag(&global.flags[1], SIP_PAGE2_RFC2833_COMPENSATE);
			}
		}
	}

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
				device = build_peer(cat, ast_variable_browse(cfg, cat), NULL, 0);
				if (device) {
					ASTOBJ_CONTAINER_LINK(&devicelist,device);
					ASTOBJ_UNREF(device, sip_destroy_device);
					peer_count++;
				}
			}
		}
	}
	if (ast_find_ourip(&sipnet.__ourip, sipnet.bindaddr)) {
		ast_log(LOG_WARNING, "Unable to get own IP address, SIP disabled\n");
		return 0;
	}
	if (!ntohs(sipnet.bindaddr.sin_port))
		sipnet.bindaddr.sin_port = ntohs(DEFAULT_LISTEN_SIP_PORT);
	sipnet.bindaddr.sin_family = AF_INET;
	sipnet_lock();
	if (sipsocket_initialized() && (memcmp(&old_bindaddr, &sipnet.bindaddr, sizeof(struct sockaddr_in)))) {
		close(sipnet.sipsock);
		sipnet.sipsock = -1;
	}
	if (!sipsocket_initialized()) 
		sipsocket_open();	/* Open socket, bind to address and set TOS option */
	sipnet_unlock();

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

	return 0;
}
