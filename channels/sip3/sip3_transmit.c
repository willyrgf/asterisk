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
 * \brief Various SIP message transmit functions
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

/*! \brief add XML encoded media control with update 
	\note XML: The only way to turn 0 bits of information into a few hundred. (markster) */
static int add_vidupdate(struct sip_request *req)
{
	const char *xml_is_a_huge_waste_of_space =
		"<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n"
		" <media_control>\r\n"
		"  <vc_primitive>\r\n"
		"   <to_encoder>\r\n"
		"    <picture_fast_update>\r\n"
		"    </picture_fast_update>\r\n"
		"   </to_encoder>\r\n"
		"  </vc_primitive>\r\n"
		" </media_control>\r\n";
	add_header(req, "Content-Type", "application/media_control+xml");
	add_header_contentLength(req, strlen(xml_is_a_huge_waste_of_space));
	add_line(req, xml_is_a_huge_waste_of_space);
	return 0;
}

/*! \brief Base transmit response function */
GNURK int __transmit_response(struct sip_dialog *p, const char *msg, struct sip_request *req, enum xmittype reliable)
{
	struct sip_request *resp;
	int seqno = 0;
	int res;


	if (reliable && (sscanf(get_header(req, "CSeq"), "%d ", &seqno) != 1)) {
		ast_log(LOG_WARNING, "Unable to determine sequence number from '%s'\n", get_header(req, "CSeq"));
		return -1;
	}

	resp = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	ast_log(LOG_DEBUG, "   :::: Response data size: %d\n", (int) resp->data_size);
	resp->seqno = seqno;
	respprep(resp, p, msg, req);
	add_header_contentLength(resp, 0);
	/* If we are cancelling an incoming invite for some reason, add information
		about the reason why we are doing this in clear text */
	if (p->method == SIP_INVITE && msg[0] != '1' && p->owner && p->owner->hangupcause) {
		char buf[10];

		add_header(resp, "X-Asterisk-HangupCause", ast_cause2str(p->owner->hangupcause));
		snprintf(buf, sizeof(buf), "%d", p->owner->hangupcause);
		add_header(resp, "X-Asterisk-HangupCauseCode", buf);
	}
	res =  send_response(p, resp, reliable);
	if (reliable == XMIT_UNRELIABLE)
		siprequest_free(resp);
	return res;
}

/*! \brief Transmit response, no retransmits */
GNURK int transmit_response(struct sip_dialog *p, const char *msg, struct sip_request *req) 
{
	return __transmit_response(p, msg, req, XMIT_UNRELIABLE);
}


/*! \brief Transmit response, Make sure you get an ACK
	This is only used for responses to INVITEs, where we need to make sure we get an ACK
*/
GNURK int transmit_response_reliable(struct sip_dialog *p, const char *msg, struct sip_request *req)
{
	return __transmit_response(p, msg, req, XMIT_CRITICAL);
}

/*! \brief Transmit responses with various attachments */
GNURK int transmit_response_with_attachment(enum responseattach attach, struct sip_dialog *p, const char *msg, 
		struct sip_request *req, enum xmittype reliable)
{
	struct sip_request *resp;
	char buf[12];
	int res;

	resp = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	respprep(resp, p, msg, req);
	if (resp->seqno == 0) {
		if (req->seqno) {
			ast_log(LOG_DEBUG, " ************ Response seqno still zero!!!!!!!!!\n");
			resp->seqno = req->seqno;
		} else {
			ast_log(LOG_DEBUG, " ************ Request seqno still zero!!!!!!!!! Can't set response seqno\n");
		}
	}
	append_date(resp);
	switch (attach) {
	case WITH_DATE:
		add_header_contentLength(resp, 0);
		break;
	case WITH_MINEXPIRY:
		snprintf(buf, sizeof(buf), "%d", expiry.min_expiry);
		add_header(resp, "Min-Expires", buf);
		break;
	case WITH_ALLOW:
		add_header(resp, "Accept", "application/sdp");
		add_header_contentLength(resp, 0);
		break;
	case WITH_SDP:
		if (p->rtp) {
			if (!p->autoframing && !ast_test_flag(&p->flags[0], SIP_OUTGOING)) {
				if (option_debug)
					ast_log(LOG_DEBUG, "Setting framing from config on incoming call\n");
				ast_rtp_codec_setpref(p->rtp, &p->prefs);
			}
			try_suggested_sip_codec(p);	
			add_sdp(resp, p);
		} else 
			ast_log(LOG_ERROR, "Can't add SDP to response, since we have no RTP session allocated. Call-ID %s\n", p->callid);
		break;
	case WITH_T38_SDP:
		if (p->udptl) {
			ast_udptl_offered_from_local(p->udptl, 0);
			add_t38_sdp(resp, p);
		} else 
			ast_log(LOG_ERROR, "Can't add T38 SDP to response, since we have no UDPTL session allocated. Call-ID %s\n", p->callid);
		break;
	}
	res =  send_response(p, resp, reliable);
	if (reliable == XMIT_UNRELIABLE)
		siprequest_free(resp);
	return res;
}

/*! \brief Transmit response, no retransmits */
GNURK int transmit_response_with_unsupported(struct sip_dialog *p, const char *msg, struct sip_request *req, const char *unsupported) 
{
	struct sip_request *resp;
	int res;

	resp = siprequest_alloc(SIP_MAX_PACKET, &sipnet);

	respprep(resp, p, msg, req);
	append_date(resp);
	add_header(resp, "Unsupported", unsupported);
	add_header_contentLength(resp, 0);
	add_blank(resp);
	res = send_response(p, resp, XMIT_UNRELIABLE);
	siprequest_free(resp);
	return res;
}

/*! \brief Respond with authorization request */
GNURK int transmit_response_with_auth(struct sip_dialog *p, const char *msg, struct sip_request *req, const char *randdata, enum xmittype reliable, const char *header, int stale)
{
	struct sip_request *resp;
	char tmp[512];
	int seqno = 0;
	int res;


	if (reliable && (sscanf(get_header(req, "CSeq"), "%d ", &seqno) != 1)) {
		ast_log(LOG_WARNING, "Unable to determine sequence number from '%s'\n", get_header(req, "CSeq"));
		return -1;
	}
	resp = siprequest_alloc(SIP_MAX_PACKET, &sipnet);


	/* Stale means that they sent us correct authentication, but 
	   based it on an old challenge (nonce) */
	snprintf(tmp, sizeof(tmp), "Digest algorithm=MD5, realm=\"%s\", nonce=\"%s\"%s", global.realm, randdata, stale ? ", stale=true" : "");
	respprep(resp, p, msg, req);
	add_header(resp, header, tmp);
	add_header_contentLength(resp, 0);
	res =  send_response(p, resp, reliable);
	if (reliable == XMIT_UNRELIABLE)
		siprequest_free(resp);
	return res;
}

/*! \brief Transmit reinvite with SDP
\note 	A re-invite is basically a new INVITE with the same CALL-ID and TAG as the
	INVITE that opened the SIP dialogue 
	We reinvite so that the audio stream (RTP) go directly between
	the SIP UAs. SIP Signalling stays with * in the path.
	IF type == 1, we send T.38 SDP 
*/
GNURK int transmit_reinvite_with_sdp(struct sip_dialog *p, int t38type)
{
	struct sip_request *req;

	req = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	reqprep(req, p, ast_test_flag(&p->flags[0], SIP_REINVITE_UPDATE) ?  SIP_UPDATE : SIP_INVITE, 0, 1);
	
	add_header(req, "Allow", ALLOWED_METHODS);
	add_header(req, "Supported", SUPPORTED_EXTENSIONS);
	if (sipdebug)
		add_header(req, "X-asterisk-Info",(t38type ? "SIP re-invite for T38 fax" : "SIP re-invite (External RTP bridge)"));
	if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY))
		append_history(p, "ReInv", "%s", (t38type ? "Re-invite sent for T38" : "Re-invite sent for external RTP media"));
	if (t38type)
		add_t38_sdp(req, p);
	else
		add_sdp(req, p);

	/* Use this as the basis */
	initialize_initreq(p, req);
	p->lastinvite = p->ocseq;
	return send_request(p, req, XMIT_CRITICAL);
}

/*! \brief Build REFER/INVITE/OPTIONS message and transmit it */
GNURK int transmit_invite(struct sip_dialog *dialog, int sipmethod, int sdp, int init)
{
	struct sip_request *req;
	int res;
	
	req = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	req->method = sipmethod;
	if (init)
		/* Bump branch even on initial requests */
		build_via(dialog, TRUE);

	if (init == 2) /* open a new dialog */
		initreqprep(req, dialog, sipmethod);
	else
		reqprep(req, dialog, sipmethod, 0, TRUE);
		
	if (dialog->inviteoptions && dialog->inviteoptions->auth)
		add_header(req, dialog->inviteoptions->authheader, dialog->inviteoptions->auth);
	append_date(req);
	if (sipmethod == SIP_REFER && dialog->refer) { /* Call transfer */
		char buf[BUFSIZ];
		if (!ast_strlen_zero(dialog->refer->refer_to))
			add_header(req, "Refer-To", dialog->refer->refer_to);
		if (!ast_strlen_zero(dialog->refer->referred_by)) {
			sprintf(buf, "%s <%s>", dialog->refer->referred_by_name, dialog->refer->referred_by);
			add_header(req, "Referred-By", buf);
		}
	}

	if (dialog->inviteoptions && !ast_strlen_zero(dialog->inviteoptions->replaces)) {
		/* This new INVITE is part of an attended transfer. Make sure that the
	 	   other end knows and replace the current call with this new call */
		add_header(req, "Replaces", dialog->inviteoptions->replaces);
		add_header(req, "Require", "replaces");
	}

	add_header(req, "Allow", ALLOWED_METHODS);
	add_header(req, "Supported", SUPPORTED_EXTENSIONS);
	if (dialog->inviteoptions && dialog->inviteoptions->addsipheaders) {
		struct ast_channel *ast;
		struct varshead *headp = NULL;
		const struct ast_var_t *current;

		ast = dialog->owner;	/* The owner channel */
		if (ast) {
			char *headdup;
	 		headp = &ast->varshead;
			if (!headp)
				ast_log(LOG_WARNING,"No varshead for the channel...ooops!\n");
			else {
				AST_LIST_TRAVERSE(headp, current, entries) {  
					/* SIPADDHEADER: Add SIP header to outgoing call */
					if (!strncasecmp(ast_var_name(current), "SIPADDHEADER", strlen("SIPADDHEADER"))) {
						char *content, *end;
						const char *header = ast_var_value(current);

						headdup = ast_strdupa(header);
						/* Strip of the starting " (if it's there) */
						if (*headdup == '"')
					 		headdup++;
						if ((content = strchr(headdup, ':'))) {
							*content++ = '\0';
							content = ast_skip_blanks(content); /* Skip white space */
							/* Strip the ending " (if it's there) */
					 		end = content + strlen(content) -1;	
							if (*end == '"')
								*end = '\0';
						
							add_header(req, headdup, content);
							if (sipdebug)
								ast_log(LOG_DEBUG, "Adding SIP Header \"%s\" with content :%s: \n", headdup, content);
						}
					}
				}
			}
		}
	}
	if (sdp) {
		if (dialog->udptl && dialog->t38.state == T38_LOCAL_DIRECT) {
			ast_udptl_offered_from_local(dialog->udptl, 1);
			if (option_debug)
				ast_log(LOG_DEBUG, "T38 is in state %d on channel %s\n", dialog->t38.state, dialog->owner ? dialog->owner->name : "<none>");
			add_t38_sdp(req, dialog);
		} else if (dialog->rtp) 
			add_sdp(req, dialog);
	} else {
		add_header_contentLength(req, 0);
	}

	if (!dialog->initreq)
		initialize_initreq(dialog, req);
	dialog->lastinvite = dialog->ocseq;
	res = send_request(dialog, req, init ? XMIT_CRITICAL : XMIT_RELIABLE);

	if (!init)
		siprequest_free(req);

	return res;
}

/*! \brief Notify user of messages waiting in voicemail
\note	- Notification only works for registered peers with mailbox= definitions
	in sip.conf
	- We use the SIP Event package message-summary
	 MIME type defaults to  "application/simple-message-summary";
 */
GNURK int transmit_notify_with_mwi(struct sip_dialog *p, int newmsgs, int oldmsgs, char *vmexten)
{
	struct sip_request *req;
	char tmp[500];
	char *t = tmp;
	size_t maxbytes = sizeof(tmp);

	req = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	initreqprep(req, p, SIP_NOTIFY);
	add_header(req, "Event", "message-summary");
	add_header(req, "Content-Type", global.default_notifymime);

	ast_build_string(&t, &maxbytes, "Messages-Waiting: %s\r\n", newmsgs ? "yes" : "no");
	ast_build_string(&t, &maxbytes, "Message-Account: sip:%s@%s\r\n",
		S_OR(vmexten, global.default_vmexten), S_OR(p->fromdomain, ast_inet_ntoa(p->ourip)));
	ast_build_string(&t, &maxbytes, "Voice-Message: %d/%d (0/0)\r\n", newmsgs, oldmsgs);
	if (p->subscribed) {
		if (p->expiry)
			add_header(req, "Subscription-State", "active");
		else	/* Expired */
			add_header(req, "Subscription-State", "terminated;reason=timeout");
	}

	if (t > tmp + sizeof(tmp))
		ast_log(LOG_WARNING, "Buffer overflow detected!!  (Please file a bug report)\n");

	add_header_contentLength(req, strlen(tmp));
	add_line(req, tmp);

	if (!p->initreq) 
		initialize_initreq(p, req);
	return send_request(p, req, XMIT_RELIABLE);
}

/*! \brief Transmit SIP request unreliably (only used in sip_notify subsystem) */
GNURK int transmit_sip_request(struct sip_dialog *p, struct sip_request *req)
{
	if (!p->initreq) 	/* Initialize first request before sending */
		initialize_initreq(p, req);
	return send_request(p, req, XMIT_UNRELIABLE);
}

/*! \brief Transmit text with SIP MESSAGE method */
GNURK int transmit_message_with_text(struct sip_dialog *p, const char *text)
{
	struct sip_request *req;
	size_t len = SIP_MAX_PACKET;

	/* If we have a very large text message, allocate enough memory for it 
		We're guessing that the max size of headers is 500 bytes here.
	*/
	if (strlen(text) > (len - 500))
		len += strlen(text);

	req = siprequest_alloc(len, &sipnet);

	reqprep(req, p, SIP_MESSAGE, 0, TRUE);
	add_text(req, text);
	return send_request(p, req, XMIT_RELIABLE);
}

/*! \brief Transmit SIP REFER message (initiated by the transfer() dialplan application
	\note this is currently broken as we have no way of telling the dialplan
	engine whether a transfer succeeds or fails.
	\todo Fix the transfer() dialplan function so that a transfer may fail
*/
GNURK int transmit_refer(struct sip_dialog *p, const char *dest)
{
	struct sip_request *req;
	char from[256];
	const char *of;
	char *c;
	char referto[256];
	char *ttag, *ftag;
	char *theirtag = ast_strdupa(p->theirtag);

	
	req = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	req->headers = 0;

	if (option_debug || sipdebug)
		ast_log(LOG_DEBUG, "SIP transfer of %s to %s\n", p->callid, dest);

	/* Are we transfering an inbound or outbound call ? */
	if (ast_test_flag(&p->flags[0], SIP_OUTGOING))  {
		of = get_header(p->initreq, "To");
		ttag = theirtag;
		ftag = p->tag;
	} else {
		of = get_header(p->initreq, "From");
		ftag = theirtag;
		ttag = p->tag;
	}

	ast_copy_string(from, of, sizeof(from));
	of = get_in_brackets(from);
	ast_string_field_set(p, from, of);
	if (strncmp(of, "sip:", 4))
		ast_log(LOG_NOTICE, "From address missing 'sip:', using it anyway\n");
	else
		of += 4;
	/* Get just the username part */
	if ((c = strchr(dest, '@')))
		c = NULL;
	else if ((c = strchr(of, '@')))
		*c++ = '\0';
	if (c) 
		snprintf(referto, sizeof(referto), "<sip:%s@%s>", dest, c);
	else
		snprintf(referto, sizeof(referto), "<sip:%s>", dest);

	/* save in case we get 407 challenge */
	sip_refer_allocate(p);
	ast_copy_string(p->refer->refer_to, referto, sizeof(p->refer->refer_to));
	ast_copy_string(p->refer->referred_by, p->our_contact, sizeof(p->refer->referred_by));
	p->refer->status = REFER_SENT;   /* Set refer status */

	reqprep(req, p, SIP_REFER, 0, TRUE);
	append_maxforwards(req);

	add_header(req, "Refer-To", referto);
	add_header(req, "Allow", ALLOWED_METHODS);
	add_header(req, "Supported", SUPPORTED_EXTENSIONS);
	if (!ast_strlen_zero(p->our_contact))
		add_header(req, "Referred-By", p->our_contact);

	return send_request(p, req, XMIT_RELIABLE);
	/* We should propably wait for a NOTIFY here until we ack the transfer */
	/* Maybe fork a new thread and wait for a STATUS of REFER_200OK on the refer status before returning to app_transfer */

	/*! \todo In theory, we should hang around and wait for a reply, before
	returning to the dial plan here. Don't know really how that would
	affect the transfer() app or the pbx, but, well, to make this
	useful we should have a STATUS code on transfer().
	*/
}


/*! \brief Send SIP INFO dtmf message, see Cisco documentation on cisco.com */
GNURK int transmit_info_with_digit(struct sip_dialog *p, const char digit, unsigned int duration)
{
	struct sip_request *req;

	req = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	reqprep(req, p, SIP_INFO, 0, TRUE);
	add_digit(req, digit, duration);
	return send_request(p, req, XMIT_RELIABLE);
}

/*! \brief Send SIP INFO with video update request */
GNURK int transmit_info_with_vidupdate(struct sip_dialog *p)
{
	struct sip_request *req;
	req = siprequest_alloc(SIP_MAX_PACKET, &sipnet);

	reqprep(req, p, SIP_INFO, 0, TRUE);
	add_vidupdate(req);
	return send_request(p, req, XMIT_RELIABLE);
}

/*! \brief Transmit generic SIP request */
GNURK int transmit_request(struct sip_dialog *p, int sipmethod, int seqno, enum xmittype reliable, int newbranch)
{
	struct sip_request *resp;
	int res;

	resp = siprequest_alloc(SIP_MAX_PACKET, &sipnet);

	reqprep(resp, p, sipmethod, seqno, newbranch);
	add_header_contentLength(resp, 0);
	res = send_request(p, resp, reliable);
	if (reliable == XMIT_UNRELIABLE)
		siprequest_free(resp);
	return res;
}

/*! \brief Transmit SIP request, auth added */
GNURK int transmit_request_with_auth(struct sip_dialog *dialog, int sipmethod, int seqno, enum xmittype reliable, int newbranch)
{
	struct sip_request *resp;
	int res;

	resp = siprequest_alloc(SIP_MAX_PACKET, &sipnet);
	if (!resp) {
		ast_log(LOG_ERROR, "--- Can't allocate SIP request for this transaction! Call ID %s\n", dialog->callid);
	}

	reqprep(resp, dialog, sipmethod, seqno, newbranch);
	if (!ast_strlen_zero(dialog->realm)) {
		char digest[1024];

		memset(digest, 0, sizeof(digest));
		if(!build_reply_digest(dialog, sipmethod, digest, sizeof(digest))) {
			char *dummy, *response;

			enum sip_auth_type code = dialog->inviteoptions ? dialog->inviteoptions->auth_type : PROXY_AUTH; /* XXX force 407 if unknown */
			auth_headers(code, &dummy, &response);
			add_header(resp, response, digest);
		} else
			ast_log(LOG_WARNING, "No authentication available for call %s\n", dialog->callid);
	}
	/* If we are hanging up and know a cause for that, send it in clear text to make
		debugging easier. */
	if (sipmethod == SIP_BYE && dialog->owner && dialog->owner->hangupcause)	{
		char buf[10];

		add_header(resp, "X-Asterisk-HangupCause", ast_cause2str(dialog->owner->hangupcause));
		snprintf(buf, sizeof(buf), "%d", dialog->owner->hangupcause);
		add_header(resp, "X-Asterisk-HangupCauseCode", buf);
	}

	add_header_contentLength(resp, 0);

	res = send_request(dialog, resp, reliable);
	if (reliable == XMIT_UNRELIABLE)
		siprequest_free(resp);
	return res;
}

/*! \brief Send a fake 401 Unauthorized response when the administrator
  wants to hide the names of local users/peers from fishers
 */
GNURK void transmit_fake_auth_response(struct sip_dialog *p, struct sip_request *req, int reliable)
{
	ast_string_field_build(p, randdata, "%08lx", ast_random());	/* Create nonce for challenge */
	transmit_response_with_auth(p, "401 Unauthorized", req, p->randdata, reliable, "WWW-Authenticate", 0);
}
