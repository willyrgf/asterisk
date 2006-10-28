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
 * \brief Various SIP SDP and RTP handling functions
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
#include "asterisk/linkedlists.h"
#include "asterisk/stringfields.h"
#include "asterisk/monitor.h"
#include "asterisk/abstract_jb.h"
#include "asterisk/compiler.h"
#include "sip3.h"
#include "sip3funcs.h"

/* Forward declarations */
static int sip_get_codec(struct ast_channel *chan);
static int sip_set_udptl_peer(struct ast_channel *chan, struct ast_udptl *udptl);
static struct ast_udptl *sip_get_udptl_peer(struct ast_channel *chan);

/*! \brief Interface structure with callbacks used to connect to RTP module */
static struct ast_rtp_protocol sip_rtp = {
	type: "SIP",
	get_rtp_info: sip_get_rtp_peer,
	get_vrtp_info: sip_get_vrtp_peer,
	set_rtp_peer: sip_set_rtp_peer,
	get_codec: sip_get_codec,
};

/*! \brief Interface structure with callbacks used to connect to UDPTL module*/
static struct ast_udptl_protocol sip_udptl = {
	type: "SIP",
	get_udptl_info: sip_get_udptl_peer,
	set_udptl_peer: sip_set_udptl_peer,
};

/*! \brief Register RTP and UDPTL to the subsystems */
void register_rtp_and_udptl(void)
{
	/* Tell the RTP subdriver that we're here */
	ast_rtp_proto_register(&sip_rtp);

	/* Tell the UDPTL subdriver that we're here */
	ast_udptl_proto_register(&sip_udptl);
}

/*! \brief UNRegister RTP and UDPTL to the subsystems */
void unregister_rtp_and_udptl(void)
{
	/* Tell the RTP subdriver that we're gone */
	ast_rtp_proto_unregister(&sip_rtp);

	/* Tell the UDPTL subdriver that we're gone */
	ast_udptl_proto_unregister(&sip_udptl);
}


/*! \brief Reads one line of SIP message body */
static char *get_body_by_line(const char *line, const char *name, int nameLen)
{
	if (strncasecmp(line, name, nameLen) == 0 && line[nameLen] == '=')
		return ast_skip_blanks(line + nameLen + 1);

	return "";
}

/*! \brief Lookup 'name' in the SDP starting
 * at the 'start' line. Returns the matching line, and 'start'
 * is updated with the next line number.
 */
static const char *get_sdp_iterate(int *start, struct sip_request *req, const char *name)
{
	int len = strlen(name);

	while (*start < req->sdp_end) {
		const char *r = get_body_by_line(req->line[(*start)++], name, len);
		if (r[0] != '\0')
			return r;
	}

	return "";
}

/*! \brief Get a line from an SDP message body */
static const char *get_sdp(struct sip_request *req, const char *name) 
{
	int dummy = 0;

	return get_sdp_iterate(&dummy, req, name);
}

/*! \brief Get the message body part identified by name= */
char *get_body(struct sip_request *req, char *name) 
{
	int x;
	int len = strlen(name);
	char *r;

	for (x = 0; x < req->lines; x++) {
		r = get_body_by_line(req->line[x], name, len);
		if (r[0] != '\0')
			return r;
	}

	return "";
}

/*! \brief Process SIP SDP offer, select formats and activate RTP channels
	If offer is rejected, we will not change any properties of the call
*/
int process_sdp(struct sip_dialog *p, struct sip_request *req)
{
	const char *m;		/* SDP media offer */
	const char *c;
	const char *a;
	char host[258];
	int len = -1;
	int portno = -1;		/*!< RTP Audio port number */
	int vportno = -1;		/*!< RTP Video port number */
	int udptlportno = -1;
	int peert38capability = 0;
	char s[256];
	int old = 0;

	/* Peer capability is the capability in the SDP, non codec is RFC2833 DTMF (101) */	
	int peercapability = 0, peernoncodeccapability = 0;
	int vpeercapability = 0, vpeernoncodeccapability = 0;
	struct sockaddr_in sin;		/*!< media socket address */
	struct sockaddr_in vsin;	/*!< Video socket address */

	const char *codecs;
	struct hostent *hp;		/*!< RTP Audio host IP */
	struct hostent *vhp = NULL;	/*!< RTP video host IP */
	struct ast_hostent audiohp;
	struct ast_hostent videohp;
	int codec;
	int destiterator = 0;
	int iterator;
	int sendonly = 0;
	int numberofports;
	struct ast_channel *bridgepeer = NULL;
	struct ast_rtp *newaudiortp, *newvideortp;	/* Buffers for codec handling */
	int newjointcapability;				/* Negotiated capability */
	int newpeercapability;
	int newnoncodeccapability;
	int numberofmediastreams = 0;
	int debug = sip_debug_test_pvt(p);
		
	int found_rtpmap_codecs[32];
	int last_rtpmap_codec=0;

	if (!p->rtp) {
		ast_log(LOG_ERROR, "Got SDP but have no RTP session allocated.\n");
		return -1;
	}

	/* Initialize the temporary RTP structures we use to evaluate the offer from the peer */
	newaudiortp = alloca(ast_rtp_alloc_size());
	memset(newaudiortp, 0, ast_rtp_alloc_size());
	ast_rtp_pt_clear(newaudiortp);

	newvideortp = alloca(ast_rtp_alloc_size());
	memset(newvideortp, 0, ast_rtp_alloc_size());
	ast_rtp_pt_clear(newvideortp);

	/* Update our last rtprx when we receive an SDP, too */
	p->lastrtprx = p->lastrtptx = time(NULL); /* XXX why both ? */


	/* Try to find first media stream */
	m = get_sdp(req, "m");
	destiterator = req->sdp_start;
	c = get_sdp_iterate(&destiterator, req, "c");
	if (ast_strlen_zero(m) || ast_strlen_zero(c)) {
		ast_log(LOG_WARNING, "Insufficient information for SDP (m = '%s', c = '%s')\n", m, c);
		return -1;
	}

	/* Check for IPv4 address (not IPv6 yet) */
	if (sscanf(c, "IN IP4 %256s", host) != 1) {
		ast_log(LOG_WARNING, "Invalid host in c= line, '%s'\n", c);
		return -1;
	}

	/* XXX This could block for a long time, and block the main thread! XXX */
	hp = ast_gethostbyname(host, &audiohp);
	if (!hp) {
		ast_log(LOG_WARNING, "Unable to lookup host in c= line, '%s'\n", c);
		return -1;
	}
	vhp = hp;	/* Copy to video address as default too */
	
	iterator = req->sdp_start;
	ast_set_flag(&p->flags[0], SIP_NOVIDEO);	


	/* Find media streams in this SDP offer */
	while ((m = get_sdp_iterate(&iterator, req, "m"))[0] != '\0') {
		int x;
		int audio = FALSE;

		numberofports = 1;
		if ((sscanf(m, "audio %d/%d RTP/AVP %n", &x, &numberofports, &len) == 2) ||
		    (sscanf(m, "audio %d RTP/AVP %n", &x, &len) == 1)) {
			audio = TRUE;
			numberofmediastreams++;
			/* Found audio stream in this media definition */
			portno = x;
			/* Scan through the RTP payload types specified in a "m=" line: */
			for (codecs = m + len; !ast_strlen_zero(codecs); codecs = ast_skip_blanks(codecs + len)) {
				if (sscanf(codecs, "%d%n", &codec, &len) != 1) {
					ast_log(LOG_WARNING, "Error in codec string '%s'\n", codecs);
					return -1;
				}
				if (debug)
					ast_verbose("Found RTP audio format %d\n", codec);
				ast_rtp_set_m_type(newaudiortp, codec);
			}
		} else if ((sscanf(m, "video %d/%d RTP/AVP %n", &x, &numberofports, &len) == 2) ||
		    (sscanf(m, "video %d RTP/AVP %n", &x, &len) == 1)) {
			/* If it is not audio - is it video ? */
			ast_clear_flag(&p->flags[0], SIP_NOVIDEO);	
			numberofmediastreams++;
			vportno = x;
			/* Scan through the RTP payload types specified in a "m=" line: */
			for (codecs = m + len; !ast_strlen_zero(codecs); codecs = ast_skip_blanks(codecs + len)) {
				if (sscanf(codecs, "%d%n", &codec, &len) != 1) {
					ast_log(LOG_WARNING, "Error in codec string '%s'\n", codecs);
					return -1;
				}
				if (debug)
					ast_verbose("Found RTP video format %d\n", codec);
				ast_rtp_set_m_type(newvideortp, codec);
			}
		} else if (p->udptl && ((sscanf(m, "image %d udptl t38%n", &x, &len) == 1))) {
			if (debug)
				ast_verbose("Got T.38 offer in SDP in dialog %s\n", p->callid);
			udptlportno = x;
			numberofmediastreams++;
			
			if (p->owner && p->lastinvite) {
				p->t38.state = T38_PEER_REINVITE; /* T38 Offered in re-invite from remote party */
				if (option_debug > 1)
					ast_log(LOG_DEBUG, "T38 state changed to %d on channel %s\n", p->t38.state, p->owner ? p->owner->name : "<none>" );
			} else {
				p->t38.state = T38_PEER_DIRECT; /* T38 Offered directly from peer in first invite */
				if (option_debug > 1)
					ast_log(LOG_DEBUG, "T38 state changed to %d on channel %s\n", p->t38.state, p->owner ? p->owner->name : "<none>");
			}
		} else 
			ast_log(LOG_WARNING, "Unsupported SDP media type in offer: %s\n", m);
		if (numberofports > 1)
			ast_log(LOG_WARNING, "SDP offered %d ports for media, not supported by Asterisk. Will try anyway...\n", numberofports);
		

		/* Check for Media-description-level-address for audio */
		c = get_sdp_iterate(&destiterator, req, "c");
		if (!ast_strlen_zero(c)) {
			if (sscanf(c, "IN IP4 %256s", host) != 1) {
				ast_log(LOG_WARNING, "Invalid secondary host in c= line, '%s'\n", c);
			} else {
				/* XXX This could block for a long time, and block the main thread! XXX */
				if (audio) {
					if ( !(hp = ast_gethostbyname(host, &audiohp)))
						ast_log(LOG_WARNING, "Unable to lookup RTP Audio host in secondary c= line, '%s'\n", c);
				} else if (!(vhp = ast_gethostbyname(host, &videohp)))
					ast_log(LOG_WARNING, "Unable to lookup RTP video host in secondary c= line, '%s'\n", c);
			}

		}
	}
	if (portno == -1 && vportno == -1 && udptlportno == -1)
		/* No acceptable offer found in SDP  - we have no ports */
		/* Do not change RTP or VRTP if this is a re-invite */
		return -2;

	if (numberofmediastreams > 2)
		/* We have too many fax, audio and/or video media streams, fail this offer */
		return -3;

	/* RTP addresses and ports for audio and video */
	sin.sin_family = AF_INET;
	vsin.sin_family = AF_INET;
	memcpy(&sin.sin_addr, hp->h_addr, sizeof(sin.sin_addr));
	if (vhp)
		memcpy(&vsin.sin_addr, vhp->h_addr, sizeof(vsin.sin_addr));
		
	if (p->rtp) {
		if (portno > 0) {
			sin.sin_port = htons(portno);
			ast_rtp_set_peer(p->rtp, &sin);
			if (debug)
				ast_verbose("Peer audio RTP is at port %s:%d\n", ast_inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
		} else {
			ast_rtp_stop(p->rtp);
			if (debug)
				ast_verbose("Peer doesn't provide audio\n");
		}
	}
	/* Setup video port number */
	if (vportno != -1)
		vsin.sin_port = htons(vportno);

	/* Setup UDPTL port number */
	if (p->udptl) {
		if (udptlportno > 0) {
			sin.sin_port = htons(udptlportno);
			ast_udptl_set_peer(p->udptl, &sin);
			if (debug)
				ast_log(LOG_DEBUG,"Peer T.38 UDPTL is at port %s:%d\n",ast_inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
		} else {
			ast_udptl_stop(p->udptl);
			if (debug)
				ast_log(LOG_DEBUG, "Peer doesn't provide T.38 UDPTL\n");
		}
	}

	/* Next, scan through each "a=rtpmap:" line, noting each
	 * specified RTP payload type (with corresponding MIME subtype):
	 */
	/* XXX This needs to be done per media stream, since it's media stream specific */
	iterator = req->sdp_start;
	while ((a = get_sdp_iterate(&iterator, req, "a"))[0] != '\0') {
		char* mimeSubtype = ast_strdupa(a); /* ensures we have enough space */
		if (option_debug > 1) {
			int breakout = FALSE;
		
			/* If we're debugging, check for unsupported sdp options */
			if (!strncasecmp(a, "rtcp:", (size_t) 5)) {
				if (debug)
					ast_verbose("Got unsupported a:rtcp in SDP offer \n");
				breakout = TRUE;
			} else if (!strncasecmp(a, "fmtp:", (size_t) 5)) {
				/* Format parameters:  Not supported */
				/* Note: This is used for codec parameters, like bitrate for
					G722 and video formats for H263 and H264 
					See RFC2327 for an example */
				if (debug)
					ast_verbose("Got unsupported a:fmtp in SDP offer \n");
				breakout = TRUE;
			} else if (!strncasecmp(a, "framerate:", (size_t) 10)) {
				/* Video stuff:  Not supported */
				if (debug)
					ast_verbose("Got unsupported a:framerate in SDP offer \n");
				breakout = TRUE;
			} else if (!strncasecmp(a, "maxprate:", (size_t) 9)) {
				/* Video stuff:  Not supported */
				if (debug)
					ast_verbose("Got unsupported a:maxprate in SDP offer \n");
				breakout = TRUE;
			} else if (!strncasecmp(a, "crypto:", (size_t) 7)) {
				/* SRTP stuff, not yet supported */
				if (debug)
					ast_verbose("Got unsupported a:crypto in SDP offer \n");
				breakout = TRUE;
			} else if (!strncasecmp(a, "ptime:", (size_t) 6)) {
				if (debug)
					ast_verbose("Got unsupported a:ptime in SDP offer \n");
				breakout = TRUE;
			}
			if (breakout)	/* We have a match, skip to next header */
				continue;
		}
		if (!strcasecmp(a, "sendonly")) {
			sendonly = 1;
			continue;
		} else if (!strcasecmp(a, "inactive")) {
			sendonly = 2;
			continue;
		}  else if (!strcasecmp(a, "sendrecv")) {
			sendonly = 0;
			continue;
		} else if (strlen(a) > 5 && !strncasecmp(a, "ptime", 5)) {
			char *tmp = strrchr(a, ':');
			long int framing = 0;
			if (tmp) {
				tmp++;
				framing = strtol(tmp, NULL, 10);
				if (framing == LONG_MIN || framing == LONG_MAX) {
					framing = 0;
					if (option_debug)
						ast_log(LOG_DEBUG, "Can't read framing from SDP: %s\n", a);
				}
			}
			if (framing && last_rtpmap_codec) {
				if (p->autoframing || global.autoframing) {
					struct ast_codec_pref *pref = ast_rtp_codec_getpref(p->rtp);
					int codec_n;
					int format = 0;
					for (codec_n = 0; codec_n < last_rtpmap_codec; codec_n++) {
						format = ast_rtp_codec_getformat(found_rtpmap_codecs[codec_n]);
						if (!format)	/* non-codec or not found */
							continue;
						if (option_debug)
							ast_log(LOG_DEBUG, "Setting framing for %d to %ld\n", format, framing);
						ast_codec_pref_setsize(pref, format, framing);
					}
					ast_rtp_codec_setpref(p->rtp, pref);
				}
			}
			memset(&found_rtpmap_codecs, 0, sizeof(found_rtpmap_codecs));
			last_rtpmap_codec = 0;
			continue;
		} else if (sscanf(a, "rtpmap: %u %[^/]/", &codec, mimeSubtype) == 2) {
			/* We have a rtpmap to handle */
			if (debug)
				ast_verbose("Found description format %s for ID %d\n", mimeSubtype, codec);
			found_rtpmap_codecs[last_rtpmap_codec] = codec;
			last_rtpmap_codec++;

			/* Note: should really look at the 'freq' and '#chans' params too */
			ast_rtp_set_rtpmap_type(newaudiortp, codec, "audio", mimeSubtype,
					ast_test_flag(&p->flags[0], SIP_G726_NONSTANDARD) ? AST_RTP_OPT_G726_NONSTANDARD : 0);
			if (p->vrtp)
				ast_rtp_set_rtpmap_type(newvideortp, codec, "video", mimeSubtype, 0);
		}
	}
	
	if (udptlportno != -1) {
		int found = 0, x;
		
		old = 0;
		
		/* Scan trough the a= lines for T38 attributes and set apropriate fileds */
		iterator = req->sdp_start;
		while ((a = get_sdp_iterate(&iterator, req, "a"))[0] != '\0') {
			if ((sscanf(a, "T38FaxMaxBuffer:%d", &x) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "MaxBufferSize:%d\n",x);
			} else if ((sscanf(a, "T38MaxBitRate:%d", &x) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG,"T38MaxBitRate: %d\n",x);
				switch (x) {
				case 14400:
					peert38capability |= T38FAX_RATE_14400 | T38FAX_RATE_12000 | T38FAX_RATE_9600 | T38FAX_RATE_7200 | T38FAX_RATE_4800 | T38FAX_RATE_2400;
					break;
				case 12000:
					peert38capability |= T38FAX_RATE_12000 | T38FAX_RATE_9600 | T38FAX_RATE_7200 | T38FAX_RATE_4800 | T38FAX_RATE_2400;
					break;
				case 9600:
					peert38capability |= T38FAX_RATE_9600 | T38FAX_RATE_7200 | T38FAX_RATE_4800 | T38FAX_RATE_2400;
					break;
				case 7200:
					peert38capability |= T38FAX_RATE_7200 | T38FAX_RATE_4800 | T38FAX_RATE_2400;
					break;
				case 4800:
					peert38capability |= T38FAX_RATE_4800 | T38FAX_RATE_2400;
					break;
				case 2400:
					peert38capability |= T38FAX_RATE_2400;
					break;
				}
			} else if ((sscanf(a, "T38FaxVersion:%d", &x) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "FaxVersion: %d\n",x);
				if (x == 0)
					peert38capability |= T38FAX_VERSION_0;
				else if (x == 1)
					peert38capability |= T38FAX_VERSION_1;
			} else if ((sscanf(a, "T38FaxMaxDatagram:%d", &x) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "FaxMaxDatagram: %d\n",x);
				ast_udptl_set_far_max_datagram(p->udptl, x);
				ast_udptl_set_local_max_datagram(p->udptl, x);
			} else if ((sscanf(a, "T38FaxFillBitRemoval:%d", &x) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "FillBitRemoval: %d\n",x);
				if (x == 1)
					peert38capability |= T38FAX_FILL_BIT_REMOVAL;
			} else if ((sscanf(a, "T38FaxTranscodingMMR:%d", &x) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "Transcoding MMR: %d\n",x);
				if (x == 1)
					peert38capability |= T38FAX_TRANSCODING_MMR;
			}
			if ((sscanf(a, "T38FaxTranscodingJBIG:%d", &x) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "Transcoding JBIG: %d\n",x);
				if (x == 1)
					peert38capability |= T38FAX_TRANSCODING_JBIG;
			} else if ((sscanf(a, "T38FaxRateManagement:%s", s) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "RateMangement: %s\n", s);
				if (!strcasecmp(s, "localTCF"))
					peert38capability |= T38FAX_RATE_MANAGEMENT_LOCAL_TCF;
				else if (!strcasecmp(s, "transferredTCF"))
					peert38capability |= T38FAX_RATE_MANAGEMENT_TRANSFERED_TCF;
			} else if ((sscanf(a, "T38FaxUdpEC:%s", s) == 1)) {
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "UDP EC: %s\n", s);
				if (!strcasecmp(s, "t38UDPRedundancy")) {
					peert38capability |= T38FAX_UDP_EC_REDUNDANCY;
					ast_udptl_set_error_correction_scheme(p->udptl, UDPTL_ERROR_CORRECTION_REDUNDANCY);
				} else if (!strcasecmp(s, "t38UDPFEC")) {
					peert38capability |= T38FAX_UDP_EC_FEC;
					ast_udptl_set_error_correction_scheme(p->udptl, UDPTL_ERROR_CORRECTION_FEC);
				} else {
					peert38capability |= T38FAX_UDP_EC_NONE;
					ast_udptl_set_error_correction_scheme(p->udptl, UDPTL_ERROR_CORRECTION_NONE);
				}
			}
		}
		if (found) { /* Some cisco equipment returns nothing beside c= and m= lines in 200 OK T38 SDP */
			p->t38.peercapability = peert38capability;
			p->t38.jointcapability = (peert38capability & 255); /* Put everything beside supported speeds settings */
			peert38capability &= (T38FAX_RATE_14400 | T38FAX_RATE_12000 | T38FAX_RATE_9600 | T38FAX_RATE_7200 | T38FAX_RATE_4800 | T38FAX_RATE_2400);
			p->t38.jointcapability |= (peert38capability & p->t38.capability); /* Put the lower of our's and peer's speed */
		}
		if (debug)
			ast_log(LOG_DEBUG, "Our T38 capability = (%d), peer T38 capability (%d), joint T38 capability (%d)\n",
				p->t38.capability,
				p->t38.peercapability,
				p->t38.jointcapability);
	} else {
		p->t38.state = T38_DISABLED;
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "T38 state changed to %d on channel %s\n", p->t38.state, p->owner ? p->owner->name : "<none>");
	}

	/* Now gather all of the codecs that we are asked for: */
	ast_rtp_get_current_formats(newaudiortp, &peercapability, &peernoncodeccapability);
	ast_rtp_get_current_formats(newvideortp, &vpeercapability, &vpeernoncodeccapability);

	newjointcapability = p->capability & (peercapability | vpeercapability);
	newpeercapability = (peercapability | vpeercapability);
	newnoncodeccapability = global.dtmf_capability & peernoncodeccapability;
		
		
	if (debug) {
		/* shame on whoever coded this.... */
		char s1[BUFSIZ], s2[BUFSIZ], s3[BUFSIZ], s4[BUFSIZ];

		ast_verbose("Capabilities: us - %s, peer - audio=%s/video=%s, combined - %s\n",
			    ast_getformatname_multiple(s1, BUFSIZ, p->capability),
			    ast_getformatname_multiple(s2, BUFSIZ, newpeercapability),
			    ast_getformatname_multiple(s3, BUFSIZ, vpeercapability),
			    ast_getformatname_multiple(s4, BUFSIZ, newjointcapability));

		ast_verbose("Non-codec capabilities (dtmf): us - %s, peer - %s, combined - %s\n",
			    ast_rtp_lookup_mime_multiple(s1, BUFSIZ, global.dtmf_capability, 0, 0),
			    ast_rtp_lookup_mime_multiple(s2, BUFSIZ, peernoncodeccapability, 0, 0),
			    ast_rtp_lookup_mime_multiple(s3, BUFSIZ, newnoncodeccapability, 0, 0));
	}
	if (!newjointcapability) {
		/* If T.38 was not negotiated either, totally bail out... */
		if (!p->t38.jointcapability) {
			ast_log(LOG_NOTICE, "No compatible codecs, not accepting this offer!\n");
			/* Do NOT Change current setting */
			return -1;
		} else {
			if (option_debug > 2)
				ast_log(LOG_DEBUG, "Have T.38 but no audio codecs, accepting offer anyway\n");
			return 0;
		}
	}

	/* We are now ready to change the sip session and p->rtp and p->vrtp with the offered codecs, since
		they are acceptable */
	p->jointcapability = newjointcapability;	/* Our joint codec profile for this call */
	p->peercapability = newpeercapability;		/* The other sides capability in latest offer */
	p->noncodeccapability = newnoncodeccapability;	/* DTMF capabilities */

	ast_rtp_pt_copy(p->rtp, newaudiortp);
	if (p->vrtp)
		ast_rtp_pt_copy(p->vrtp, newvideortp);

	if (ast_test_flag(&p->flags[0], SIP_DTMF) == SIP_DTMF_AUTO) {
		ast_clear_flag(&p->flags[0], SIP_DTMF);
		if (newnoncodeccapability & AST_RTP_DTMF) {
			/* XXX Would it be reasonable to drop the DSP at this point? XXX */
			ast_set_flag(&p->flags[0], SIP_DTMF_RFC2833);
		} else {
			ast_set_flag(&p->flags[0], SIP_DTMF_INBAND);
		}
	}

	/* Setup audio port number */
	if (p->rtp && sin.sin_port) {
		ast_rtp_set_peer(p->rtp, &sin);
		if (debug)
			ast_verbose("Peer audio RTP is at port %s:%d\n", ast_inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
	}

	/* Setup video port number */
	if (p->vrtp && vsin.sin_port) {
		ast_rtp_set_peer(p->vrtp, &vsin);
		if (debug) 
			ast_verbose("Peer video RTP is at port %s:%d\n", ast_inet_ntoa(vsin.sin_addr), ntohs(vsin.sin_port));
	}

	/* Ok, we're going with this offer */
	if (option_debug > 1) {
		char buf[BUFSIZ];
		ast_log(LOG_DEBUG, "We're settling with these formats: %s\n", ast_getformatname_multiple(buf, BUFSIZ, p->jointcapability));
	}

	if (!p->owner) 	/* There's no open channel owning us so we can return here. For a re-invite or so, we proceed */
		return 0;

	if (option_debug > 3)
		ast_log(LOG_DEBUG, "We have an owner, now see if we need to change this call\n");

	if (!(p->owner->nativeformats & p->jointcapability & AST_FORMAT_AUDIO_MASK)) {
		if (debug) {
			char s1[BUFSIZ], s2[BUFSIZ];
			ast_log(LOG_DEBUG, "Oooh, we need to change our audio formats since our peer supports only %s and not %s\n", 
				ast_getformatname_multiple(s1, BUFSIZ, p->jointcapability),
				ast_getformatname_multiple(s2, BUFSIZ, p->owner->nativeformats));
		}
		p->owner->nativeformats = ast_codec_choose(&p->prefs, p->jointcapability, 1) | (p->capability & vpeercapability);
		ast_set_read_format(p->owner, p->owner->readformat);
		ast_set_write_format(p->owner, p->owner->writeformat);
	}
	
	/* Turn on/off music on hold if we are holding/unholding */
	if ((bridgepeer = ast_bridged_channel(p->owner))) {
		if (sin.sin_addr.s_addr && !sendonly) {
			ast_queue_control(p->owner, AST_CONTROL_UNHOLD);
			/* Activate a re-invite */
			ast_queue_frame(p->owner, &ast_null_frame);
		} else if (!sin.sin_addr.s_addr || sendonly) {
			ast_queue_control_data(p->owner, AST_CONTROL_HOLD, 
					       S_OR(p->mohsuggest, NULL),
					       !ast_strlen_zero(p->mohsuggest) ? strlen(p->mohsuggest) + 1 : 0);
			if (sendonly)
				ast_rtp_stop(p->rtp);
			/* RTCP needs to go ahead, even if we're on hold!!! */
			/* Activate a re-invite */
			ast_queue_frame(p->owner, &ast_null_frame);
		}
	}

	/* Manager Hold and Unhold events must be generated, if necessary */
	if (sin.sin_addr.s_addr && !sendonly) {
		if (ast_test_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD)) {
			append_history(p, "Unhold", "%s", req->data);
			if (global.callevents)
				manager_event(EVENT_FLAG_CALL, "Unhold",
					"Channel: %s\r\n"
					"Uniqueid: %s\r\n",
					p->owner->name, 
					p->owner->uniqueid);
			sip_peer_hold(p, 0);
		} 
		ast_clear_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD);	/* Clear both flags */
	} else if (!sin.sin_addr.s_addr || sendonly ) {
		/* No address for RTP, we're on hold */
		append_history(p, "Hold", "%s", req->data);

		if (global.callevents && !ast_test_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD)) {
			manager_event(EVENT_FLAG_CALL, "Hold",
				"Channel: %s\r\n"
				"Uniqueid: %s\r\n",
				p->owner->name, 
				p->owner->uniqueid);
		}
		if (sendonly == 1)	/* One directional hold (sendonly/recvonly) */
			ast_set_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD_ONEDIR);
		else if (sendonly == 2)	/* Inactive stream */
			ast_set_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD_INACTIVE);
		sip_peer_hold(p, 1);
	}
	
	return 0;
}


/*! \brief Set the RTP peer for this call */
int sip_set_rtp_peer(struct ast_channel *chan, struct ast_rtp *rtp, struct ast_rtp *vrtp, int codecs, int nat_active)
{
	struct sip_dialog *p;
	int changed = 0;

	p = chan->tech_pvt;
	if (!p) 
		return -1;
	ast_mutex_lock(&p->lock);
	if (ast_test_flag(&p->flags[0], SIP_ALREADYGONE)) {
		/* If we're destroyed, don't bother */
		ast_mutex_unlock(&p->lock);
		return 0;
	}

	/* if this peer cannot handle reinvites of the media stream to devices
	   that are known to be behind a NAT, then stop the process now
	*/
	if (nat_active && !ast_test_flag(&p->flags[0], SIP_CAN_REINVITE_NAT)) {
		ast_mutex_unlock(&p->lock);
		return 0;
	}

	if (rtp) {
		changed |= ast_rtp_get_peer(rtp, &p->redirip);
	} else if (p->redirip.sin_addr.s_addr || ntohs(p->redirip.sin_port) != 0) {
		memset(&p->redirip, 0, sizeof(p->redirip));
		changed = 1;
	}
	if (vrtp) {
		changed |= ast_rtp_get_peer(vrtp, &p->vredirip);
	} else if (p->vredirip.sin_addr.s_addr || ntohs(p->vredirip.sin_port) != 0) {
		memset(&p->vredirip, 0, sizeof(p->vredirip));
		changed = 1;
	}
	if (codecs && (p->redircodecs != codecs)) {
		p->redircodecs = codecs;
		changed = 1;
	}
	if (changed && !ast_test_flag(&p->flags[0], SIP_GOTREFER)) {
		if (chan->_state != AST_STATE_UP) {	/* We are in early state */
			if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY))
				append_history(p, "ExtInv", "Initial invite sent with remote bridge proposal.");
			if (option_debug)
				ast_log(LOG_DEBUG, "Early remote bridge setting SIP '%s' - Sending media to %s\n", p->callid, ast_inet_ntoa(rtp ? p->redirip.sin_addr : p->ourip));
		} else if (!p->pendinginvite) {		/* We are up, and have no outstanding invite */
			if (option_debug > 2) {
				ast_log(LOG_DEBUG, "Sending reinvite on SIP '%s' - It's audio soon redirected to IP %s\n", p->callid, ast_inet_ntoa(rtp ? p->redirip.sin_addr : p->ourip));
			}
			transmit_reinvite_with_sdp(p);
		} else if (!ast_test_flag(&p->flags[0], SIP_PENDINGBYE)) {
			if (option_debug > 2) {
				ast_log(LOG_DEBUG, "Deferring reinvite on SIP '%s' - It's audio will be redirected to IP %s\n", p->callid, ast_inet_ntoa(rtp ? p->redirip.sin_addr : p->ourip));
			}
			/* We have a pending Invite. Send re-invite when we're done with the invite */
			ast_set_flag(&p->flags[0], SIP_NEEDREINVITE);	
		}
	}
	/* Reset lastrtprx timer */
	p->lastrtprx = p->lastrtptx = time(NULL);
	ast_mutex_unlock(&p->lock);
	return 0;
}

/*! \brief Returns null if we can't reinvite audio (part of RTP interface) */
enum ast_rtp_get_result sip_get_rtp_peer(struct ast_channel *chan, struct ast_rtp **rtp)
{
	struct sip_dialog *p = NULL;
	enum ast_rtp_get_result res = AST_RTP_TRY_PARTIAL;

	if (!(p = chan->tech_pvt))
		return AST_RTP_GET_FAILED;

	ast_mutex_lock(&p->lock);
	if (!(p->rtp)) {
		ast_mutex_unlock(&p->lock);
		return AST_RTP_GET_FAILED;
	}

	*rtp = p->rtp;

	if (ast_test_flag(&p->flags[0], SIP_CAN_REINVITE))
		res = AST_RTP_TRY_NATIVE;
	else if (ast_test_flag(&global.jbconf, AST_JB_FORCED))
		res = AST_RTP_GET_FAILED;

	ast_mutex_unlock(&p->lock);

	return res;
}

/*! \brief Returns null if we can't reinvite video (part of RTP interface) */
enum ast_rtp_get_result sip_get_vrtp_peer(struct ast_channel *chan, struct ast_rtp **rtp)
{
	struct sip_dialog *p = NULL;
	enum ast_rtp_get_result res = AST_RTP_TRY_PARTIAL;
	
	if (!(p = chan->tech_pvt) || !(p->vrtp))
		return AST_RTP_GET_FAILED;

	ast_mutex_lock(&p->lock);

	*rtp = p->vrtp;

	if (ast_test_flag(&p->flags[0], SIP_CAN_REINVITE))
		res = AST_RTP_TRY_NATIVE;

	ast_mutex_unlock(&p->lock);

	return res;
}

/*!
  \brief Determine whether a SIP message contains an SDP in its body
  \param req the SIP request to process
  \return 1 if SDP found, 0 if not found

  Also updates req->sdp_start and req->sdp_end to indicate where the SDP
  lives in the message body.
*/
int find_sdp(struct sip_request *req)
{
	const char *content_type;
	const char *search;
	char *boundary;
	unsigned int x;

	content_type = get_header(req, "Content-Type");

	/* if the body contains only SDP, this is easy */
	if (!strcasecmp(content_type, "application/sdp")) {
		req->sdp_start = 0;
		req->sdp_end = req->lines;
		return 1;
	}

	/* if it's not multipart/mixed, there cannot be an SDP */
	if (strncasecmp(content_type, "multipart/mixed", 15))
		return 0;

	/* if there is no boundary marker, it's invalid */
	if (!(search = strcasestr(content_type, ";boundary=")))
		return 0;

	search += 10;

	if (ast_strlen_zero(search))
		return 0;

	/* make a duplicate of the string, with two extra characters
	   at the beginning */
	boundary = ast_strdupa(search - 2);
	boundary[0] = boundary[1] = '-';

	/* search for the boundary marker, but stop when there are not enough
	   lines left for it, the Content-Type header and at least one line of
	   body */
	for (x = 0; x < (req->lines - 2); x++) {
		if (!strncasecmp(req->line[x], boundary, strlen(boundary)) &&
		    !strcasecmp(req->line[x + 1], "Content-Type: application/sdp")) {
			req->sdp_start = x + 2;
			/* search for the end of the body part */
			for ( ; x < req->lines; x++) {
				if (!strncasecmp(req->line[x], boundary, strlen(boundary)))
					break;
			}
			req->sdp_end = x;
			return 1;
		}
	}

	return 0;
}

/*! \brief Add RFC 2833 DTMF offer to SDP */
static void add_noncodec_to_sdp(const struct sip_dialog *p, int format, int sample_rate,
				char **m_buf, size_t *m_size, char **a_buf, size_t *a_size,
				int debug)
{
	int rtp_code;

	if (debug)
		ast_verbose("Adding non-codec 0x%x (%s) to SDP\n", format, ast_rtp_lookup_mime_subtype(0, format, 0));
	if ((rtp_code = ast_rtp_lookup_code(p->rtp, 0, format)) == -1)
		return;

	ast_build_string(m_buf, m_size, " %d", rtp_code);
	ast_build_string(a_buf, a_size, "a=rtpmap:%d %s/%d\r\n", rtp_code,
			 ast_rtp_lookup_mime_subtype(0, format, 0),
			 sample_rate);
	if (format == AST_RTP_DTMF)
		/* Indicate we support DTMF and FLASH... */
		ast_build_string(a_buf, a_size, "a=fmtp:%d 0-16\r\n", rtp_code);
}

/*! \brief Add codec offer to SDP offer/answer body in INVITE or 200 OK */
static void add_codec_to_sdp(const struct sip_dialog *p, int codec, int sample_rate,
			     char **m_buf, size_t *m_size, char **a_buf, size_t *a_size,
			     int debug)
{
	int rtp_code;
	struct ast_format_list fmt;


	if (debug)
		ast_verbose("Adding codec 0x%x (%s) to SDP\n", codec, ast_getformatname(codec));
	if ((rtp_code = ast_rtp_lookup_code(p->rtp, 1, codec)) == -1)
		return;

	if (p->rtp) {
		struct ast_codec_pref *pref = ast_rtp_codec_getpref(p->rtp);
		fmt = ast_codec_pref_getsize(pref, codec);
	} else /* I dont see how you couldn't have p->rtp, but good to check for and error out if not there like earlier code */
		return;
	ast_build_string(m_buf, m_size, " %d", rtp_code);
	ast_build_string(a_buf, a_size, "a=rtpmap:%d %s/%d\r\n", rtp_code,
			 ast_rtp_lookup_mime_subtype(1, codec,
						     ast_test_flag(&p->flags[0], SIP_G726_NONSTANDARD) ? AST_RTP_OPT_G726_NONSTANDARD : 0),
			 sample_rate);
	if (codec == AST_FORMAT_G729A) {
		/* Indicate that we don't support VAD (G.729 annex B) */
		ast_build_string(a_buf, a_size, "a=fmtp:%d annexb=no\r\n", rtp_code);
	} else if (codec == AST_FORMAT_ILBC) {
		/* Add information about us using only 20/30 ms packetization */
		ast_build_string(a_buf, a_size, "a=fmtp:%d mode=%d\r\n", rtp_code, fmt.cur_ms);
	}

	if (codec != AST_FORMAT_ILBC) 
		ast_build_string(a_buf, a_size, "a=ptime:%d\r\n", fmt.cur_ms);
}

/*! \brief Add Session Description Protocol message */
int add_sdp(struct sip_request *resp, struct sip_dialog *p)
{
	int len = 0;
	int alreadysent = 0;

	struct sockaddr_in sin;
	struct sockaddr_in vsin;
	struct sockaddr_in dest;
	struct sockaddr_in vdest = { 0, };

	/* SDP fields */
	char *version = 	"v=0\r\n";		/* Protocol version */
	char *subject = 	"s=session\r\n";	/* Subject of the session */
	char owner[256];				/* Session owner/creator */
	char connection[256];				/* Connection data */
	char *stime = "t=0 0\r\n"; 			/* Time the session is active */
	char bandwidth[256] = "";			/* Max bitrate */
	char *hold;
	char m_audio[256];				/* Media declaration line for audio */
	char m_video[256];				/* Media declaration line for video */
	char a_audio[1024];				/* Attributes for audio */
	char a_video[1024];				/* Attributes for video */
	char *m_audio_next = m_audio;
	char *m_video_next = m_video;
	size_t m_audio_left = sizeof(m_audio);
	size_t m_video_left = sizeof(m_video);
	char *a_audio_next = a_audio;
	char *a_video_next = a_video;
	size_t a_audio_left = sizeof(a_audio);
	size_t a_video_left = sizeof(a_video);

	int x;
	int capability;
	int needvideo = FALSE;
	int debug = sip_debug_test_pvt(p);

	m_video[0] = '\0';	/* Reset the video media string if it's not needed */

	if (!p->rtp) {
		ast_log(LOG_WARNING, "No way to add SDP without an RTP structure\n");
		return -1;
	}

	/* Set RTP Session ID and version */
	if (!p->sessionid) {
		p->sessionid = getpid();
		p->sessionversion = p->sessionid;
	} else
		p->sessionversion++;

	/* Get our addresses */
	ast_rtp_get_us(p->rtp, &sin);
	if (p->vrtp)
		ast_rtp_get_us(p->vrtp, &vsin);

	/* Is this a re-invite to move the media out, then use the original offer from caller  */
	if (p->redirip.sin_addr.s_addr) {
		dest.sin_port = p->redirip.sin_port;
		dest.sin_addr = p->redirip.sin_addr;
		if (p->redircodecs)
			capability = p->redircodecs;
	} else {
		dest.sin_addr = p->ourip;
		dest.sin_port = sin.sin_port;
	}

	/* Ok, let's start working with codec selection here */
	capability = p->jointcapability;

	if (option_debug > 1) {
		char codecbuf[BUFSIZ];
		ast_log(LOG_DEBUG, "** Our capability: %s Video flag: %s\n", ast_getformatname_multiple(codecbuf, sizeof(codecbuf), capability), ast_test_flag(&p->flags[0], SIP_NOVIDEO) ? "True" : "False");
		ast_log(LOG_DEBUG, "** Our prefcodec: %s \n", ast_getformatname_multiple(codecbuf, sizeof(codecbuf), p->prefcodec));
	}
	
	if ((ast_test_flag(&p->t38.t38support, SIP_PAGE2_T38SUPPORT_RTP))) {
		ast_build_string(&m_audio_next, &m_audio_left, " %d", 191);
		ast_build_string(&a_audio_next, &a_audio_left, "a=rtpmap:%d %s/%d\r\n", 191, "t38", 8000);
	}

	/* Check if we need video in this call */
	if((capability & AST_FORMAT_VIDEO_MASK) && !ast_test_flag(&p->flags[0], SIP_NOVIDEO)) {
		if (p->vrtp) {
			needvideo = TRUE;
			if (option_debug > 1)
				ast_log(LOG_DEBUG, "This call needs video offers! \n");
		} else if (option_debug > 1)
			ast_log(LOG_DEBUG, "This call needs video offers, but there's no video support enabled ! \n");
	}
		

	/* Ok, we need video. Let's add what we need for video and set codecs.
	   Video is handled differently than audio since we can not transcode. */
	if (needvideo) {

		/* Determine video destination */
		if (p->vredirip.sin_addr.s_addr) {
			vdest.sin_addr = p->vredirip.sin_addr;
			vdest.sin_port = p->vredirip.sin_port;
		} else {
			vdest.sin_addr = p->ourip;
			vdest.sin_port = vsin.sin_port;
		}
		ast_build_string(&m_video_next, &m_video_left, "m=video %d RTP/AVP", ntohs(vdest.sin_port));

		/* Build max bitrate string */
		if (p->maxcallbitrate)
			snprintf(bandwidth, sizeof(bandwidth), "b=CT:%d\r\n", p->maxcallbitrate);
		if (debug) 
			ast_verbose("Video is at %s port %d\n", ast_inet_ntoa(p->ourip), ntohs(vsin.sin_port));	

		/* For video, we can't negotiate video offers. Let's compare the incoming call with what we got. */
		if (p->prefcodec) {
			int videocapability = (capability & p->prefcodec) & AST_FORMAT_VIDEO_MASK; /* Outbound call */
		
			/*! \todo XXX We need to select one codec, not many, since there's no transcoding */

			/* Now, merge this video capability into capability while removing unsupported codecs */
			if (!videocapability) {
				needvideo = FALSE;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "** No compatible video codecs... Disabling video.\n");
			} 

			/* Replace video capabilities with the new videocapability */
			capability = (capability & AST_FORMAT_AUDIO_MASK) | videocapability;

			if (option_debug > 4) {
				char codecbuf[BUFSIZ];
				if (videocapability)
					ast_log(LOG_DEBUG, "** Our video codec selection is: %s \n", ast_getformatname_multiple(codecbuf, sizeof(codecbuf), videocapability));
				ast_log(LOG_DEBUG, "** Capability now set to : %s \n", ast_getformatname_multiple(codecbuf, sizeof(codecbuf), capability));
			}
		}
	}
	if (debug) 
		ast_verbose("Audio is at %s port %d\n", ast_inet_ntoa(p->ourip), ntohs(sin.sin_port));	

	/* Start building generic SDP headers */

	/* We break with the "recommendation" and send our IP, in order that our
	   peer doesn't have to ast_gethostbyname() us */

	snprintf(owner, sizeof(owner), "o=root %d %d IN IP4 %s\r\n", p->sessionid, p->sessionversion, ast_inet_ntoa(dest.sin_addr));
	snprintf(connection, sizeof(connection), "c=IN IP4 %s\r\n", ast_inet_ntoa(dest.sin_addr));
	ast_build_string(&m_audio_next, &m_audio_left, "m=audio %d RTP/AVP", ntohs(dest.sin_port));

	if (ast_test_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD_ONEDIR))
		hold = "a=recvonly\r\n";
	else if (ast_test_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD_INACTIVE))
		hold = "a=inactive\r\n";
	else
		hold = "a=sendrecv\r\n";

	/* Now, start adding audio codecs. These are added in this order:
		- First what was requested by the calling channel
		- Then preferences in order from sip.conf device config for this peer/user
		- Then other codecs in capabilities, including video
	*/

	/* Prefer the audio codec we were requested to use, first, no matter what 
		Note that p->prefcodec can include video codecs, so mask them out
	 */
	if (capability & p->prefcodec) {
		add_codec_to_sdp(p, p->prefcodec & AST_FORMAT_AUDIO_MASK, 8000,
				 &m_audio_next, &m_audio_left,
				 &a_audio_next, &a_audio_left,
				 debug);
		alreadysent |= p->prefcodec & AST_FORMAT_AUDIO_MASK;
	}


	/* Start by sending our preferred audio codecs */
	for (x = 0; x < 32; x++) {
		int pref_codec;

		if (!(pref_codec = ast_codec_pref_index(&p->prefs, x)))
			break; 

		if (!(capability & pref_codec))
			continue;

		if (alreadysent & pref_codec)
			continue;

		add_codec_to_sdp(p, pref_codec, 8000,
				 &m_audio_next, &m_audio_left,
				 &a_audio_next, &a_audio_left,
				 debug);
		alreadysent |= pref_codec;
	}

	/* Now send any other common audio and video codecs, and non-codec formats: */
	for (x = 1; x <= (needvideo ? AST_FORMAT_MAX_VIDEO : AST_FORMAT_MAX_AUDIO); x <<= 1) {
		if (!(capability & x))	/* Codec not requested */
			continue;

		if (alreadysent & x)	/* Already added to SDP */
			continue;

		if (x <= AST_FORMAT_MAX_AUDIO)
			add_codec_to_sdp(p, x, 8000,
					 &m_audio_next, &m_audio_left,
					 &a_audio_next, &a_audio_left,
					 debug);
		else 
			add_codec_to_sdp(p, x, 90000,
					 &m_video_next, &m_video_left,
					 &a_video_next, &a_video_left,
					 debug);
	}

	/* Now add DTMF RFC2833 telephony-event as a codec */
	for (x = 1; x <= AST_RTP_MAX; x <<= 1) {
		if (!(p->noncodeccapability & x))
			continue;

		add_noncodec_to_sdp(p, x, 8000,
				    &m_audio_next, &m_audio_left,
				    &a_audio_next, &a_audio_left,
				    debug);
	}

	if (option_debug > 2)
		ast_log(LOG_DEBUG, "-- Done with adding codecs to SDP\n");

	if(!p->owner || !ast_internal_timing_enabled(p->owner))
		ast_build_string(&a_audio_next, &a_audio_left, "a=silenceSupp:off - - - -\r\n");

	if ((m_audio_left < 2) || (m_video_left < 2) || (a_audio_left == 0) || (a_video_left == 0))
		ast_log(LOG_WARNING, "SIP SDP may be truncated due to undersized buffer!!\n");

	ast_build_string(&m_audio_next, &m_audio_left, "\r\n");
	if (needvideo)
		ast_build_string(&m_video_next, &m_video_left, "\r\n");

	len = strlen(version) + strlen(subject) + strlen(owner) + strlen(connection) + strlen(stime) + strlen(m_audio) + strlen(a_audio) + strlen(hold);
	if (needvideo) /* only if video response is appropriate */
		len += strlen(m_video) + strlen(a_video) + strlen(bandwidth) + strlen(hold);

	add_header(resp, "Content-Type", "application/sdp");
	add_header_contentLength(resp, len);
	add_line(resp, version);
	add_line(resp, owner);
	add_line(resp, subject);
	add_line(resp, connection);
	if (needvideo)	 	/* only if video response is appropriate */
		add_line(resp, bandwidth);
	add_line(resp, stime);
	add_line(resp, m_audio);
	add_line(resp, a_audio);
	add_line(resp, hold);
	if (needvideo) { /* only if video response is appropriate */
		add_line(resp, m_video);
		add_line(resp, a_video);
		add_line(resp, hold);	/* Repeat hold for the video stream */
	}

	/* Update lastrtprx when we send our SDP */
	p->lastrtprx = p->lastrtptx = time(NULL); /* XXX why both ? */

	if (option_debug > 2) {
		char buf[BUFSIZ];
		ast_log(LOG_DEBUG, "Done building SDP. Settling with this capability: %s\n", ast_getformatname_multiple(buf, BUFSIZ, capability));
	}

	return 0;
}

/*! \brief Return SIP UA's codec (part of the RTP interface) */
static int sip_get_codec(struct ast_channel *chan)
{
	struct sip_dialog *p = chan->tech_pvt;
	return p->peercapability;	
}

/*! \brief Read RTP from network */
static struct ast_frame *sip_rtp_read(struct ast_channel *ast, struct sip_dialog *p, int *faxdetect)
{
	/* Retrieve audio/etc from channel.  Assumes p->lock is already held. */
	struct ast_frame *f;
	
	if (!p->rtp) {
		/* We have no RTP allocated for this channel */
		return &ast_null_frame;
	}

	switch(ast->fdno) {
	case 0:
		f = ast_rtp_read(p->rtp);	/* RTP Audio */
		break;
	case 1:
		f = ast_rtcp_read(p->rtp);	/* RTCP Control Channel */
		break;
	case 2:
		f = ast_rtp_read(p->vrtp);	/* RTP Video */
		break;
	case 3:
		f = ast_rtcp_read(p->vrtp);	/* RTCP Control Channel for video */
		break;
	case 5:
		f = ast_udptl_read(p->udptl);	/* UDPTL for T.38 */
		break;
	default:
		f = &ast_null_frame;
	}
	/* Don't forward RFC2833 if we're not supposed to */
	if (f && (f->frametype == AST_FRAME_DTMF) &&
	    (ast_test_flag(&p->flags[0], SIP_DTMF) != SIP_DTMF_RFC2833))
		return &ast_null_frame;

	if (p->owner) {
		/* We already hold the channel lock */
		if (f->frametype == AST_FRAME_VOICE) {
			if (f->subclass != (p->owner->nativeformats & AST_FORMAT_AUDIO_MASK)) {
				if (option_debug)
					ast_log(LOG_DEBUG, "Oooh, format changed to %d\n", f->subclass);
				p->owner->nativeformats = (p->owner->nativeformats & AST_FORMAT_VIDEO_MASK) | f->subclass;
				ast_set_read_format(p->owner, p->owner->readformat);
				ast_set_write_format(p->owner, p->owner->writeformat);
			}
			if ((ast_test_flag(&p->flags[0], SIP_DTMF) == SIP_DTMF_INBAND) && p->vad) {
				f = ast_dsp_process(p->owner, p->vad, f);
				if (f && f->frametype == AST_FRAME_DTMF) {
					if (ast_test_flag(&p->t38.t38support, SIP_PAGE2_T38SUPPORT_UDPTL) && f->subclass == 'f') {
						if (option_debug)
							ast_log(LOG_DEBUG, "Fax CNG detected on %s\n", ast->name);
						*faxdetect = 1;
					} else if (option_debug) {
						ast_log(LOG_DEBUG, "* Detected inband DTMF '%c'\n", f->subclass);
					}
				}
			}
		}
	}
	return f;
}

/*! \brief Read SIP RTP from channel */
static struct ast_frame *sip_read(struct ast_channel *ast)
{
	struct ast_frame *fr;
	struct sip_dialog *p = ast->tech_pvt;
	int faxdetected = FALSE;

	ast_mutex_lock(&p->lock);
	fr = sip_rtp_read(ast, p, &faxdetected);
	p->lastrtprx = time(NULL);

	/* If we are NOT bridged to another channel, and we have detected fax tone we issue T38 re-invite to a peer */
	/* If we are bridged then it is the responsibility of the SIP device to issue T38 re-invite if it detects CNG or fax preamble */
	if (faxdetected && ast_test_flag(&p->t38.t38support, SIP_PAGE2_T38SUPPORT_UDPTL) && (p->t38.state == T38_DISABLED) && !(ast_bridged_channel(ast))) {
		if (!ast_test_flag(&p->flags[0], SIP_GOTREFER)) {
			if (!p->pendinginvite) {
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "Sending reinvite on SIP (%s) for T.38 negotiation.\n",ast->name);
				p->t38.state = T38_LOCAL_REINVITE;
				transmit_reinvite_with_t38_sdp(p);
				if (option_debug > 1)
					ast_log(LOG_DEBUG, "T38 state changed to %d on channel %s\n", p->t38.state, ast->name);
			}
		} else if (!ast_test_flag(&p->flags[0], SIP_PENDINGBYE)) {
			if (option_debug > 2)
				ast_log(LOG_DEBUG, "Deferring reinvite on SIP (%s) - it will be re-negotiated for T.38\n", ast->name);
			ast_set_flag(&p->flags[0], SIP_NEEDREINVITE);
		}
	}

	ast_mutex_unlock(&p->lock);
	return fr;
}

/*! \brief Get UDPTL peer address (part of UDPTL interface) */
static struct ast_udptl *sip_get_udptl_peer(struct ast_channel *chan)
{
	struct sip_dialog *p;
	struct ast_udptl *udptl = NULL;
	
	p = chan->tech_pvt;
	if (!p)
		return NULL;
	
	ast_mutex_lock(&p->lock);
	if (p->udptl && ast_test_flag(&p->flags[0], SIP_CAN_REINVITE))
		udptl = p->udptl;
	ast_mutex_unlock(&p->lock);
	return udptl;
}

/*! \brief Determine UDPTL peer address for re-invite (part of UDPTL interface) */
static int sip_set_udptl_peer(struct ast_channel *chan, struct ast_udptl *udptl)
{
	struct sip_dialog *p;
	
	p = chan->tech_pvt;
	if (!p)
		return -1;
	ast_mutex_lock(&p->lock);
	if (udptl)
		ast_udptl_get_peer(udptl, &p->udptlredirip);
	else
		memset(&p->udptlredirip, 0, sizeof(p->udptlredirip));
	if (!ast_test_flag(&p->flags[0], SIP_GOTREFER)) {
		if (!p->pendinginvite) {
			if (option_debug > 2) {
				ast_log(LOG_DEBUG, "Sending reinvite on SIP '%s' - It's UDPTL soon redirected to IP %s:%d\n", p->callid, ast_inet_ntoa(udptl ? p->udptlredirip.sin_addr : p->ourip), udptl ? ntohs(p->udptlredirip.sin_port) : 0);
			}
			transmit_reinvite_with_t38_sdp(p);
		} else if (!ast_test_flag(&p->flags[0], SIP_PENDINGBYE)) {
			if (option_debug > 2) {
				ast_log(LOG_DEBUG, "Deferring reinvite on SIP '%s' - It's UDPTL will be redirected to IP %s:%d\n", p->callid, ast_inet_ntoa(udptl ? p->udptlredirip.sin_addr : p->ourip), udptl ? ntohs(p->udptlredirip.sin_port) : 0);
			}
			ast_set_flag(&p->flags[0], SIP_NEEDREINVITE);
		}
	}
	/* Reset lastrtprx timer */
	p->lastrtprx = p->lastrtptx = time(NULL);
	ast_mutex_unlock(&p->lock);
	return 0;
}
