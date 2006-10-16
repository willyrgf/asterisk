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

/*! \brief Get a specific line from the message body */
static char *get_body(struct sip_request *req, char *name) 
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
static int process_sdp(struct sip_pvt *p, struct sip_request *req)
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
static int sip_set_rtp_peer(struct ast_channel *chan, struct ast_rtp *rtp, struct ast_rtp *vrtp, int codecs, int nat_active)
{
	struct sip_pvt *p;
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
			if (global.recordhistory)
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
static enum ast_rtp_get_result sip_get_rtp_peer(struct ast_channel *chan, struct ast_rtp **rtp)
{
	struct sip_pvt *p = NULL;
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

	ast_mutex_unlock(&p->lock);

	return res;
}

/*! \brief Returns null if we can't reinvite video (part of RTP interface) */
static enum ast_rtp_get_result sip_get_vrtp_peer(struct ast_channel *chan, struct ast_rtp **rtp)
{
	struct sip_pvt *p = NULL;
	enum ast_rtp_get_result res = AST_RTP_TRY_PARTIAL;
	
	if (!(p = chan->tech_pvt))
		return AST_RTP_GET_FAILED;

	ast_mutex_lock(&p->lock);
	if (!(p->vrtp)) {
		ast_mutex_unlock(&p->lock);
		return AST_RTP_GET_FAILED;
	}

	*rtp = p->vrtp;

	if (ast_test_flag(&p->flags[0], SIP_CAN_REINVITE))
		res = AST_RTP_TRY_NATIVE;

	ast_mutex_unlock(&p->lock);

	return res;
}

