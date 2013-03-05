/*
* Asterisk -- An open source telephony toolkit.
*
* Copyright (C) 2013 Olle E. Johansson, Edvina AB
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

/*! \file rtcp.c
*
* \brief RTCP additional functions
*
* \author Olle E. Johansson <oej@edvina.net>
*/

/*** MODULEINFO
	<support_level>core</support_level>
***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/utils.h"
#include "include/rtcp.h"


/*! \brief send manager report of RTCP 
	reporttype = 0  means report during call (if configured)
	reporttype = 1  means endof-call (hangup) report
	reporttype = 10  means report at end of call leg (like transfer)
*/
static void sip_rtcp_report(struct sip_pvt *p, struct ast_rtp *rtp, enum media_type type, int reporttype)
{
	struct ast_rtp_quality *qual;
	char *rtpqstring = NULL;
	int qosrealtime = ast_check_realtime("rtpqos");
	unsigned int duration;	/* Duration in secs */
 	int readtrans = FALSE, writetrans = FALSE;

	memset(&qual, sizeof(qual), 0);
  
	if (p && p->owner) {
		struct ast_channel *bridgepeer = ast_bridged_channel(p->owner);
		if (bridgepeer) {
			/* Store the bridged peer data while we have it */
			ast_rtcp_set_bridged(rtp, p->owner->name, p->owner->uniqueid, S_OR(bridgepeer->name,""), S_OR(bridgepeer->uniqueid,""));
			ast_log(LOG_DEBUG, "---- Setting bridged peer name to %s\n", bridgepeer->name);
		} else {
			ast_rtcp_set_bridged(rtp, p->owner->name, p->owner->uniqueid, NULL, NULL);
		}

 		/* Try to find out if there's active transcoding */
		/* Currently, the only media stream that has translation is the audio stream. At some point
		   we might have transcoding for other types of media. */
		if (type == SDP_AUDIO) {
			/* if we have a translator, the bridge delay is increased, which affects the QoS of the call.  */
 			readtrans = p->owner->readtrans != NULL;
 			writetrans = p->owner->writetrans != NULL;
			ast_rtcp_settranslator(rtp, readtrans ? p->owner->readtrans->t->name : NULL, readtrans ? p->owner->readtrans->t->cost : 0,
					writetrans ? p->owner->writetrans->t->name : NULL, writetrans ? p->owner->writetrans->t->cost : 0);
		
			if (option_debug > 1) {
 				if (readtrans && p->owner->readtrans->t) {
 					ast_log(LOG_DEBUG, "--- Audio Read translator: %s Cost %d\n", p->owner->readtrans->t->name, p->owner->readtrans->t->cost);
 				}
 				if (writetrans && p->owner->writetrans->t) {
 					ast_log(LOG_DEBUG, "--- Audio Write translator: %s Cost %d\n", p->owner->writetrans->t->name, p->owner->writetrans->t->cost);
 				}
			}
		}

	}

	rtpqstring =  ast_rtp_get_quality(rtp);
	qual = ast_rtp_get_qualdata(rtp);
	if (!qual) {
		/* Houston, we got a problem */
		return;
	}
	
	if (global_rtcpevents) {
		/* 
		   If numberofreports == 0 we have no incoming RTCP active, thus we can't
		   get any reliable data to handle packet loss or any RTT timing.
		*/

		duration = (unsigned int)(ast_tvdiff_ms(ast_tvnow(), qual->start) / 1000);
		manager_event(EVENT_FLAG_CALL, "RTPQuality", 
			"Channel: %s\r\n"			/* AST_CHANNEL for this call */
			"Uniqueid: %s\r\n"			/* AST_CHANNEL for this call */
			"BridgedChannel: %s\r\n"
			"BridgedUniqueid: %s\r\n"
			"RTPreporttype: %s\r\n"
			"RTPrtcpstatus: %s\r\n"
			"Duration: %u\r\n"		/* used in cdr_manager */
			"PvtCallid: %s\r\n"		/* ??? Generic PVT identifier */
			"RTPipaddress: %s\r\n"
			"RTPmedia: %s\r\n"		/* Audio, video, text */
			"RTPsendformat: %s\r\n"
			"RTPrecvformat: %s\r\n"
			"RTPlocalssrc: %u\r\n"
			"RTPremotessrc: %u\r\n"
			"RTPrtt: %f\r\n"
			"RTPrttMax: %f\r\n"
			"RTPrttMin: %f\r\n"
			"RTPLocalJitter: %f\r\n"
			"RTPRemoteJitter: %f\r\n" 
			"RTPInPacketLoss: %d\r\n" 
			"RTPInLocalPlPercent: %5.2f\r\n"
			"RTPOutPacketLoss: %d\r\n"
			"RTPOutPlPercent: %5.2f\r\n"
			"TranslateRead: %s\r\n"
			"TranslateReadCost: %d\r\n"
			"TranslateWrite: %s\r\n"
			"TranslateWriteCost: %d\r\n"
			"\r\n", 
			p->owner ? p->owner->name : "",
			p->owner ? p->owner->uniqueid : "",
			qual->bridgedchan[0] ? qual->bridgedchan : "" ,
			qual->bridgeduniqueid[0] ? qual->bridgeduniqueid : "",
			reporttype == 1 ? "Final" : "Update",
			qual->numberofreports == 0 ? "Inactive" : "Active",
			duration,
			p->callid, 
			ast_inet_ntoa(qual->them.sin_addr), 	
			type == SDP_AUDIO ? "audio" : (type == SDP_VIDEO ? "video" : "fax") ,
			ast_getformatname(qual->lasttxformat),
			ast_getformatname(qual->lastrxformat),
			qual->local_ssrc, 
			qual->remote_ssrc,
			qual->rtt,
			qual->rttmax,
			qual->rttmin,
			qual->local_jitter,
			qual->remote_jitter,
			qual->local_lostpackets,
			/* The local counter of lost packets in inbound stream divided with received packets plus lost packets */
			(qual->remote_count + qual->local_lostpackets) > 0 ? (double) qual->local_lostpackets / (qual->remote_count + qual->local_lostpackets) * 100 : 0,
			qual->remote_lostpackets,
			/* The remote counter of lost packets (if we got the reports)
			   divided with our counter of sent packets
			 */
			(qual->local_count + qual->remote_lostpackets) > 0 ? (double) qual->remote_lostpackets / qual->local_count  * 100 : 0,
			qual->readtranslator, qual->readcost,
			qual->writetranslator, qual->writecost
		);
	}

	/* CDR records are not reliable when it comes to near-death-of-channel events, so we need to store the RTCP
	   report in realtime when we have it.
	   Tests have proven that storing to realtime from the call thread is NOT a good thing. Therefore, we just save
	   the quality report structure in the PVT and let the function that kills the pvt store the stuff in the
	   monitor thread instead.
	 */
	if (reporttype == 1 {
		if (type == SDP_AUDIO) {  /* Audio */
			p->audioqual = ast_calloc(sizeof(struct ast_rtp_quality), 1);
			(* p->audioqual) = *qual;
			p->audioqual->end = ast_tvnow();
 			p->audioqual->mediatype = type;
		} else if (type == SDP_VIDEO) {  /* Video */
			p->videoqual = ast_calloc(sizeof(struct ast_rtp_quality), 1);
			(* p->videoqual) = *qual;
 			p->videoqual->mediatype = type;
			p->videoqual->end = ast_tvnow();
		}
	}
}

/*! \brief Write quality report to realtime storage */
void qos_write_realtime(struct sip_pvt *dialog, struct ast_rtp_quality *qual)
{
	unsigned int duration;	/* Duration in secs */
	char buf_duration[10], buf_lssrc[30], buf_rssrc[30];
	char buf_rtt[10], buf_rttmin[10], buf_rttmax[10];
	char localjitter[10], remotejitter[10];
	char buf_readcost[5], buf_writecost[5];
	char buf_mediatype[10];
	char buf_remoteip[25];
	char buf_inpacketloss[25], buf_outpacketloss[25];
	char buf_outpackets[25], buf_inpackets[25];

	/* Since the CDR is already gone, we need to calculate our own duration.
	   The CDR duration is the definitive resource for billing, this is
	   the RTP stream duration which may include early media (ringing and
	   provider messages). Only useful for measurements.
	 */
	if (!ast_tvzero(qual->end)) {
		duration = (unsigned int)(ast_tvdiff_ms(qual->end, qual->start) / 1000);
	} else {
		duration = 0;
	}

	/* Realtime is based on strings, so let's make strings */
	sprintf(localjitter, "%f", qual->local_jitter);
	sprintf(remotejitter, "%f", qual->remote_jitter);
	sprintf(buf_lssrc, "%u", qual->local_ssrc);
	sprintf(buf_rssrc, "%u", qual->remote_ssrc);
	sprintf(buf_rtt, "%.0f", qual->rtt);
	sprintf(buf_rttmax, "%.0f", qual->rttmax);
	sprintf(buf_rttmin, "%.0f", qual->rttmin);
	sprintf(buf_duration, "%u", duration);
	sprintf(buf_readcost, "%d", qual->readcost);
	sprintf(buf_writecost, "%d", qual->writecost);
	sprintf(buf_mediatype,"%s", qual->mediatype == SDP_AUDIO ? "audio" : (qual->mediatype == SDP_VIDEO ? "video" : "fax") );
	sprintf(buf_remoteip,"%s", ast_inet_ntoa(qual->them.sin_addr));
	sprintf(buf_inpacketloss, "%d", qual->local_lostpackets);
	sprintf(buf_outpacketloss, "%d", qual->remote_lostpackets);
	sprintf(buf_inpackets, "%d", qual->remote_count);	/* Do check again */
	sprintf(buf_outpackets, "%d", qual->local_count);

	ast_log(LOG_NOTICE,"RTPQOS Channel: %s Uid %s Bch %s Buid %s Pvt %s Media %s Lssrc %s Rssrc %s Rip %s Rtt %s:%s:%s Ljitter %s Rjitter %s Rtcpstatus %s Dur %s Pout %s Plossout %s Pin %s Plossin %s\n",
		qual->channel[0] ? qual->channel : "",
		qual->uniqueid[0] ? qual->uniqueid : "",
		qual->bridgedchan[0] ? qual->bridgedchan : "" ,
		qual->bridgeduniqueid[0] ? qual->bridgeduniqueid : "",
		dialog->callid,
		buf_mediatype,
		buf_lssrc,
		buf_rssrc,
		buf_remoteip,
		buf_rtt, buf_rttmax, buf_rttmin,
		localjitter,
		remotejitter,
		qual->numberofreports == 0 ? "Inactive" : "Active",
		buf_duration,
		buf_outpackets,
		buf_outpacketloss,
		buf_inpackets,
		buf_inpacketloss);

#ifdef REALTIME2
	ast_store_realtime("rtpqos", 
		"channel", qual->channel[0] ? qual->channel : "--no channel--",
		"uniqueid", qual->uniqueid[0] ? qual->uniqueid : "--no uniqueid --",
		"bridgedchan", qual->bridgedchan[0] ? qual->bridgedchan : "" ,
		"bridgeduniqueid", qual->bridgeduniqueid[0] ? qual->bridgeduniqueid : "",
		"pvtcallid", dialog->callid, 
		"rtpmedia", buf_mediatype, 
		"localssrc", buf_lssrc, 
		"remotessrc", buf_rssrc,
		"remoteip", buf_remoteip,
		"rtt", buf_rtt, 
		"rttmax", buf_rttmax, 
		"rttmin", buf_rttmin, 
		"localjitter", localjitter, 
		"remotejitter", remotejitter, 
		"sendformat", ast_getformatname(qual->lasttxformat),
		"receiveformat", ast_getformatname(qual->lastrxformat),
		"rtcpstatus", qual->numberofreports == 0 ? "Inactive" : "Active",
		"duration", buf_duration,
		"writetranslator", qual->writetranslator[0] ? qual->writetranslator : "",
		"writecost", buf_writecost,
		"readtranslator", qual->readtranslator[0] ? qual->readtranslator : "",
		"readcost", buf_readcost,
		"packetlossin", buf_inpacketloss,
		"packetlossout", buf_outpacketloss,
		"packetsent", buf_outpackets,
		"packetreceived", buf_inpackets,
		NULL);
#endif
}

/*! \brief Send RTCP manager events */
static int send_rtcp_events(const void *data)
{
	struct sip_pvt *dialog = (struct sip_pvt *) data;

	if (dialog->rtp && ast_rtp_isactive(dialog->rtp)) {
		sip_rtcp_report(dialog, dialog->rtp, SDP_AUDIO, FALSE);
	}
	if (dialog->vrtp && ast_rtp_isactive(dialog->vrtp)) {
		sip_rtcp_report(dialog, dialog->vrtp, SDP_VIDEO, FALSE);
	}
	return global_rtcptimer;
}

/*! \brief Activate RTCP events at start of call */
static void start_rtcp_events(struct sip_pvt *dialog)
{
	if (!global_rtcpevents || !global_rtcptimer) {
		return;
	}
	/* Check if it's already active */
	if (dialog->rtcpeventid != -1) {
		return;
	}

	/*! \brief Schedule events */
	dialog->rtcpeventid = ast_sched_add(sched, global_rtcptimer * 1000, send_rtcp_events, dialog);
}
