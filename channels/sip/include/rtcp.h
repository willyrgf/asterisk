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

/*! \file rtcp.h
 *
 * \brief RTCP additional functions
 *
 * \author Olle E. Johansson <oej@edvina.net>
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/utils.h"

#ifndef _SIP_RTCP_H
#define _SIP_RTCP_H

static int send_rtcp_events(const void *data);
static void start_rtcp_events(struct sip_pvt *dialog);
static void sip_rtcp_report(struct sip_pvt *p, struct ast_rtp *rtp, enum media_type type, int reporttype);
static void qos_write_realtime(struct sip_pvt *dialog, struct ast_rtp_quality *qual);



#endif /* _SIP_RTCP_H */
