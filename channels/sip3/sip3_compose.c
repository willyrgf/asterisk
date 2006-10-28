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
 * \brief Various SIP functions for composing SIP packets
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
#include "asterisk/acl.h"
#include "asterisk/callerid.h"
#include "asterisk/cli.h"
#include "asterisk/app.h"
#include "asterisk/manager.h"
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
#include "asterisk/linkedlists.h"
#include "asterisk/stringfields.h"
#include "asterisk/monitor.h"
#include "asterisk/localtime.h"
#include "asterisk/compiler.h"
#include "sip3.h"
#include "sip3funcs.h"

/*! \brief Build SIP Call-ID value for a non-REGISTER transaction */
void build_callid_pvt(struct sip_dialog *pvt)
{
	char buf[33];

	const char *host = S_OR(pvt->fromdomain, ast_inet_ntoa(pvt->ourip));
	
	ast_string_field_build(pvt, callid, "%s@%s", generate_random_string(buf, sizeof(buf)), host);

}

/*! \brief Append date to SIP message */
void append_date(struct sip_request *req)
{
	char tmpdat[256];
	struct tm tm;
	time_t t = time(NULL);

	gmtime_r(&t, &tm);
	strftime(tmpdat, sizeof(tmpdat), "%a, %d %b %Y %T GMT", &tm);
	add_header(req, "Date", tmpdat);
}

/*! \brief Add text body to SIP message */
int add_text(struct sip_request *req, const char *text)
{
	/* XXX Convert \n's to \r\n's XXX */
	add_header(req, "Content-Type", "text/plain");
	add_header_contentLength(req, strlen(text));
	add_line(req, text);
	return 0;
}

/*! \brief Add DTMF INFO tone to sip message */
/* Always adds default duration 250 ms, regardless of what came in over the line */
int add_digit(struct sip_request *req, char digit)
{
	char tmp[256];

	snprintf(tmp, sizeof(tmp), "Signal=%c\r\nDuration=250\r\n", digit);
	add_header(req, "Content-Type", "application/dtmf-relay");
	add_header_contentLength(req, strlen(tmp));
	add_line(req, tmp);
	return 0;
}

