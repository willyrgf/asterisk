/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2006  Edvina AB, Sollentuna, Sweden (chan_sip3 changes/additions)
 * and Edvina AB, Sollentuna, Sweden (chan_sip3 changes/additions)
 *
 * Olle E. Johansson
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
 * \brief Various SIP utility functions
 *
 * Version 3 of chan_sip
 *
 * \author Olle E. Johansson <oej@edvina.net> 
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
#include "asterisk/manager.h"
#include "asterisk/acl.h"
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


GNURK void logdebug(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

/*! \brief Output message to LOG_DEBUG channel */
static void logdebug_va(int level, const char *fmt, va_list ap)
{
	if (option_debug >= level)
		ast_log(LOG_DEBUG, fmt, ap);
}

/*! \brief Append to SIP dialog history with arg list  */
GNURK void logdebug(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logdebug_va(level, fmt, ap);
	va_end(ap);

	return;
}

