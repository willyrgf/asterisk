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
 * \brief Various SIP dialog handlers
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

/*! \page chan_sip3_dialogs Chan_sip3: The dialog list
	\par The dialog list
	The dialog list contains all active dialogs in various states.
	A dialog can be 
	- an active call
	- a call in hangup state - waiting for cleanup
	- a subscription
	- an inbound or outbound registration

	We will implement dialog states soon
	\ref enum dialogstate

*/

/*! \brief Protect the SIP dialog list (of sip_dialog's) */
AST_MUTEX_DEFINE_STATIC(dialoglock);

/*! \brief Lock list of active SIP dialogs */
void dialoglist_lock(void)
{
	ast_mutex_lock(&dialoglock);
}

/*! \brief Unlock list of active SIP dialogs */
void dialoglist_unlock(void)
{
	ast_mutex_unlock(&dialoglock);
}


/*! \brief Kill a SIP dialog (called by scheduler) */
static int __sip_autodestruct(void *data)
{
	struct sip_dialog *p = data;

	/* If this is a subscription, tell the phone that we got a timeout */
	if (p->subscribed) {
		p->subscribed = TIMEOUT;
		transmit_state_notify(p, AST_EXTENSION_DEACTIVATED, 1);	/* Send last notification */
		p->subscribed = NONE;
		append_history(p, "Subscribestatus", "timeout");
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "Re-scheduled destruction of SIP subsription %s\n", p->callid ? p->callid : "<unknown>");
		return 10000;	/* Reschedule this destruction so that we know that it's gone */
	}

	/* Reset schedule ID */
	p->autokillid = -1;

	if (option_debug)
		ast_log(LOG_DEBUG, "Auto destroying SIP dialog '%s'\n", p->callid);
	append_history(p, "AutoDestroy", "%s", p->callid);
	if (p->owner) {
		ast_log(LOG_WARNING, "Autodestruct on dialog '%s' with owner in place (Method: %s)\n", p->callid, sip_method2txt(p->method));
		ast_queue_hangup(p->owner);
	} else if (p->refer)
		transmit_request_with_auth(p, SIP_BYE, 0, XMIT_RELIABLE, 1);
	else 
		sip_destroy(p);
	return 0;
}

/*! \brief Schedule destruction of SIP dialog */
GNURK void sip_scheddestroy(struct sip_dialog *p, int ms)
{
	if (ms < 0) {
		if (p->timer_t1 == 0)
			p->timer_t1 = 500;	/* Set timer T1 if not set (RFC 3261) */
		ms = p->timer_t1 * 64;
	}
	if (sip_debug_test_pvt(p))
		ast_verbose("Scheduling destruction of SIP dialog '%s' in %d ms (Method: %s)\n", p->callid, ms, sip_method2txt(p->method));
	if (!ast_test_flag(&p->flags[0], SIP_NO_HISTORY))
		append_history(p, "SchedDestroy", "%d ms", ms);

	if (p->autokillid > -1)
		ast_sched_del(sched, p->autokillid);
	p->autokillid = ast_sched_add(sched, ms, __sip_autodestruct, p);
}

/*! \brief Cancel destruction of SIP dialog */
GNURK void sip_cancel_destroy(struct sip_dialog *p)
{
	if (p->autokillid > -1) {
		ast_sched_del(sched, p->autokillid);
		append_history(p, "CancelDestroy", "");
		p->autokillid = -1;
	}
}

