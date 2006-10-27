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
 * \brief Various SIP domains function
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

static AST_LIST_HEAD_STATIC(domain_list, domain);	/*!< The SIP domain list */

/*! \brief Add SIP domain to list of domains we are responsible for */
int add_sip_domain(const char *domain, const enum domain_mode mode, const char *context)
{
	struct domain *d;

	if (ast_strlen_zero(domain)) {
		ast_log(LOG_WARNING, "Zero length domain.\n");
		return 1;
	}

	if (!(d = ast_calloc(1, sizeof(*d))))
		return 0;

	ast_copy_string(d->domain, domain, sizeof(d->domain));

	if (!ast_strlen_zero(context))
		ast_copy_string(d->context, context, sizeof(d->context));

	d->mode = mode;

	AST_LIST_LOCK(&domain_list);
	AST_LIST_INSERT_TAIL(&domain_list, d, list);
	AST_LIST_UNLOCK(&domain_list);

 	if (option_debug > 2)	
		ast_log(LOG_DEBUG, "Added local SIP domain '%s'\n", domain);

	return 1;
}

/*! \brief return TRUE if any domains are configured for this server */
int domains_configured(void)
{
	return (!AST_LIST_EMPTY(&domain_list));
}


/*! \brief  check_sip_domain: Check if domain part of uri is local to our server */
int check_sip_domain(const char *domain, char *context, size_t len)
{
	struct domain *d;
	int result = 0;

	AST_LIST_LOCK(&domain_list);
	AST_LIST_TRAVERSE(&domain_list, d, list) {
		if (strcasecmp(d->domain, domain))
			continue;

		if (len && !ast_strlen_zero(d->context))
			ast_copy_string(context, d->context, len);
		
		result = 1;
		break;
	}
	AST_LIST_UNLOCK(&domain_list);

	return result;
}

/*! \brief Clear our domain list (at reload) */
void clear_sip_domains(void)
{
	struct domain *d;

	AST_LIST_LOCK(&domain_list);
	while ((d = AST_LIST_REMOVE_HEAD(&domain_list, list)))
		free(d);
	AST_LIST_UNLOCK(&domain_list);
}


/*! \brief  Dial plan function to check if domain is local */
int func_check_sipdomain(struct ast_channel *chan, char *cmd, char *data, char *buf, size_t len)
{
	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "CHECKSIPDOMAIN requires an argument - A domain name\n");
		return -1;
	}
	if (check_sip_domain(data, NULL, 0))
		ast_copy_string(buf, data, len);
	else
		buf[0] = '\0';
	return 0;
}

struct ast_custom_function checksipdomain_function = {
	.name = "CHECKSIPDOMAIN",
	.synopsis = "Checks if domain is a local domain",
	.syntax = "CHECKSIPDOMAIN(<domain|IP>)",
	.read = func_check_sipdomain,
	.desc = "This function checks if the domain in the argument is configured\n"
		"as a local SIP domain that this Asterisk server is configured to handle.\n"
		"Returns the domain name if it is locally handled, otherwise an empty string.\n"
		"Check the domain= configuration in sip.conf\n",
};

/*! \brief Print domain mode to cli */
const char *domain_mode_to_text(const enum domain_mode mode)
{
	switch (mode) {
	case SIP_DOMAIN_AUTO:
		return "[Automatic]";
	case SIP_DOMAIN_CONFIG:
		return "[Configured]";
	}

	return "";
}

/*! \brief CLI command to list local domains */
int sip_show_domains(int fd, int argc, char *argv[])
{
	struct domain *d;
#define FORMAT "%-40.40s %-20.20s %-16.16s\n"

	if (domains_configured()) {
		ast_cli(fd, "SIP Domain support not enabled.\n\n");
		return RESULT_SUCCESS;
	} else {
		ast_cli(fd, FORMAT, "Our local SIP domains:", "Context", "Set by");
		AST_LIST_LOCK(&domain_list);
		AST_LIST_TRAVERSE(&domain_list, d, list)
			ast_cli(fd, FORMAT, d->domain, S_OR(d->context, "(default)"),
				domain_mode_to_text(d->mode));
		AST_LIST_UNLOCK(&domain_list);
		ast_cli(fd, "\n");
		return RESULT_SUCCESS;
	}
}
#undef FORMAT
