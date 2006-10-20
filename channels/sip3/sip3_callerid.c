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
 * \brief Various SIP callerid functions
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
#include "asterisk/callerid.h"
#include "asterisk/app.h"
#include "asterisk/astdb.h"
#include "asterisk/causes.h"
#include "asterisk/utils.h"
#include "asterisk/file.h"
#include "asterisk/astobj.h"
#include "asterisk/dnsmgr.h"
#include "asterisk/linkedlists.h"
#include "asterisk/monitor.h"
#include "asterisk/localtime.h"
#include "asterisk/compiler.h"
#include "sip3.h"
#include "sip3funcs.h"


/*! \brief  Get caller id number from Remote-Party-ID header field 
 *	Returns true if number should be restricted (privacy setting found)
 *	output is set to NULL if no number found
 */
int get_rpid_num(const char *input, char *output, int maxlen)
{
	char *start;
	char *end;

	start = strchr(input,':');
	if (!start) {
		output[0] = '\0';
		return 0;
	}
	start++;

	/* we found "number" */
	ast_copy_string(output,start,maxlen);
	output[maxlen-1] = '\0';

	end = strchr(output,'@');
	if (end)
		*end = '\0';
	else
		output[0] = '\0';
	if (strstr(input,"privacy=full") || strstr(input,"privacy=uri"))
		return AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED;

	return 0;
}

/*! \brief  Get caller id name from SIP headers */
char *get_calleridname(const char *input, char *output, size_t outputsize)
{
	const char *end = strchr(input,'<');	/* first_bracket */
	const char *tmp = strchr(input,'"');	/* first quote */
	int bytes = 0;
	int maxbytes = outputsize - 1;

	if (!end || end == input)	/* we require a part in brackets */
		return NULL;

	/* move away from "<" */
	end--;

	/* we found "name" */
	if (tmp && tmp < end) {
		end = strchr(tmp+1, '"');
		if (!end)
			return NULL;
		bytes = (int) (end - tmp);
		/* protect the output buffer */
		if (bytes > maxbytes)
			bytes = maxbytes;
		ast_copy_string(output, tmp + 1, bytes);
	} else {
		/* we didn't find "name" */
		/* clear the empty characters in the begining*/
		input = ast_skip_blanks(input);
		/* clear the empty characters in the end */
		while(*end && *end < 33 && end > input)
			end--;
		if (end >= input) {
			bytes = (int) (end - input) + 2;
			/* protect the output buffer */
			if (bytes > maxbytes)
				bytes = maxbytes;
			ast_copy_string(output, input, bytes);
		} else
			return NULL;
	}
	return output;
}
