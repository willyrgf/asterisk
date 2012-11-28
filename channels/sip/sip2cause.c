/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2012, Digium, inc and Edvina AB
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
 * \brief SIP-to-ISDN cause code conversions
 *
 * \author Olle E. Johansson <oej@edvina.net>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"
#include "asterisk/causes.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "include/sip.h"
#include "include/config_parser.h"
#include "include/sip_utils.h"

/*! \brief Convert SIP hangup causes to Asterisk hangup causes */
int hangup_sip2cause(int cause)
{
	/* Possible values taken from causes.h */

	switch(cause) {
		case 401:	/* Unauthorized */
			return AST_CAUSE_CALL_REJECTED;
		case 403:	/* Not found */
			return AST_CAUSE_CALL_REJECTED;
		case 404:	/* Not found */
			return AST_CAUSE_UNALLOCATED;
		case 405:	/* Method not allowed */
			return AST_CAUSE_INTERWORKING;
		case 407:	/* Proxy authentication required */
			return AST_CAUSE_CALL_REJECTED;
		case 408:	/* No reaction */
			return AST_CAUSE_NO_USER_RESPONSE;
		case 409:	/* Conflict */
			return AST_CAUSE_NORMAL_TEMPORARY_FAILURE;
		case 410:	/* Gone */
			return AST_CAUSE_NUMBER_CHANGED;
		case 411:	/* Length required */
			return AST_CAUSE_INTERWORKING;
		case 413:	/* Request entity too large */
			return AST_CAUSE_INTERWORKING;
		case 414:	/* Request URI too large */
			return AST_CAUSE_INTERWORKING;
		case 415:	/* Unsupported media type */
			return AST_CAUSE_INTERWORKING;
		case 420:	/* Bad extension */
			return AST_CAUSE_NO_ROUTE_DESTINATION;
		case 480:	/* No answer */
			return AST_CAUSE_NO_ANSWER;
		case 481:	/* No answer */
			return AST_CAUSE_INTERWORKING;
		case 482:	/* Loop detected */
			return AST_CAUSE_INTERWORKING;
		case 483:	/* Too many hops */
			return AST_CAUSE_NO_ANSWER;
		case 484:	/* Address incomplete */
			return AST_CAUSE_INVALID_NUMBER_FORMAT;
		case 485:	/* Ambiguous */
			return AST_CAUSE_UNALLOCATED;
		case 486:	/* Busy everywhere */
			return AST_CAUSE_BUSY;
		case 487:	/* Request terminated */
			return AST_CAUSE_INTERWORKING;
		case 488:	/* No codecs approved */
			return AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
		case 491:	/* Request pending */
			return AST_CAUSE_INTERWORKING;
		case 493:	/* Undecipherable */
			return AST_CAUSE_INTERWORKING;
		case 500:	/* Server internal failure */
			return AST_CAUSE_FAILURE;
		case 501:	/* Call rejected */
			return AST_CAUSE_FACILITY_REJECTED;
		case 502:
			return AST_CAUSE_DESTINATION_OUT_OF_ORDER;
		case 503:	/* Service unavailable */
			return AST_CAUSE_CONGESTION;
		case 504:	/* Gateway timeout */
			return AST_CAUSE_RECOVERY_ON_TIMER_EXPIRE;
		case 505:	/* SIP version not supported */
			return AST_CAUSE_INTERWORKING;
		case 600:	/* Busy everywhere */
			return AST_CAUSE_USER_BUSY;
		case 603:	/* Decline */
			return AST_CAUSE_CALL_REJECTED;
		case 604:	/* Does not exist anywhere */
			return AST_CAUSE_UNALLOCATED;
		case 606:	/* Not acceptable */
			return AST_CAUSE_BEARERCAPABILITY_NOTAVAIL;
		default:
			if (cause < 500 && cause >= 400) {
				/* 4xx class error that is unknown - someting wrong with our request */
				return AST_CAUSE_INTERWORKING;
			} else if (cause < 600 && cause >= 500) {
				/* 5xx class error - problem in the remote end */
				return AST_CAUSE_CONGESTION;
			} else if (cause < 700 && cause >= 600) {
				/* 6xx - global errors in the 4xx class */
				return AST_CAUSE_INTERWORKING;
			}
			return AST_CAUSE_NORMAL;
	}
	/* Never reached */
	return 0;
}

/*! \brief Convert Asterisk hangup causes to SIP codes
\verbatim
 Possible values from causes.h
        AST_CAUSE_NOTDEFINED    AST_CAUSE_NORMAL        AST_CAUSE_BUSY
        AST_CAUSE_FAILURE       AST_CAUSE_CONGESTION    AST_CAUSE_UNALLOCATED

	In addition to these, a lot of PRI codes is defined in causes.h
	...should we take care of them too ?

	Quote RFC 3398

   ISUP Cause value                        SIP response
   ----------------                        ------------
   1  unallocated number                   404 Not Found
   2  no route to network                  404 Not found
   3  no route to destination              404 Not found
   16 normal call clearing                 --- (*)
   17 user busy                            486 Busy here
   18 no user responding                   408 Request Timeout
   19 no answer from the user              480 Temporarily unavailable
   20 subscriber absent                    480 Temporarily unavailable
   21 call rejected                        403 Forbidden (+)
   22 number changed (w/o diagnostic)      410 Gone
   22 number changed (w/ diagnostic)       301 Moved Permanently
   23 redirection to new destination       410 Gone
   26 non-selected user clearing           404 Not Found (=)
   27 destination out of order             502 Bad Gateway
   28 address incomplete                   484 Address incomplete
   29 facility rejected                    501 Not implemented
   31 normal unspecified                   480 Temporarily unavailable
\endverbatim
*/
const char *hangup_cause2sip(int cause)
{
	switch (cause) {
		case AST_CAUSE_UNALLOCATED:		/* 1 */
		case AST_CAUSE_NO_ROUTE_DESTINATION:	/* 3 IAX2: Can't find extension in context */
		case AST_CAUSE_NO_ROUTE_TRANSIT_NET:	/* 2 */
			return "404 Not Found";
		case AST_CAUSE_CONGESTION:		/* 34 */
		case AST_CAUSE_SWITCH_CONGESTION:	/* 42 */
			return "503 Service Unavailable";
		case AST_CAUSE_NO_USER_RESPONSE:	/* 18 */
			return "408 Request Timeout";
		case AST_CAUSE_NO_ANSWER:		/* 19 */
		case AST_CAUSE_UNREGISTERED:        /* 20 */
			return "480 Temporarily unavailable";
		case AST_CAUSE_CALL_REJECTED:		/* 21 */
			return "403 Forbidden";
		case AST_CAUSE_NUMBER_CHANGED:		/* 22 */
			return "410 Gone";
		case AST_CAUSE_NORMAL_UNSPECIFIED:	/* 31 */
			return "480 Temporarily unavailable";
		case AST_CAUSE_INVALID_NUMBER_FORMAT:
			return "484 Address incomplete";
		case AST_CAUSE_USER_BUSY:
			return "486 Busy here";
		case AST_CAUSE_FAILURE:
			return "500 Server internal failure";
		case AST_CAUSE_FACILITY_REJECTED:	/* 29 */
			return "501 Not Implemented";
		case AST_CAUSE_CHAN_NOT_IMPLEMENTED:
			return "503 Service Unavailable";
		/* Used in chan_iax2 */
		case AST_CAUSE_DESTINATION_OUT_OF_ORDER:
			return "502 Bad Gateway";
		case AST_CAUSE_BEARERCAPABILITY_NOTAVAIL:	/* Can't find codec to connect to host */
			return "488 Not Acceptable Here";
			
		case AST_CAUSE_NOTDEFINED:
		default:
			ast_debug(1, "AST hangup cause %d (no match found in SIP)\n", cause);
			return NULL;
	}

	/* Never reached */
	return 0;
}
