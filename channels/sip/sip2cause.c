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
#include "include/sip2cause.h"

/*! \brief structure for conversion between ISDN and SIP codes */
struct sip2causestruct {
	int	sip;			/*!< SIP code (200-699) - no provisional codes */
	int	cause;			/*!< ISDN cause code */
	char	*reason;		/*!< SIP reason text, like "Busy", "Inte min domän" or "Que?" */
	struct sip2causestruct *next;	/*!< Pointer to next entry */
};

/*! \brief Main structure for tables, including default values */
struct sip2causetable {
	struct sip2causestruct *table;
	int	defaultcode;
	char	*defaultreason;
};

/*! \brief Actual table for sip => ISDN lookups */
struct sip2causetable sip2causelookup;

/*! \brief Actual table for ISDN => sip lookups */
struct sip2causetable cause2siplookup;

static struct sip2causestruct *newsip2cause(int sip, int cause, char *reason, struct sip2causestruct *next)
{
	struct sip2causestruct *s2c = ast_calloc(1, sizeof(struct sip2causestruct));

	if (!s2c) {
		return NULL;
	}
	s2c->sip = sip;
	s2c->cause = cause;
	s2c->reason = reason;
	s2c->next = next;
	return(s2c);
 }

/*! \brief Initialize structure with default values */
void sip2cause_init(void)
{
	/* Initialize table for SIP => ISDN codes */
	sip2causelookup.table = newsip2cause(401, /* Unauthorized */ AST_CAUSE_CALL_REJECTED, "", NULL);
	sip2causelookup.table = newsip2cause(403, /* Not found */ AST_CAUSE_CALL_REJECTED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(404, /* Not found */ AST_CAUSE_UNALLOCATED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(405, /* Method not allowed */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(407, /* Proxy authentication required */ AST_CAUSE_CALL_REJECTED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(408, /* No reaction */ AST_CAUSE_NO_USER_RESPONSE, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(409, /* Conflict */ AST_CAUSE_NORMAL_TEMPORARY_FAILURE, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(410, /* Gone */ AST_CAUSE_NUMBER_CHANGED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(411, /* Length required */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(413, /* Request entity too large */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(414, /* Request URI too large */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(415, /* Unsupported media type */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(420, /* Bad extension */ AST_CAUSE_NO_ROUTE_DESTINATION, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(480, /* No answer */ AST_CAUSE_NO_ANSWER, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(481, /* No answer */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(482, /* Loop detected */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(483, /* Too many hops */ AST_CAUSE_NO_ANSWER, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(484, /* Address incomplete */ AST_CAUSE_INVALID_NUMBER_FORMAT, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(485, /* Ambiguous */ AST_CAUSE_UNALLOCATED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(486, /* Busy everywhere */ AST_CAUSE_BUSY, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(487, /* Request terminated */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(488, /* No codecs approved */ AST_CAUSE_BEARERCAPABILITY_NOTAVAIL, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(491, /* Request pending */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(493, /* Undecipherable */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(500, /* Server internal failure */ AST_CAUSE_FAILURE, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(501, /* Call rejected */ AST_CAUSE_FACILITY_REJECTED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(502, AST_CAUSE_DESTINATION_OUT_OF_ORDER, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(503, /* Service unavailable */ AST_CAUSE_CONGESTION, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(504, /* Gateway timeout */ AST_CAUSE_RECOVERY_ON_TIMER_EXPIRE, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(505, /* SIP version not supported */ AST_CAUSE_INTERWORKING, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(600, /* Busy everywhere */ AST_CAUSE_USER_BUSY, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(603, /* Decline */ AST_CAUSE_CALL_REJECTED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(604, /* Does not exist anywhere */ AST_CAUSE_UNALLOCATED, "", sip2causelookup.table);
	sip2causelookup.table = newsip2cause(606, /* Not acceptable */ AST_CAUSE_BEARERCAPABILITY_NOTAVAIL, "", sip2causelookup.table);


}
	

/*! \brief Make sure we free the cause code list from memory */
void sip2cause_free(void)
{
	struct sip2causestruct *s2c = sip2causelookup.table;
	while (s2c) {
		struct sip2causestruct *next = s2c->next;
		ast_free(s2c);
		s2c = next;
	}
	s2c = cause2siplookup.table;
	while (s2c) {
		struct sip2causestruct *next = s2c->next;
		ast_free(s2c);
		s2c = next;
	}
}


/*! \brief Convert SIP hangup causes to Asterisk hangup causes */
int hangup_sip2cause(int cause)
{
	struct sip2causestruct *s2c = sip2causelookup.table;
	while (s2c) {
		if (s2c->sip == cause) {
			return s2c->cause;
		}
		s2c = s2c->next;
	}

	/* Possible values taken from causes.h */

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
