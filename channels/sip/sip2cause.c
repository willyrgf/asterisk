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
#include "asterisk/strings.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")
#include "include/sip2cause.h"

/*! \brief structure for conversion between ISDN and SIP codes */
struct sip2causestruct {
	int	sip;			/*!< SIP code (200-699) - no provisional codes */
	int	cause;			/*!< ISDN cause code */
	char	reason[64];		/*!< SIP reason text, like "486 Busy", "404 Inte min domän" or "500 Que?" */
	int	private;		/*!< If 1 = private extension */
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

/*! \brief Add conversion entry to table */
static struct sip2causestruct *newsip2cause(int sip, int cause, const char *reason, int private, struct sip2causestruct *next)
{
	struct sip2causestruct *s2c = ast_calloc(1, sizeof(struct sip2causestruct));

	if (!s2c) {
		return NULL;
	}
	s2c->sip = sip;
	s2c->cause = cause;
	ast_copy_string(s2c->reason, reason, sizeof(s2c->reason));
	s2c->next = next;
	ast_debug(4, "SIP2CAUSE adding %d %s <=> %d (%s) \n", sip, reason, cause, ast_cause2str(cause));
	return(s2c);
 }

/*! \brief Initialize structure with default values */
void sip2cause_init(void)
{
	/* Initialize table for SIP => ISDN codes */
	sip2causelookup.table = newsip2cause(401, /* Unauthorized */ AST_CAUSE_CALL_REJECTED, "", 0, NULL);
	sip2causelookup.table = newsip2cause(403, /* Not found */ AST_CAUSE_CALL_REJECTED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(404, /* Not found */ AST_CAUSE_UNALLOCATED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(405, /* Method not allowed */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(407, /* Proxy authentication required */ AST_CAUSE_CALL_REJECTED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(408, /* No reaction */ AST_CAUSE_NO_USER_RESPONSE, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(409, /* Conflict */ AST_CAUSE_NORMAL_TEMPORARY_FAILURE, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(410, /* Gone */ AST_CAUSE_NUMBER_CHANGED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(411, /* Length required */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(413, /* Request entity too large */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(414, /* Request URI too large */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(415, /* Unsupported media type */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(420, /* Bad extension */ AST_CAUSE_NO_ROUTE_DESTINATION, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(480, /* No answer */ AST_CAUSE_NO_ANSWER, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(481, /* No answer */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(482, /* Loop detected */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(483, /* Too many hops */ AST_CAUSE_NO_ANSWER, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(484, /* Address incomplete */ AST_CAUSE_INVALID_NUMBER_FORMAT, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(485, /* Ambiguous */ AST_CAUSE_UNALLOCATED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(486, /* Busy everywhere */ AST_CAUSE_BUSY, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(487, /* Request terminated */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(488, /* No codecs approved */ AST_CAUSE_BEARERCAPABILITY_NOTAVAIL, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(491, /* Request pending */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(493, /* Undecipherable */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(500, /* Server internal failure */ AST_CAUSE_FAILURE, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(501, /* Call rejected */ AST_CAUSE_FACILITY_REJECTED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(502, AST_CAUSE_DESTINATION_OUT_OF_ORDER, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(503, /* Service unavailable */ AST_CAUSE_CONGESTION, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(504, /* Gateway timeout */ AST_CAUSE_RECOVERY_ON_TIMER_EXPIRE, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(505, /* SIP version not supported */ AST_CAUSE_INTERWORKING, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(600, /* Busy everywhere */ AST_CAUSE_USER_BUSY, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(603, /* Decline */ AST_CAUSE_CALL_REJECTED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(604, /* Does not exist anywhere */ AST_CAUSE_UNALLOCATED, "", 0, sip2causelookup.table);
	sip2causelookup.table = newsip2cause(606, /* Not acceptable */ AST_CAUSE_BEARERCAPABILITY_NOTAVAIL, "", 0, sip2causelookup.table);

	/* Add the reverse table */
	cause2siplookup.table = newsip2cause(404, AST_CAUSE_UNALLOCATED, "404 Not Found", 0, NULL);
	cause2siplookup.table = newsip2cause(404, AST_CAUSE_NO_ROUTE_DESTINATION, "404 Not Found", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(404, AST_CAUSE_NO_ROUTE_TRANSIT_NET, "404 Not Found", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(503, AST_CAUSE_CONGESTION, "503 Service Unavailable", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(503, AST_CAUSE_SWITCH_CONGESTION, "503 Service Unavailable", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(408, AST_CAUSE_NO_USER_RESPONSE, "408 Request Timeout", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(480, AST_CAUSE_NO_ANSWER, "480 Temporarily unavailable", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(480, AST_CAUSE_UNREGISTERED, "480 Temporarily unavailable", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(403, AST_CAUSE_CALL_REJECTED, "403 Forbidden", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(410, AST_CAUSE_NUMBER_CHANGED, "410 Gone", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(480, AST_CAUSE_NORMAL_UNSPECIFIED, "480 Temporarily unavailable", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(484, AST_CAUSE_INVALID_NUMBER_FORMAT, "484 Address Incomplete", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(486, AST_CAUSE_USER_BUSY, "486 Busy here", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(500, AST_CAUSE_FAILURE, "500 Server internal failure", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(501, AST_CAUSE_FACILITY_REJECTED, "501 Not implemented", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(503, AST_CAUSE_CHAN_NOT_IMPLEMENTED, "503 Service unavailable", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(502, AST_CAUSE_DESTINATION_OUT_OF_ORDER, "502 Bad gateway", 0, cause2siplookup.table);
	cause2siplookup.table = newsip2cause(488, AST_CAUSE_BEARERCAPABILITY_NOTAVAIL, "488 Not Acceptable Here", 0, cause2siplookup.table);

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
int hangup_sip2cause(int sipcode)
{
	struct sip2causestruct *s2c = sip2causelookup.table;
	while (s2c) {
		if (s2c->sip == sipcode) {
			ast_debug(1, "SIP2CAUSE returning %d (%s) based on SIP code %d        [%s]\n", s2c->cause, ast_cause2str(s2c->cause), sipcode, s2c->private ? "config" : "default");
			return s2c->cause;
		}
		s2c = s2c->next;
	}

	/* Possible values taken from causes.h */

	if (sipcode < 500 && sipcode >= 400) {
		/* 4xx class error that is unknown - someting wrong with our request */
		ast_debug(4, "SIP2CAUSE returning default %d (%s) based on SIP code %d\n", AST_CAUSE_INTERWORKING, ast_cause2str(AST_CAUSE_INTERWORKING), sipcode);
		return AST_CAUSE_INTERWORKING;
	} else if (sipcode < 600 && sipcode >= 500) {
		ast_debug(4, "SIP2CAUSE returning default %d (%s) based on SIP code %d\n", AST_CAUSE_CONGESTION, ast_cause2str(AST_CAUSE_CONGESTION), sipcode);
		/* 5xx class error - problem in the remote end */
		return AST_CAUSE_CONGESTION;
	} else if (sipcode < 700 && sipcode >= 600) {
		ast_debug(4, "SIP2CAUSE returning default %d (%s) based on SIP code %d\n", AST_CAUSE_INTERWORKING, ast_cause2str(AST_CAUSE_INTERWORKING), sipcode);
		/* 6xx - global errors in the 4xx class */
		return AST_CAUSE_INTERWORKING;
	}
	ast_debug(4, "SIP2CAUSE returning default %d (%s) based on SIP code %d\n", s2c->cause, ast_cause2str(s2c->cause), sipcode);
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
char *hangup_cause2sip(int cause)
{
	struct sip2causestruct *s2c = cause2siplookup.table;
	while (s2c) {
		if (s2c->cause == cause) {
			ast_debug(4, "cause2sip returning %s based on ISDN cause %d - %s           [%s]\n", s2c->reason, cause, ast_cause2str(cause), s2c->private ? "config" : "default");
			return s2c->reason;
		}
		s2c = s2c->next;
	}
	ast_debug(1, "AST hangup cause %d (no match found in SIP)\n", cause);
	return NULL;
}

/*! \brief Load configuration

- Check if SIP code is valid
- Check if we can parse the cause code using functions in channel.c

*/
int sip2cause_load(struct ast_config *s2c_config)
{
	struct ast_variable *v;
	int respcode;
	int cause;
	int number=0;

	ast_debug(2, "AST sip2cause configuration parser");
	for (v = ast_variable_browse(s2c_config, "sip2cause"); v; v = v->next) {
		ast_debug(1, "====> SIP2cause ::: Name %s Value %s \n", v->name, v->value);
		respcode = 42;
		cause = 0;
		number = sscanf(v->name, "%d", &respcode);
		if (number != 1) {
			ast_log(LOG_ERROR, "Unknown SIP response code format %s in sip2cause.conf section [sip2cause] Respcode %d Number %d\n", v->name, respcode, number);
			continue;
		}
		if (respcode < 200 || respcode > 699) {
			ast_log(LOG_ERROR, "Bad SIP response code:  Asterisk cause code \'%s=>%s\' in sip2cause.conf section [sip2cause] \n", v->name, v->value);
			continue;
		}
		if ((cause = ast_str2cause(v->value)) == -1) {
			ast_log(LOG_ERROR, "Unknown Asterisk cause code %s in sip2cause.conf section [sip2cause] Cause %d\n", v->value, cause);
			continue;
		} 
		sip2causelookup.table = newsip2cause(respcode, cause, "", 1, sip2causelookup.table);
	}
	for (v = ast_variable_browse(s2c_config, "cause2sip"); v; v = v->next) {
		ast_debug(1, "====> CAUSE2SIP ::: Name %s Value %s \n", v->name, v->value);
		if ((cause = ast_str2cause(v->name)) == -1) {
			ast_log(LOG_ERROR, "Unknown Asterisk cause code %s in sip2cause.conf section [cause2sip] \n", v->name);
			continue;
		} 
		if (sscanf(v->value, "%d ", &respcode) != 1) {
			ast_log(LOG_ERROR, "Bad syntax:  Asterisk cause code \'%s=>%s\' in sip2cause.conf section [cause2sip] \n", v->name, v->value);
			continue;
		}
		if (respcode < 200 || respcode > 699) {
			ast_log(LOG_ERROR, "Bad SIP response code:  \'%s=>%s\' in sip2cause.conf section [cause2sip] \n", v->name, v->value);
			continue;
		}
		cause2siplookup.table = newsip2cause(respcode, cause, v->value, 1, cause2siplookup.table);
	}
	return 1;
}
