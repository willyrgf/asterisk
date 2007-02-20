/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 * and Edvina AB, Sollentuna, Sweden
 *
 * Mark Spencer <markster@digium.com>
 * and Olle E. Johansson, Edvina.net
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

/*! \file
 *
 * \brief MiniVoiceMail - A Minimal Voicemail System
 *
 * A voicemail system in small building blocks, working together
 * 
 * based on the Comedian Mail voicemail system (app_voicemail.c).
 * 
 * \par See also
 * \arg \ref Config_vm
 * \ingroup applications
 * \page App_minivm	Markodian Mail - A minimal voicemail system
 *	
 *	This is a minimal voicemail system, building blocks for something
 *	else. Currently, there's two applications in here:
 *	- minivm_send - record voicemail and send as e-mail
 *	- minivm_greet - Play user's greeting or default greeting
 *
 *	- General configuration in minivm.conf
 *	- Users in realtime or configuration file
 *	- Or configured on the command line with just the e-mail address
 *		
 *	Voicemail accounts are identified 
 *	by userid and domain
 *
 *	Language codes are like setlocale - langcode_countrycode
 *
 *	
 */

/*! \page App_minivm_todo Markodian Minimail - todo
 *	- Do not create directories by default for users, just check if they exist
 *	- Record all voice files in standard temp directory - configurable
 *	- add documentation -not done
 *	- Implement log file
 *	- configure accounts from AMI?
 *	- test, test, test, test
 *	- fix "vm-theextensionis.gsm" voiceprompt from Allison in various formats
 *		"The extension you are calling"
 */

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <dirent.h>

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/astobj.h"
#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/options.h"
#include "asterisk/config.h"
#include "asterisk/say.h"
#include "asterisk/module.h"
#include "asterisk/app.h"
#include "asterisk/manager.h"
#include "asterisk/dsp.h"
#include "asterisk/localtime.h"
#include "asterisk/cli.h"
#include "asterisk/utils.h"
#include "asterisk/linkedlists.h"
#include "asterisk/callerid.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif


#define MVM_REVIEW		(1 << 0)	/*!< Review message */
#define MVM_OPERATOR		(1 << 1)	/*!< Operator exit during voicemail recording */
#define MVM_REALTIME		(1 << 2)	/*!< This user is a realtime account */
#define MVM_SVMAIL		(1 << 3)
#define MVM_ENVELOPE		(1 << 4)
#define MVM_PBXSKIP		(1 << 9)
#define MVM_ALLOCED		(1 << 13)

/* Default mail command to mail voicemail. Change it with the
    mailcmd= command in voicemail.conf */
#define SENDMAIL "/usr/sbin/sendmail -t"

#define SOUND_INTRO "vm-intro"
#define B64_BASEMAXINLINE 256	/*!< Buffer size for Base 64 attachment encoding */
#define B64_BASELINELEN 72	/*!< Line length for Base 64 endoded messages */
#define EOL "\r\n"

#define MAX_DATETIME_FORMAT	512
#define MAX_NUM_CID_CONTEXTS 10

#define ERROR_LOCK_PATH		-100
#define	VOICEMAIL_DIR_MODE	0700
#define	VOICEMAIL_FILE_MODE	0600

#define VOICEMAIL_CONFIG "minivm.conf"
#define ASTERISK_USERNAME "asterisk"	/*!< Default username for sending mail is asterisk@localhost */

static char MVM_SPOOL_DIR[AST_CONFIG_MAX_PATH];

static char *tdesc = "Mini VoiceMail (A minimal Voicemail e-mail System)";
static char *app = "MiniVM";		 	/* Leave a message */
static char *app_greet = "MiniVMgreet";		/* Play voicemail prompts */

static char *synopsis_vm = "Receive voicemail and forward via e-mail";
static char *descrip_vm = 
	"Syntax: minivm(username@domain[,options])\n"
	"This application is part of the Mini-Voicemail system, configured in minivm.conf.\n"
	"MiniVM records audio file in configured format and forwards message to e-mail and pager.\n"
	"If there's no user account for that address, a temporary account will\n"
	"be used with default options.\n"
	"The application will exit if any of the following DTMF digits are \n"
	"received and the requested extension exist in the current context.\n"
	"    0 - Jump to the 'o' extension in the current dialplan context.\n"
	"    * - Jump to the 'a' extension in the current dialplan context.\n"
	"\n"
	"Result is given in channel variable MINIVM_STATUS\n"
	"        The possible values are:     SUCCESS | USEREXIT | FAILED\n\n"
	"  Options:\n"
	"    g(#) - Use the specified amount of gain when recording the voicemail\n"
	"           message. The units are whole-number decibels (dB).\n"
	"\n";

static char *synopsis_vm_greet = "Play voicemail prompts";
static char *descrip_vm_greet = 
	"Syntax: minivm_greet(username@domain[,options])\n"
	"This application is part of the Mini-Voicemail system, configured in minivm.conf.\n"
	"minivm_greet() plays default prompts or user specific prompts.\n"
	"\n"
	"Result is given in channel variable MINIVM_STATUS\n"
	"        The possible values are:     SUCCESS | USEREXIT | FAILED\n\n"
	"  Options:\n"
	"    b    - Play the 'busy' greeting to the calling party.\n"
	"    s    - Skip the playback of instructions for leaving a message to the\n"
	"           calling party.\n"
	"    u    - Play the 'unavailable greeting.\n"
	"\n";

enum {
	OPT_SILENT =	   (1 << 0),
	OPT_BUSY_GREETING =    (1 << 1),
	OPT_UNAVAIL_GREETING = (1 << 2),
	OPT_RECORDGAIN =       (1 << 3),
	OPT_PREPEND_MAILBOX =  (1 << 4),
	OPT_PRIORITY_JUMP =    (1 << 5),
} minivm_option_flags;

enum {
	OPT_ARG_RECORDGAIN = 0,
	OPT_ARG_ARRAY_SIZE = 1,
} minivm_option_args;

AST_APP_OPTIONS(minivm_app_options, {
	AST_APP_OPTION('s', OPT_SILENT),
	AST_APP_OPTION('b', OPT_BUSY_GREETING),
	AST_APP_OPTION('u', OPT_UNAVAIL_GREETING),
	AST_APP_OPTION_ARG('g', OPT_RECORDGAIN, OPT_ARG_RECORDGAIN),
	AST_APP_OPTION('j', OPT_PRIORITY_JUMP),
});



/*! Structure for linked list of users 
*/
struct minivm_user {
	char username[AST_MAX_CONTEXT];	/*!< Mailbox username */
	char domain[AST_MAX_CONTEXT];	/*!< Voicemail domain */
	char password[80];		/*!< Secret pin code, numbers only */
	char fullname[80];		/*!< Full name, for directory app */
	char email[80];			/*!< E-mail address - override */
	char pager[80];			/*!< E-mail address to pager (no attachment) */
	char serveremail[80];		/*!< From: Mail address */
	char mailcmd[160];		/*!< Configurable mail command */
	char language[MAX_LANGUAGE];    /*!< Config: Language setting */
	char zonetag[80];		/*!< Time zone */
	char uniqueid[20];		/*!< Unique integer identifier */
	char exit[80];			/*!< Options for exiting from voicemail() */
	char attachfmt[80];		/*!< Format for voicemail audio file attachment */
	char etemplate[80];		/*!< Pager template */
	char ptemplate[80];		/*!< Voicemail format */
	unsigned int flags;		/*!< MVM_ flags */	
	double volgain;			/*!< Volume gain for voicemails sent via e-mail */
	AST_LIST_ENTRY(minivm_user) list;	
};

/*! \brief Linked list of e-mail templates in various languages 
	These are used as templates for e-mails, pager messages and jabber messages
*/
struct minivm_message {
	char	name[80];		/*!< Template name */
	char	*body;			/*!< Body of this template */
	char	fromstring[100];	/*!< Who's sending the e-mail? */
	char	subject[100];		/*!< Subject line */
	char	charset[32];		/*!< Default character set for this template */
	char	dateformat[80];		/*!< Date format to use in this attachment */
	int	attachment;		/*!< Attachment of media yes/no - no for pager messages */
	AST_LIST_ENTRY(minivm_message) list;	/*!< List mechanics */
};

static AST_LIST_HEAD_STATIC(message_templates, minivm_message);	/*!< The list of e-mail templates */
static AST_LIST_HEAD_STATIC(minivm_users, minivm_user);	/*!< The list of e-mail templates */

/*! Options for leaving voicemail with the voicemail() application */
struct leave_vm_options {
	unsigned int flags;
	signed char record_gain;
};

/*! \brief Structure for base64 encoding */
struct b64_baseio {
	int iocp;
	int iolen;
	int linelength;
	int ateof;
	unsigned char iobuf[B64_BASEMAXINLINE];
};



/*! Voicemail time zones */
struct minivm_zone {
	char name[80];	/* Name of this time zone */
	char timezone[80];
	char msg_format[512];
	AST_LIST_ENTRY(minivm_zone) list;	/*!< List mechanics */
};

static AST_LIST_HEAD_STATIC(minivm_zones, minivm_zone);	/*!< The list of e-mail templates */

/*! \brief Structure for gathering statistics */
struct minivm_stats {
	int voicemailaccounts;		/*!< Number of static accounts */
	int timezones;			/*!< Number of time zones */
	int templates;			/*!< Number of templates */

	time_t reset;			/*!< Time for last reset */
	int receivedmessages;		/*!< Number of received messages since reset */
	time_t lastvoicemail;		/*!< Time for last voicemail sent */
};

static struct minivm_stats global_stats;

AST_MUTEX_DEFINE_STATIC(minivmlock);

static int global_vmminmessage;		/*!< Minimum duration of messages */
static int global_vmmaxmessage;		/*!< Maximum duration of message */
static int global_maxsilence;		/*!< Maximum silence during recording */
static int global_silencethreshold = 128;
static char global_serveremail[80];	/*!< Senders email address for notification */
static char global_mailcmd[160];	/*!< Configurable mail cmd */
static char global_externnotify[160]; 	/*!< External notification application */

static char default_vmformat[80];
static int maxgreet;

static struct ast_flags globalflags = {0};

static int global_saydurationminfo;

/* XXX These will be replaced by the template structure */
struct minivm_message *default_mailtemplate;
struct minivm_message *default_pagertemplate;
static char *emailbody = NULL;
static char *emailsubject = NULL;
static char *pagerbody = NULL;
static char *pagersubject = NULL;

static char global_fromstring[100];
static char global_pagerfromstring[100];
static char global_subject[100];
static char global_charset[32];

static double global_volgain;	/* Volume gain for voicmemail via e-mail */
static char global_emaildateformat[32] = "%A, %B %d, %Y at %r";

STANDARD_LOCAL_USER;

LOCAL_USER_DECL;


/*! \brief Create message template */
static struct minivm_message *message_template_create(char *name)
{
	struct minivm_message *template;

	template = calloc(1, sizeof(struct minivm_message));
	if (!template)
		return NULL;

	ast_copy_string(template->name, name, sizeof(template->name));

	return template;
}

/*! \brief Release memory allocated by message template */
static void message_template_free(struct minivm_message *template)
{
	if (template->body)
		free(template->body);

	free (template);
}

/*! \brief Build message template from configuration */
static int message_template_build(char *name, struct ast_variable *var)
{
	struct minivm_message *template;
	template = message_template_create(name);
	int error = 0;

	while (var) {
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "-_-_- Configuring template option %s = %s for template %s\n", var->name, var->value, name);
		if (!strcasecmp(var->name, "fromaddress")) {
			ast_copy_string(template->fromstring, var->value, sizeof(template->fromstring));
		} else if (!strcasecmp(var->name, "subject")) {
			ast_copy_string(template->subject, var->value, sizeof(template->subject));
		} else if (!strcasecmp(var->name, "attachmedia")) {
			template->attachment = ast_true(var->value);
		} else if (!strcasecmp(var->name, "dateformat")) {
			ast_copy_string(template->dateformat, var->value, sizeof(template->dateformat));
		} else if (!strcasecmp(var->name, "charset")) {
			ast_copy_string(template->charset, var->value, sizeof(template->charset));
		} else if (!strcasecmp(var->name, "templatefile")) {
			/* NO op */
		} else {
			ast_log(LOG_ERROR, "Unknown message template configuration option \"%s=%s\"\n", var->name, var->value);
			error++;
		}
		var = var->next;
	}	
	AST_LIST_LOCK(&message_templates);
	AST_LIST_INSERT_TAIL(&message_templates, template, list);
	AST_LIST_UNLOCK(&message_templates);

	global_stats.templates++;

	return error;
}

/*! \brief Find named template */
static struct minivm_message *message_template_find(char *name)
{
	struct minivm_message *this, *res = NULL;

	if (ast_strlen_zero(name))
		return NULL;

	AST_LIST_LOCK(&message_templates);
	AST_LIST_TRAVERSE(&message_templates, this, list) {
		if (!strcasecmp(this->name, name)) {
			res = this;
			break;
		}
	}
	AST_LIST_UNLOCK(&message_templates);

	return res;
}


/*! \brief Clear list of templates */
static void message_destroy_list(void)
{
	struct minivm_message *this;
	AST_LIST_LOCK(&message_templates);
	while ((this = AST_LIST_REMOVE_HEAD(&message_templates, list))) 
		message_template_free(this);
		
	AST_LIST_UNLOCK(&message_templates);
}

/*! \brief read buffer from file (base64 conversion) */
static int b64_inbuf(struct b64_baseio *bio, FILE *fi)
{
	int l;

	if (bio->ateof)
		return 0;

	if ((l = fread(bio->iobuf, 1, B64_BASEMAXINLINE,fi)) <= 0) {
		if (ferror(fi))
			return -1;

		bio->ateof = 1;
		return 0;
	}

	bio->iolen= l;
	bio->iocp= 0;

	return 1;
}

/*! \brief read character from file to buffer (base64 conversion) */
static int b64_inchar(struct b64_baseio *bio, FILE *fi)
{
	if (bio->iocp >= bio->iolen) {
		if (!b64_inbuf(bio, fi))
			return EOF;
	}

	return bio->iobuf[bio->iocp++];
}

/*! \brief write buffer to file (base64 conversion) */
static int b64_ochar(struct b64_baseio *bio, int c, FILE *so)
{
	if (bio->linelength >= B64_BASELINELEN) {
		if (fputs(EOL,so) == EOF)
			return -1;

		bio->linelength= 0;
	}

	if (putc(((unsigned char) c), so) == EOF)
		return -1;

	bio->linelength++;

	return 1;
}

/*! \brief Encode file to base64 encoding for email attachment (base64 conversion) */
static int base_encode(char *filename, FILE *so)
{
	unsigned char dtable[B64_BASEMAXINLINE];
	int i,hiteof= 0;
	FILE *fi;
	struct b64_baseio bio;

	memset(&bio, 0, sizeof(bio));
	bio.iocp = B64_BASEMAXINLINE;

	if (!(fi = fopen(filename, "rb"))) {
		ast_log(LOG_WARNING, "Failed to open file: %s: %s\n", filename, strerror(errno));
		return -1;
	}

	for (i= 0; i<9; i++) {
		dtable[i]= 'A'+i;
		dtable[i+9]= 'J'+i;
		dtable[26+i]= 'a'+i;
		dtable[26+i+9]= 'j'+i;
	}
	for (i= 0; i < 8; i++) {
		dtable[i+18]= 'S'+i;
		dtable[26+i+18]= 's'+i;
	}
	for (i= 0; i < 10; i++) {
		dtable[52+i]= '0'+i;
	}
	dtable[62]= '+';
	dtable[63]= '/';

	while (!hiteof){
		unsigned char igroup[3], ogroup[4];
		int c,n;

		igroup[0]= igroup[1]= igroup[2]= 0;

		for (n= 0; n < 3; n++) {
			if ((c = b64_inchar(&bio, fi)) == EOF) {
				hiteof= 1;
				break;
			}
			igroup[n]= (unsigned char)c;
		}

		if (n> 0) {
			ogroup[0]= dtable[igroup[0]>>2];
			ogroup[1]= dtable[((igroup[0]&3)<<4)|(igroup[1]>>4)];
			ogroup[2]= dtable[((igroup[1]&0xF)<<2)|(igroup[2]>>6)];
			ogroup[3]= dtable[igroup[2]&0x3F];

			if (n<3) {
				ogroup[3]= '=';

				if (n<2)
					ogroup[2]= '=';
			}

			for (i= 0;i<4;i++)
				b64_ochar(&bio, ogroup[i], so);
		}
	}

	/* Put end of line - line feed */
	if (fputs(EOL, so) == EOF)
		return 0;

	fclose(fi);

	return 1;
}

static int get_date(char *s, int len)
{
	struct tm tm;
	time_t t;
	t = time(0);
	localtime_r(&t,&tm);
	return strftime(s, len, "%a %b %e %r %Z %Y", &tm);
}


/*! \brief Free user structure - if it's allocated */
static void free_user(struct minivm_user *vmu)
{
	if (ast_test_flag(vmu, MVM_ALLOCED))
		free(vmu);
}



/*! \brief Prepare for voicemail template by adding channel variables 
	to the channel
*/
static void prep_email_sub_vars(struct ast_channel *ast, const struct minivm_user *vmu, const char *cidnum, const char *cidname, const char *dur, const char *date)
{
	char callerid[256];
	/* Prepare variables for substition in email body and subject */
	pbx_builtin_setvar_helper(ast, "MVM_NAME", vmu->fullname);
	pbx_builtin_setvar_helper(ast, "MVM_DUR", dur);
	pbx_builtin_setvar_helper(ast, "MVM_DOMAIN", vmu->domain);
	pbx_builtin_setvar_helper(ast, "MVM_USERNAME", vmu->username);
	pbx_builtin_setvar_helper(ast, "MVM_CALLERID", ast_callerid_merge(callerid, sizeof(callerid), cidname, cidnum, "Unknown Caller"));
	pbx_builtin_setvar_helper(ast, "MVM_CIDNAME", (cidname ? cidname : "an unknown caller"));
	pbx_builtin_setvar_helper(ast, "MVM_CIDNUM", (cidnum ? cidnum : "an unknown caller"));
	pbx_builtin_setvar_helper(ast, "MVM_DATE", date);
}

static void populate_defaults(struct minivm_user *vmu)
{
	ast_copy_flags(vmu, (&globalflags), AST_FLAGS_ALL);	
	ast_copy_string(vmu->attachfmt, default_vmformat, sizeof(vmu->attachfmt));
	vmu->volgain = global_volgain;
}

/*! \brief Fix quote of mail headers for non-ascii characters */
static char *mailheader_quote(const char *from, char *to, size_t len)
{
	char *ptr = to;
	*ptr++ = '"';
	for (; ptr < to + len - 1; from++) {
		if (*from == '"')
			*ptr++ = '\\';
		else if (*from == '\0')
			break;
		*ptr++ = *from;
	}
	if (ptr < to + len - 1)
		*ptr++ = '"';
	*ptr = '\0';
	return to;
}


/*! \brief Send pager e-mail */
static int sendpage(char *srcemail, char *pager, char *context, char *mailbox, char *cidnum, char *cidname, int duration, struct minivm_user *vmu)
{
	FILE *p=NULL;
	int pfd;
	char date[256];
	char host[MAXHOSTNAMELEN] = "";
	char who[256];
	char dur[PATH_MAX];
	char tmp[80] = "/tmp/astmail-XXXXXX";
	char tmp2[PATH_MAX];
	time_t t;
	struct tm tm;
	struct minivm_zone *the_zone = NULL;
	pfd = mkstemp(tmp);
	struct ast_channel *ast = ast_channel_alloc(0);

	if (pfd > -1) {
		p = fdopen(pfd, "w");
		if (!p) {
			close(pfd);
			pfd = -1;
		}
	}

	if (!p) {
		ast_log(LOG_WARNING, "Unable to launch '%s'\n", global_mailcmd);
		return -1;
	}
	gethostname(host, sizeof(host)-1);
	if (strchr(srcemail, '@'))
		ast_copy_string(who, srcemail, sizeof(who));
	else 
		snprintf(who, sizeof(who), "%s@%s", srcemail, host);

	snprintf(dur, sizeof(dur), "%d:%02d", duration / 60, duration % 60);
	time(&t);

	/* Does this user have a timezone specified? */
	if (!ast_strlen_zero(vmu->zonetag)) {
		/* Find the zone in the list */
		struct minivm_zone *z;

		AST_LIST_LOCK(&minivm_zones);
		AST_LIST_TRAVERSE(&minivm_zones, z, list) {
			if (strcmp(z->name, vmu->zonetag)) 
				continue;
			the_zone = z;
		}
		AST_LIST_UNLOCK(&minivm_zones);
	}

	if (the_zone)
		ast_localtime(&t,&tm,the_zone->timezone);
	else
		ast_localtime(&t,&tm,NULL);

	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", &tm);
	fprintf(p, "Date: %s\n", date);

	prep_email_sub_vars(ast, vmu, cidnum, cidname, dur, date);

	if (!ast_strlen_zero(global_pagerfromstring)) {

		if (ast) {
			char *passdata;
			int vmlen = strlen(global_fromstring)*3 + 200;
			if ((passdata = alloca(vmlen))) {
				memset(passdata, 0, vmlen);
				pbx_substitute_variables_helper(ast, global_pagerfromstring, passdata, vmlen);
				fprintf(p, "From: %s <%s>\n",passdata,who);
			} else 
				ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
			ast_channel_free(ast);
		} else
			ast_log(LOG_WARNING, "Cannot allocate the channel for variables substitution\n");
	} else
		fprintf(p, "From: Asterisk PBX <%s>\n", who);
	fprintf(p, "To: %s\n", pager);
	if (pagersubject) {
	       if (ast) {
		       char *passdata;
		       int vmlen = strlen(pagersubject)*3 + 200;
		       if ((passdata = alloca(vmlen))) {
			       memset(passdata, 0, vmlen);
			       pbx_substitute_variables_helper(ast, pagersubject, passdata, vmlen);
			       fprintf(p, "Subject: %s\n\n",passdata);
		       } else
				ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
		       ast_channel_free(ast);
	       } else
			ast_log(LOG_WARNING, "Cannot allocate the channel for variables substitution\n");
	} else
	       fprintf(p, "Subject: New VM\n\n");
	strftime(date, sizeof(date), "%A, %B %d, %Y at %r", &tm);
        if (pagerbody) {
	       if (ast) {
		       char *passdata;
		       int vmlen = strlen(pagerbody)*3 + 200;
		       if ((passdata = alloca(vmlen))) {
			       memset(passdata, 0, vmlen);
			       pbx_substitute_variables_helper(ast, pagerbody, passdata, vmlen);
			       fprintf(p, "%s\n",passdata);
		       } else
				ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
		       ast_channel_free(ast);
	       } else
			ast_log(LOG_WARNING, "Cannot allocate the channel for variables substitution\n");
	} else {
	       fprintf(p, "New %s long msg in box %s\n"
			       "from %s, on %s", dur, mailbox, (cidname ? cidname : (cidnum ? cidnum : "unknown")), date);
	}
	fclose(p);
	snprintf(tmp2, sizeof(tmp2), "( %s < %s ; rm -f %s ) &", global_mailcmd, tmp, tmp);
	ast_safe_system(tmp2);
	if (option_debug)
		ast_log(LOG_DEBUG, "Sent page to %s with command '%s'\n", pager, global_mailcmd);
	return 0;
}

static struct minivm_user *mvm_user_alloc(void);

/*! \brief Allocate new vm user and set default values */
static struct minivm_user *mvm_user_alloc()
{
	struct minivm_user *new;

	//new = ast_calloc(1, sizeof(struct minivm_user));
	new = calloc(1, sizeof(struct minivm_user));
	if (!new)
		return NULL;
	ast_set2_flag(new, TRUE, MVM_ALLOCED);	
	populate_defaults(new);

	return new;
}

static int create_vmaccount(char *name, struct ast_variable *var, int realtime);
static struct minivm_user *find_user_realtime(const char *domain, const char *username);

/*! \brief Clear list of users */
static void vmaccounts_destroy_list(void)
{
	struct minivm_user *this;
	AST_LIST_LOCK(&minivm_users);
	while ((this = AST_LIST_REMOVE_HEAD(&minivm_users, list))) 
		free(this);
	AST_LIST_UNLOCK(&minivm_users);
}


/*! \brief Find user from static memory object list */
static struct minivm_user *find_user(const char *domain, const char *username)
{
	struct minivm_user *vmu = NULL, *cur;


	if (ast_strlen_zero(domain) || ast_strlen_zero(username)) {
		ast_log(LOG_NOTICE, "No username or domain? \n");
		return NULL;
	}
	if (option_debug > 2)
		ast_log(LOG_DEBUG, "-_-_-_- Looking for voicemail user %s in domain %s\n", username, domain);

	AST_LIST_LOCK(&minivm_users);
	AST_LIST_TRAVERSE(&minivm_users, cur, list) {
		ast_log(LOG_DEBUG, " ---> Checking %s@%s\n", cur->username, cur->domain);
		/* Is this the voicemail account we're looking for? */
		if (!strcasecmp(domain, cur->domain) && !strcasecmp(username, cur->username))
			break;
	}
	AST_LIST_UNLOCK(&minivm_users);

	if (cur) {
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "-_-_- Found account for %s@%s\n", username, domain);

		/* Make a copy, so that on a reload, we have no race */
		vmu = mvm_user_alloc();
		if (vmu) 
			memcpy(vmu, cur, sizeof(struct minivm_user));
	} else
		vmu = find_user_realtime(domain, username);

	if (!vmu) {
		/* Create a temporary user, send e-mail and be gone */
		vmu = mvm_user_alloc();
		if (vmu) {
			ast_copy_string(vmu->username, username, sizeof(vmu->username));
			ast_copy_string(vmu->domain, domain, sizeof(vmu->domain));
			if (option_debug)
				ast_log(LOG_DEBUG, "--- Created temporary account\n");
		}

	}
	return vmu;
}

/*! \brief Find user in realtime storage 
	Returns pointer to minivm_user structure
*/
static struct minivm_user *find_user_realtime(const char *domain, const char *username)
{
	struct ast_variable *var;
	struct minivm_user *retval;
	char name[MAXHOSTNAMELEN];

	retval = mvm_user_alloc();
	if (!retval)
		return NULL;

	if (username) 
		ast_copy_string(retval->username, username, sizeof(retval->username));

	populate_defaults(retval);
	var = ast_load_realtime("voicemail", "username", username, "domain", domain, NULL);

	if (!var) {
		free(retval);
		return NULL;
	}

	snprintf(name, sizeof(name), "%s@%s", username, domain);
	create_vmaccount(name, var, TRUE);

	ast_variables_destroy(var);
	return retval;
}

/*! Send voicemail with audio file as an attachment */
static int sendmail(struct minivm_message *template, char *srcemail, struct minivm_user *vmu, char *cidnum, char *cidname, char *attach, char *format, int duration, int attach_user_voicemail)
{
	FILE *p = NULL;
	int pfd;
	char email[256];
	char date[256];
	char host[MAXHOSTNAMELEN];
	char who[256];
	char bound[256];
	char fname[PATH_MAX];
	char dur[PATH_MAX];
	char tmp[80] = "/tmp/astmail-XXXXXX";
	char tmp2[PATH_MAX];
	time_t now;
	struct tm tm;
	struct minivm_zone *the_zone = NULL;
	int len_passdata;
	char *passdata2;
	struct ast_channel *ast;

	if (vmu && !ast_strlen_zero(vmu->email)) {
		ast_copy_string(email, vmu->email, sizeof(email));	
	} else if (!ast_strlen_zero(vmu->username) && !ast_strlen_zero(vmu->domain))
		snprintf(email, sizeof(email), "%s@%s", vmu->username, vmu->domain);
	else {
		ast_log(LOG_WARNING, "No mail address to send to.\n");
		return -1;	
	}

	if (option_debug > 2)
		ast_log(LOG_DEBUG, "-_-_- Sending mail to %s@%s - Using template %s\n", vmu->username, vmu->domain, template->name);

	if (!strcmp(format, "wav49"))
		format = "WAV";


	/* If we have a gain option, process it now with sox */
	if (vmu->volgain < -.001 || vmu->volgain > .001) {
		char newtmp[PATH_MAX];
		char tmpcmd[PATH_MAX];
		int tmpfd;

		snprintf(newtmp, sizeof(newtmp), "/tmp/XXXXXX");
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "newtmp: %s\n", newtmp);
		tmpfd = mkstemp(newtmp);
		snprintf(tmpcmd, sizeof(tmpcmd), "sox -v %.4f %s.%s %s.%s", vmu->volgain, attach, format, newtmp, format);
		ast_safe_system(tmpcmd);
		attach = newtmp;
		if (option_debug > 2)
			ast_log	(LOG_DEBUG, "VOLGAIN: Stored at: %s.%s - Level: %.4f - Mailbox: %s\n", attach, format, vmu->volgain, vmu->username);
	}

	/* Create file name */
	snprintf(fname, sizeof(fname), "%s.%s", attach, format);

	if (option_debug)
		ast_log(LOG_DEBUG, "Attaching file '%s', format '%s', uservm is '%d'\n", attach, format, attach_user_voicemail);
	/* Make a temporary file instead of piping directly to sendmail, in case the mail
	   command hangs */
	pfd = mkstemp(tmp);
	if (pfd > -1) {
		p = fdopen(pfd, "w");
		if (!p) {
			close(pfd);
			pfd = -1;
		}
	}
	if (!p) {
		ast_log(LOG_WARNING, "Unable to launch '%s'\n", global_mailcmd);
		return -1;
	}
	/* Allocate channel used for chanvar substitution */
	ast = ast_channel_alloc(0);
	gethostname(host, sizeof(host)-1);

	/* If needed, add hostname as domain */
	if (strchr(srcemail, '@'))
		ast_copy_string(who, srcemail, sizeof(who));
	else 
		snprintf(who, sizeof(who), "%s@%s", srcemail, host);

	snprintf(dur, sizeof(dur), "%d:%02d", duration / 60, duration % 60);

	/* Does this user have a timezone specified? */
	if (!ast_strlen_zero(vmu->zonetag)) {
		/* Find the zone in the list */
		struct minivm_zone *z;
		AST_LIST_LOCK(&minivm_zones);
		AST_LIST_TRAVERSE(&minivm_zones, z, list) {
			if (strcmp(z->name, vmu->zonetag)) 
				continue;
			the_zone = z;
		}
		AST_LIST_UNLOCK(&minivm_zones);
	}

	time(&now);
	ast_localtime(&now, &tm, the_zone ? the_zone->timezone : NULL);
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", &tm);

	/* Start printing the email to the temporary file */
	fprintf(p, "Date: %s\n", date);

	/* Set date format for voicemail mail */
	strftime(date, sizeof(date), global_emaildateformat, &tm);

	/* Populate channel with channel variables for substitution */
	prep_email_sub_vars(ast, vmu, cidnum, cidname, dur, date);

	if (ast_strlen_zero(global_fromstring)) {
		fprintf(p, "From: Asterisk PBX <%s>\n", who);
	} else {
		char *passdata;
		int vmlen = strlen(global_fromstring)*3 + 200;
		if ((passdata = alloca(vmlen))) {
			memset(passdata, 0, vmlen);
			pbx_substitute_variables_helper(ast, global_fromstring, passdata, vmlen);
			len_passdata = strlen(passdata) * 2 + 3;
			passdata2 = alloca(len_passdata);
			fprintf(p, "From: %s <%s>\n", mailheader_quote(passdata, passdata2, len_passdata), who);
		} else 
			ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
	} 

	len_passdata = strlen(vmu->fullname) * 2 + 3;
	passdata2 = alloca(len_passdata);
	fprintf(p, "To: %s <%s>\n", mailheader_quote(vmu->fullname, passdata2, len_passdata), vmu->email);

	if (emailsubject) {
		char *passdata;
		int vmlen = strlen(emailsubject) * 3 + 200;
		if ((passdata = alloca(vmlen))) {
			memset(passdata, 0, vmlen);
			pbx_substitute_variables_helper(ast, emailsubject, passdata, vmlen);
			fprintf(p, "Subject: %s\n", passdata);
		} else
			ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
		ast_channel_free(ast);
	} else if (!ast_strlen_zero(global_subject)) {
		fprintf(p, global_subject, 0, vmu->username) ;
		fprintf(p,"\n") ;
	} else if (ast_test_flag((&globalflags), MVM_PBXSKIP))
		fprintf(p, "Subject: New message in mailbox %s@%s\n", vmu->username, vmu->domain);
	else
		fprintf(p, "Subject: [PBX]: New message in mailbox %s@%s\n", vmu->username, vmu->domain);
	fprintf(p, "Message-ID: <Asterisk-%d-%s-%d@%s>\n", (unsigned int)rand(), vmu->username, getpid(), host);
	fprintf(p, "MIME-Version: 1.0\n");

	/* Something unique. */
	snprintf(bound, sizeof(bound), "voicemail_%s%d%d", vmu->username, getpid(), (unsigned int)rand());

	fprintf(p, "Content-Type: multipart/mixed; boundary=\"%s\"\n\n\n", bound);

	fprintf(p, "--%s\n", bound);
	fprintf(p, "Content-Type: text/plain; charset=%s\nContent-Transfer-Encoding: 8bit\n\n", global_charset);
	if (emailbody) {
		char *passdata;
		int vmlen = strlen(emailbody)*3 + 200;
		if ((passdata = alloca(vmlen))) {
			memset(passdata, 0, vmlen);
			pbx_substitute_variables_helper(ast, emailbody, passdata, vmlen);
			fprintf(p, "%s\n", passdata);
		} else ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
	} else {
		fprintf(p, "Dear %s:\n\n\tJust wanted to let you know you were just left a %s long message \n"

			"in mailbox %s from %s, on %s so you might\n"
			"want to check it when you get a chance.  Thanks!\n\n\t\t\t\t--Asterisk\n\n", vmu->fullname, 
			dur,  vmu->username, (cidname ? cidname : (cidnum ? cidnum : "an unknown caller")), date);
	}
	/* Eww. We want formats to tell us their own MIME type */
	char *ctype = "audio/x-";
	if (!strcasecmp(format, "ogg"))
		ctype = "application/";
	
	fprintf(p, "--%s\n", bound);
	fprintf(p, "Content-Type: %s%s; name=\"voicemailmsg.%s\"\n", ctype, format, format);
	fprintf(p, "Content-Transfer-Encoding: base64\n");
	fprintf(p, "Content-Description: Voicemail sound attachment.\n");
	fprintf(p, "Content-Disposition: attachment; filename=\"voicemailmsg.%s\"\n\n", format);

	base_encode(fname, p);
	fprintf(p, "\n\n--%s--\n.\n", bound);
	fclose(p);
	snprintf(tmp2, sizeof(tmp2), "( %s < %s ; rm -f %s ) &", global_mailcmd, tmp, tmp);
	ast_safe_system(tmp2);
	if (option_debug)
		ast_log(LOG_DEBUG, "Sent mail to %s with command '%s'\n", vmu->email, global_mailcmd);
	ast_channel_free(ast);
	return 0;
}

static int make_dir(char *dest, int len, const char *context, const char *ext, const char *folder)
{
	return snprintf(dest, len, "%s%s/%s/%s", MVM_SPOOL_DIR, context, ext, folder);
}

/*! \brief basically mkdir -p $dest/$domain/$ext/$$username
 * \param dest    String. base directory.
 * \param domain String. Ignored if is null or empty string.
 * \param ext	  String. Ignored if is null or empty string.
 * \param username String. Ignored if is null or empty string. 
 * \param returns 0 on failure, 1 on success.
 */
static int create_dirpath(char *dest, int len, char *domain, char *ext, char *username)
{
	mode_t	mode = VOICEMAIL_DIR_MODE;

	if(!ast_strlen_zero(domain)) {
		make_dir(dest, len, domain, "", "");
		if(mkdir(dest, mode) && errno != EEXIST) {
			ast_log(LOG_WARNING, "mkdir '%s' failed: %s\n", dest, strerror(errno));
			return 0;
		}
	}
	if(!ast_strlen_zero(ext)) {
		make_dir(dest, len, domain, ext, "");
		if(mkdir(dest, mode) && errno != EEXIST) {
			ast_log(LOG_WARNING, "mkdir '%s' failed: %s\n", dest, strerror(errno));
			return 0;
		}
	}
	if(!ast_strlen_zero(username)) {
		make_dir(dest, len, domain, ext, username);
		if(mkdir(dest, mode) && errno != EEXIST) {
			ast_log(LOG_WARNING, "mkdir '%s' failed: %s\n", dest, strerror(errno));
			return 0;
		}
	}
	if (option_debug > 1)
		ast_log(LOG_DEBUG, "Creating directory for %s@%s ext %s : %s\n", username, domain, ext, dest);
	return 1;
}


/*! \brief Play intro message before recording voicemail 
	\note maybe this should be done in the dialplan, not
		in the application
*/
static int invent_message(struct ast_channel *chan, char *domain, char *username, int busy, char *ecodes)
{
	int res;
	char fn[PATH_MAX];
	char dest[PATH_MAX];

	if (option_debug > 1)
		ast_log(LOG_DEBUG, "-_-_- Still preparing to play message ...\n");

	snprintf(fn, sizeof(fn), "%s%s/%s/greet", MVM_SPOOL_DIR, domain, username);

	if (!(res = create_dirpath(dest, sizeof(dest), domain, username, "greet"))) {
		ast_log(LOG_WARNING, "Failed to make directory(%s)\n", fn);
		return -1;
	}

	if (ast_fileexists(fn, NULL, NULL) > 0) {
		res = ast_streamfile(chan, fn, chan->language);
		if (res) 
			return -1;
		res = ast_waitstream(chan, ecodes);
		if (res) 
			return res;
	} else {
		int numericusername = 1;
		char *i = username;

		if (option_debug > 1)
			ast_log(LOG_DEBUG, "-_-_- No personal prompts. Using default prompt set for language\n");
		
		while (*i)  {
			if (option_debug > 1)
				ast_log(LOG_DEBUG, "-_-_- Numeric? Checking %c\n", *i);
			if (!isdigit(*i)) {
				numericusername = FALSE;
				break;
			}
			i++;
		}

		if (numericusername) {
			if(ast_streamfile(chan, "vm-theperson", chan->language))
				return -1;
			if ((res = ast_waitstream(chan, ecodes)))
				return res;
	
			res = ast_say_digit_str(chan, username, ecodes, chan->language);
			if (res)
				return res;
		} else {
			if(ast_streamfile(chan, "vm-theextensionis", chan->language))
				return -1;
			if ((res = ast_waitstream(chan, ecodes)))
				return res;
		}
	}

	res = ast_streamfile(chan, busy ? "vm-isonphone" : "vm-isunavail", chan->language);
	if (res)
		return -1;
	res = ast_waitstream(chan, ecodes);
	return res;
}

/*! \brief Delete attribute file */
static int vm_delete(char *file)
{
	char *txt;
	int txtsize = 0;

	if (option_debug)
		ast_log(LOG_DEBUG, "--- Deleting voicemail file %s\n", file);

	txtsize = (strlen(file) + 5) * sizeof(char);
	txt = (char *)alloca(txtsize);
	/* Sprintf here would safe because we alloca'd exactly the right length,
	 * but trying to eliminate all sprintf's anyhow
	 */
	snprintf(txt, txtsize, "%s.txt", file);
	unlink(txt);
	return ast_filedelete(file, NULL);
}


/*! \brief Record voicemail message & let caller review or re-record it, or set options if applicable */
static int play_record_review(struct ast_channel *chan, char *playfile, char *recordfile, int maxtime, char *fmt,
			      int outsidecaller, struct minivm_user *vmu, int *duration, const char *unlockdir,
			      signed char record_gain)
{
 	int res = 0;
 	int cmd = 0;
 	int max_attempts = 3;
 	int attempts = 0;
 	int recorded = 0;
 	int message_exists = 0;
	signed char zero_gain = 0;
	char *acceptdtmf = "#";
	char *canceldtmf = "";

 	/* Note that urgent and private are for flagging messages as such in the future */
 
	/* barf if no pointer passed to store duration in */
	if (duration == NULL) {
		ast_log(LOG_WARNING, "Error play_record_review called without duration pointer\n");
		return -1;
	}

 	cmd = '3';	 /* Want to start by recording */
 
	while ((cmd >= 0) && (cmd != 't')) {
		switch (cmd) {
		case '1':
			if (!message_exists) {
 				/* In this case, 1 is to record a message */
 				cmd = '3';
 				break;
 			} else {
 				/* Otherwise 1 is to save the existing message */
 				if (option_verbose > 2)
					ast_verbose(VERBOSE_PREFIX_3 "Saving message as is\n");
 				ast_streamfile(chan, "vm-msgsaved", chan->language);
 				ast_waitstream(chan, "");
 				cmd = 't';
 				return res;
 			}
 		case '2':
 			/* Review */
 			if (option_verbose > 2)
				ast_verbose(VERBOSE_PREFIX_3 "Reviewing the message\n");
 			ast_streamfile(chan, recordfile, chan->language);
 			cmd = ast_waitstream(chan, AST_DIGIT_ANY);
 			break;
 		case '3':
 			message_exists = 0;
 			/* Record */
 			if (recorded == 1) {
				if (option_verbose > 2)
					ast_verbose(VERBOSE_PREFIX_3 "Re-recording the message\n");
 			} else {	
				if (option_verbose > 2)
					ast_verbose(VERBOSE_PREFIX_3 "Recording the message\n");
			}
			if (recorded && outsidecaller) 
 				cmd = ast_play_and_wait(chan, "beep");
 			recorded = 1;
 			/* After an attempt has been made to record message, we have to take care of INTRO and beep for incoming messages, but not for greetings */
			if (record_gain)
				ast_channel_setoption(chan, AST_OPTION_RXGAIN, &record_gain, sizeof(record_gain), 0);
			if (ast_test_flag(vmu, MVM_OPERATOR))
				canceldtmf = "0";
			cmd = ast_play_and_record_full(chan, playfile, recordfile, maxtime, fmt, duration, global_silencethreshold, global_maxsilence, unlockdir, acceptdtmf, canceldtmf);
			if (record_gain)
				ast_channel_setoption(chan, AST_OPTION_RXGAIN, &zero_gain, sizeof(zero_gain), 0);
 			if (cmd == -1) 
 			/* User has hung up, no options to give */
 				return cmd;
 			if (cmd == '0')
 				break;
 			else if (cmd == '*')
 				break;
 			else {
 				/* If all is well, a message exists */
 				message_exists = 1;
				cmd = 0;
 			}
 			break;
 		case '4':
 		case '5':
 		case '6':
 		case '7':
 		case '8':
 		case '9':
		case '*':
		case '#':
 			cmd = ast_play_and_wait(chan, "vm-sorry");
 			break;
 		case '0':
			if(!ast_test_flag(vmu, MVM_OPERATOR)) {
 				cmd = ast_play_and_wait(chan, "vm-sorry");
 				break;
			}
			if (message_exists || recorded) {
				cmd = ast_play_and_wait(chan, "vm-saveoper");
				if (!cmd)
					cmd = ast_waitfordigit(chan, 3000);
				if (cmd == '1') {
					ast_play_and_wait(chan, "vm-msgsaved");
					cmd = '0';
				} else {
					ast_play_and_wait(chan, "vm-deleted");
					vm_delete(recordfile);
					cmd = '0';
				}
			}
			return cmd;
 		default:
			/* If the caller is an ouside caller, and the review option is enabled,
			   allow them to review the message, but let the owner of the box review
			   their OGM's */
			if (outsidecaller && !ast_test_flag(vmu, MVM_REVIEW))
				return cmd;
 			if (message_exists) {
 				cmd = ast_play_and_wait(chan, "vm-review");
 			} else {
 				cmd = ast_play_and_wait(chan, "vm-torerecord");
 				if (!cmd)
 					cmd = ast_waitfordigit(chan, 600);
 			}
 			
 			if (!cmd && outsidecaller && ast_test_flag(vmu, MVM_OPERATOR)) {
 				cmd = ast_play_and_wait(chan, "vm-reachoper");
 				if (!cmd)
 					cmd = ast_waitfordigit(chan, 600);
 			}
 			if (!cmd)
 				cmd = ast_waitfordigit(chan, 6000);
 			if (!cmd) {
 				attempts++;
 			}
 			if (attempts > max_attempts) {
 				cmd = 't';
 			}
 		}
 	}
 	if (outsidecaller)  
		ast_play_and_wait(chan, "vm-goodbye");
 	if (cmd == 't')
 		cmd = 0;
 	return cmd;
}

/*! \brief Lock path
 only return failure if ast_lock_path returns 'timeout',
   not if the path does not exist or any other reason
*/
static int vm_lock_path(const char *path)
{
	switch (ast_lock_path(path)) {
	case AST_LOCK_TIMEOUT:
		return -1;
	default:
		return 0;
	}
}

/*! \brief Send message to voicemail account owner */
static int notify_new_message(struct ast_channel *chan, struct minivm_user *vmu, char *filename, long duration, char *fmt, char *cidnum, char *cidname)
{
	char ext_context[PATH_MAX], *stringp;
	char *myserveremail = global_serveremail;
	struct minivm_message *etemplate;

	snprintf(ext_context, sizeof(ext_context), "%s@%s", vmu->username, vmu->domain);

	if (!ast_strlen_zero(vmu->attachfmt)) {
		if (strstr(fmt, vmu->attachfmt)) {
			fmt = vmu->attachfmt;
		} else 
			ast_log(LOG_WARNING, "Attachment format '%s' is not one of the recorded formats '%s'.  Falling back to default format for '%s@%s'.\n", vmu->attachfmt, fmt, vmu->username, vmu->domain);
	}

	etemplate = message_template_find(vmu->etemplate);
	if (!etemplate)
		etemplate = message_template_find("email-default");

	/* Attach only the first format */
	fmt = ast_strdupa(fmt);
	stringp = fmt;
	strsep(&stringp, "|");


	if (!ast_strlen_zero(vmu->serveremail))
		myserveremail = vmu->serveremail;

	sendmail(etemplate, myserveremail, vmu, cidnum, cidname, filename, fmt, duration, TRUE);

	if (!ast_strlen_zero(vmu->pager)) 
		sendpage(myserveremail, vmu->pager, vmu->domain, vmu->username, cidnum, cidname, duration, vmu);

	vm_delete(filename);

	manager_event(EVENT_FLAG_CALL, "MiniVoiceMail", "Action: SentMail\rn\nMailbox: %s@%s\r\n", vmu->username, vmu->domain);
	// this needs to come back at a later time
	//run_externnotify(vmu->context, vmu->mailbox);
	return 0;
}

 
/*! \brief Record voicemail message, store into file prepared for sending e-mail 
*/
static int leave_voicemail(struct ast_channel *chan, char *username, struct leave_vm_options *options)
{
	char tmptxtfile[PATH_MAX];
	char callerid[256];
	FILE *txt;
	int res = 0, txtdes;
	int msgnum;
	int duration = 0;
	char date[256];
	char dir[PATH_MAX], tmpdir[PATH_MAX];
	char ext_context[256] = "";
	char fmt[80];
	char *domain;
	char tmp[256] = "";
	struct minivm_user *vmu;

	ast_copy_string(tmp, username, sizeof(tmp));
	username = tmp;
	domain = strchr(tmp, '@');
	if (domain) {
		*domain = '\0';
		domain++;
	}

	if (!(vmu = find_user(domain, username))) {
		/* We could not find user, let's exit */
		ast_log(LOG_WARNING, "No entry in voicemail config file for '%s@%s'\n", username, domain);
		if (ast_test_flag(options, OPT_PRIORITY_JUMP) || option_priority_jumping)
			ast_goto_if_exists(chan, chan->context, chan->exten, chan->priority + 101);
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
		return res;
	}

	/* Setup pre-file if appropriate */
	if (strcmp(vmu->domain, "localhost"))
		snprintf(ext_context, sizeof(ext_context), "%s@%s", username, vmu->domain);
	else
		ast_copy_string(ext_context, vmu->domain, sizeof(ext_context));

	/* The meat of recording the message...  All the announcements and beeps have been played*/
	if (ast_strlen_zero(vmu->attachfmt))
		ast_copy_string(fmt, default_vmformat, sizeof(fmt));
	else
		ast_copy_string(fmt, vmu->attachfmt, sizeof(fmt));

	if (ast_strlen_zero(fmt)) {
		ast_log(LOG_WARNING, "No format for saving voicemail? Default %s\n", default_vmformat);
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
		free_user(vmu);
		return res;
	}
	msgnum = 0;

	/* It's easier just to try to make it than to check for its existence */
	create_dirpath(tmpdir, sizeof(tmpdir), vmu->domain, "tmp", username);

	snprintf(tmptxtfile, sizeof(tmptxtfile), "%s/XXXXXX", tmpdir);
	/* XXX This file needs to be in temp directory */
	txtdes = mkstemp(tmptxtfile);
	if (txtdes < 0) {
		res = ast_streamfile(chan, "vm-mailboxfull", chan->language);
		if (!res)
			res = ast_waitstream(chan, "");
		ast_log(LOG_ERROR, "Unable to create message file: %s\n", strerror(errno));
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
		goto leave_vm_out;
	}

	/* Now play the beep once we have the message number for our next message. */
	if (res >= 0) {
		/* Unless we're *really* silent, try to send the beep */
		res = ast_streamfile(chan, "beep", chan->language);
		if (!res)
			res = ast_waitstream(chan, "");
	}

	/* OEJ XXX Maybe this can be turned into a log file? Hmm. */
	/* Store information */
	if (option_debug)
		ast_log(LOG_DEBUG, "Open file for metadata: %s\n", tmptxtfile);

	txt = fdopen(txtdes, "w+");
	if (txt) {
		struct tm tm;
		time_t now;
		char timebuf[30];
		get_date(date, sizeof(date));
		now = time(NULL);
		//ast_localtime(&now, &tm, the_zone ? the_zone->timezone : NULL);
		ast_localtime(&now, &tm, NULL);
		strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm);
		
		fprintf(txt, 
			/* "Mailbox:domain:macrocontext:exten:priority:callerchan:callerid:origdate:origtime:duration" */
			"%s:%s:%s:%s:%d:%s:%s:%s:%s:%s\n",
			username,
			chan->context,
			chan->macrocontext, 
			chan->exten,
			chan->priority,
			chan->name,
			ast_callerid_merge(callerid, sizeof(callerid), chan->cid.cid_name, chan->cid.cid_num, "Unknown"),
			date, 
			timebuf,
			"durationholder"); 
	} else
		ast_log(LOG_WARNING, "Error opening text file for output\n");

	res = play_record_review(chan, NULL, tmptxtfile, global_vmmaxmessage, fmt, 1, vmu, &duration, NULL, options->record_gain);

// static int play_record_review(struct ast_channel *chan, char *playfile, char *recordfile, int maxtime, char *fmt,
//			      int outsidecaller, struct minivm_user *vmu, int *duration, const char *unlockdir,
//			      signed char record_gain)

	if (txt) {
		if (duration < global_vmminmessage) {
			if (option_verbose > 2) 
				ast_verbose( VERBOSE_PREFIX_3 "Recording was %d seconds long but needs to be at least %d - abandoning\n", duration, global_vmminmessage);
			fclose(txt);
			ast_filedelete(tmptxtfile, NULL);
			unlink(tmptxtfile);
			pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
			free_user(vmu);
			return 0;
		} 
		fprintf(txt, "duration=%d\n", duration);
		fclose(txt);
		if (vm_lock_path(dir)) {
			ast_log(LOG_ERROR, "Couldn't lock directory %s.  Voicemail will be lost.\n", dir);
			/* Delete files */
			ast_filedelete(tmptxtfile, NULL);
			unlink(tmptxtfile);
			pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
			free_user(vmu);
			return 0;
		}
		if (ast_fileexists(tmptxtfile, NULL, NULL) <= 0) {
			if (option_debug) 
				ast_log(LOG_DEBUG, "The recorded media file is gone, so we should remove the .txt file too!\n");
			unlink(tmptxtfile);
			ast_unlock_path(dir);
			pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
			free_user(vmu);
			return 0;
		}

		/* assign a variable with the name of the voicemail file */	  
		pbx_builtin_setvar_helper(chan, "MVM_MESSAGEFILE", tmptxtfile);

		ast_unlock_path(dir);

		if (ast_fileexists(tmptxtfile, NULL, NULL) > 0)
			notify_new_message(chan, vmu, tmptxtfile, duration, fmt, chan->cid.cid_num, chan->cid.cid_name);
	}

	if (res > 0)
		res = 0;

	pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "SUCCESS");
 leave_vm_out:
	free_user(vmu);
	
	return res;
}

/*! \brief Play voicemail prompts - either generic or user specific */
static int minivm_prompt_exec(struct ast_channel *chan, void *data)
{
	struct localuser *u;
	struct leave_vm_options leave_options = { 0, '\0'};
	int argc;
	char *argv[2];
	struct ast_flags flags = { 0 };
	char *opts[OPT_ARG_ARRAY_SIZE];
	int res = 0;
	int ausemacro = 0;
	int ousemacro = 0;
	int ouseexten = 0;
	char tmp[PATH_MAX];
	char tmpdir[PATH_MAX];
	char dest[PATH_MAX];
	char prefile[PATH_MAX] = "";
	char tempfile[PATH_MAX] = "";
	char ext_context[256] = "";
	char *domain;
	char ecodes[16] = "#";
	char *tmpptr;
	struct minivm_user *vmu;
	char *username = argv[0];
	
	LOCAL_USER_ADD(u);

	/* Answer channel if it's not already answered */
	if (chan->_state != AST_STATE_UP)
		ast_answer(chan);

	if (ast_strlen_zero(data))  {
		ast_log(LOG_ERROR, "Minivm needs at least an account argument \n");
		LOCAL_USER_REMOVE(u);
		return -1;
	}
	tmpptr = ast_strdupa((char *)data);
	if (!tmpptr) {
		ast_log(LOG_ERROR, "Out of memory\n");
		LOCAL_USER_REMOVE(u);
		return -1;
	}
	argc = ast_app_separate_args(tmpptr, '|', argv, sizeof(argv) / sizeof(argv[0]));
	if (argc == 2) {
		if (ast_app_parse_options(minivm_app_options, &flags, opts, argv[1])) {
			LOCAL_USER_REMOVE(u);
			return -1;
		}
		ast_copy_flags(&leave_options, &flags, OPT_SILENT | OPT_BUSY_GREETING | OPT_UNAVAIL_GREETING | OPT_PRIORITY_JUMP);
	}

	ast_copy_string(tmp, argv[0], sizeof(tmp));
	username = tmp;
	domain = strchr(tmp, '@');
	if (domain) {
		*domain = '\0';
		domain++;
	} 
	if (ast_strlen_zero(domain) || ast_strlen_zero(username)) {
		ast_log(LOG_ERROR, "Need username@domain as argument. Sorry. Argument 0 %s\n", argv[0]);
		LOCAL_USER_REMOVE(u);
		return -1;
	}
	if (option_debug)
		ast_log(LOG_DEBUG, "-_-_- Trying to find prompts for user %s in domain %s\n", username, domain);

	if (!(vmu = find_user(domain, username))) {
		/* We could not find user, let's exit */
		ast_log(LOG_WARNING, "No entry in voicemail config file for '%s@%s'\n", username, domain);
		if (ast_test_flag(&leave_options, OPT_PRIORITY_JUMP) || option_priority_jumping)
			ast_goto_if_exists(chan, chan->context, chan->exten, chan->priority + 101);
		pbx_builtin_setvar_helper(chan, "MINIVMGREETSTATUS", "FAILED");
		return res;
	}

	/* Setup pre-file if appropriate */
	if (strcmp(vmu->domain, "localhost"))
		snprintf(ext_context, sizeof(ext_context), "%s@%s", username, vmu->domain);
	else
		ast_copy_string(ext_context, vmu->domain, sizeof(ext_context));

	if (ast_test_flag(&leave_options, OPT_BUSY_GREETING)) {
		res = create_dirpath(dest, sizeof(dest), vmu->domain, username, "busy");
		snprintf(prefile, sizeof(prefile), "%s%s/%s/busy", MVM_SPOOL_DIR, vmu->domain, username);
	} else if (ast_test_flag(&leave_options, OPT_UNAVAIL_GREETING)) {
		res = create_dirpath(dest, sizeof(dest), vmu->domain, username, "unavail");
		snprintf(prefile, sizeof(prefile), "%s%s/%s/unavail", MVM_SPOOL_DIR, vmu->domain, username);
	}
	snprintf(tempfile, sizeof(tempfile), "%s%s/%s/temp", MVM_SPOOL_DIR, vmu->domain, username);
	if (!(res = create_dirpath(dest, sizeof(dest), vmu->domain, username, "temp"))) {
		ast_log(LOG_WARNING, "Failed to make directory (%s)\n", tempfile);
		return -1;
	}
	if (option_debug > 1)
		ast_log(LOG_DEBUG, "-_-_- Preparing to play message ...\n");

	/* Play the message */
	if (ast_fileexists(tempfile, NULL, NULL) > 0)
		ast_copy_string(prefile, tempfile, sizeof(prefile));

	/* It's easier just to try to make it than to check for its existence */
	create_dirpath(tmpdir, sizeof(tmpdir), vmu->domain, username, "tmp");

	/* Check current or macro-calling context for special extensions */
	if (ast_test_flag(vmu, MVM_OPERATOR)) {
		if (!ast_strlen_zero(vmu->exit)) {
			if (ast_exists_extension(chan, vmu->exit, "o", 1, chan->cid.cid_num)) {
				strncat(ecodes, "0", sizeof(ecodes) - strlen(ecodes) - 1);
				ouseexten = 1;
			}
		} else if (ast_exists_extension(chan, chan->context, "o", 1, chan->cid.cid_num)) {
			strncat(ecodes, "0", sizeof(ecodes) - strlen(ecodes) - 1);
			ouseexten = 1;
		}
		else if (!ast_strlen_zero(chan->macrocontext) && ast_exists_extension(chan, chan->macrocontext, "o", 1, chan->cid.cid_num)) {
			strncat(ecodes, "0", sizeof(ecodes) - strlen(ecodes) - 1);
			ousemacro = 1;
		}
	}

	if (!ast_strlen_zero(vmu->exit)) {
		if (ast_exists_extension(chan, vmu->exit, "a", 1, chan->cid.cid_num))
			strncat(ecodes, "*", sizeof(ecodes) -  strlen(ecodes) - 1);
	} else if (ast_exists_extension(chan, chan->context, "a", 1, chan->cid.cid_num))
		strncat(ecodes, "*", sizeof(ecodes) -  strlen(ecodes) - 1);
	else if (!ast_strlen_zero(chan->macrocontext) && ast_exists_extension(chan, chan->macrocontext, "a", 1, chan->cid.cid_num)) {
		strncat(ecodes, "*", sizeof(ecodes) -  strlen(ecodes) - 1);
		ausemacro = 1;
	}

	/* Play the beginning intro if desired */
	if (!ast_strlen_zero(prefile)) {
		if (ast_fileexists(prefile, NULL, NULL) > 0) {
			if (ast_streamfile(chan, prefile, chan->language) > -1) 
				res = ast_waitstream(chan, ecodes);
		} else {
			if (option_debug > 1)
				ast_log(LOG_DEBUG, "%s doesn't exist, doing what we can\n", prefile);
			res = invent_message(chan, vmu->domain, username, ast_test_flag(&leave_options, OPT_BUSY_GREETING), ecodes);
		}
		if (res < 0) {
			if (option_debug > 1)
				ast_log(LOG_DEBUG, "Hang up during prefile playback\n");
			free_user(vmu);
			pbx_builtin_setvar_helper(chan, "MINIVMGREETSTATUS", "FAILED");
			return -1;
		}
	}
	if (res == '#') {
		/* On a '#' we skip the instructions */
		ast_set_flag(&leave_options, OPT_SILENT);
		res = 0;
	}
	if (!res && !ast_test_flag(&leave_options, OPT_SILENT)) {
		res = ast_streamfile(chan, SOUND_INTRO, chan->language);
		if (!res)
			res = ast_waitstream(chan, ecodes);
		if (res == '#') {
			ast_set_flag(&leave_options, OPT_SILENT);
			res = 0;
		}
	}
	if (res > 0)
		ast_stopstream(chan);
	/* Check for a '*' here in case the caller wants to escape from voicemail to something
	   other than the operator -- an automated attendant or mailbox login for example */
	if (res == '*') {
		chan->exten[0] = 'a';
		chan->exten[1] = '\0';
		if (!ast_strlen_zero(vmu->exit)) {
			ast_copy_string(chan->context, vmu->exit, sizeof(chan->context));
		} else if (ausemacro && !ast_strlen_zero(chan->macrocontext)) {
			ast_copy_string(chan->context, chan->macrocontext, sizeof(chan->context));
		}
		chan->priority = 0;
		free_user(vmu);
		pbx_builtin_setvar_helper(chan, "MINIVMGREETSTATUS", "USEREXIT");
		return 0;
	}

	/* Check for a '0' here */
	if (res == '0') {
		if(ouseexten || ousemacro) {
			chan->exten[0] = 'o';
			chan->exten[1] = '\0';
			if (!ast_strlen_zero(vmu->exit)) {
				ast_copy_string(chan->context, vmu->exit, sizeof(chan->context));
			} else if (ousemacro && !ast_strlen_zero(chan->macrocontext)) {
				ast_copy_string(chan->context, chan->macrocontext, sizeof(chan->context));
			}
			ast_play_and_wait(chan, "transfer");
			chan->priority = 0;
			free_user(vmu);
			pbx_builtin_setvar_helper(chan, "MINIVMGREETSTATUS", "USEREXIT");
		}
		return 0;
	}
	if (res < 0) {
		free_user(vmu);
		pbx_builtin_setvar_helper(chan, "MINIVMGREETSTATUS", "FAILED");
		return -1;
	}

	pbx_builtin_setvar_helper(chan, "MINIVMGREETSTATUS", "SUCCESS");

	/* Ok, we're ready to rock and roll. Return to dialplan */
	LOCAL_USER_REMOVE(u);

	return res;

}

/*! \brief Dialplan core function */
static int minivm_exec(struct ast_channel *chan, void *data)
{
	int res = 0;
	struct localuser *u;
	char *tmp;
	struct leave_vm_options leave_options;
	int argc;
	char *argv[2];
	struct ast_flags flags = { 0 };
	char *opts[OPT_ARG_ARRAY_SIZE];
	
	LOCAL_USER_ADD(u);
	
	memset(&leave_options, 0, sizeof(leave_options));

	/* Answer channel if it's not already answered */
	if (chan->_state != AST_STATE_UP)
		ast_answer(chan);

	if (ast_strlen_zero(data))  {
		ast_log(LOG_ERROR, "Minivm needs at least an account argument \n");
		LOCAL_USER_REMOVE(u);
		return -1;
	}
	tmp = ast_strdupa((char *)data);
	if (!tmp) {
		ast_log(LOG_ERROR, "Out of memory\n");
		LOCAL_USER_REMOVE(u);
		return -1;
	}
	argc = ast_app_separate_args(tmp, '|', argv, sizeof(argv) / sizeof(argv[0]));
	if (argc == 2) {
		if (ast_app_parse_options(minivm_app_options, &flags, opts, argv[1])) {
			LOCAL_USER_REMOVE(u);
			return -1;
		}
		ast_copy_flags(&leave_options, &flags, OPT_SILENT | OPT_BUSY_GREETING | OPT_UNAVAIL_GREETING | OPT_PRIORITY_JUMP);
		if (ast_test_flag(&flags, OPT_RECORDGAIN)) {
			int gain;

			if (sscanf(opts[OPT_ARG_RECORDGAIN], "%d", &gain) != 1) {
				ast_log(LOG_WARNING, "Invalid value '%s' provided for record gain option\n", opts[OPT_ARG_RECORDGAIN]);
				LOCAL_USER_REMOVE(u);
				return -1;
			} else 
				leave_options.record_gain = (signed char) gain;
		}
	} 

	/* Now run the appliation and good luck to you! */
	res = leave_voicemail(chan, argv[0], &leave_options);

	if (res == ERROR_LOCK_PATH) {
		ast_log(LOG_ERROR, "Could not leave voicemail. The path is already locked.\n");
		/*Send the call to n+101 priority, where n is the current priority*/
		if (ast_test_flag(&leave_options, OPT_PRIORITY_JUMP) || option_priority_jumping)
			if (ast_goto_if_exists(chan, chan->context, chan->exten, chan->priority + 101))
				ast_log(LOG_WARNING, "Extension %s, priority %d doesn't exist.\n", chan->exten, chan->priority + 101);
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
		res = 0;
	}
	pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "SUCCESS");
	
	LOCAL_USER_REMOVE(u);

	return res;
}

static void free_zone(struct minivm_zone *z)
{
	free(z);
}

/*! \brief Append new mailbox to mailbox list from configuration file */
static int create_vmaccount(char *name, struct ast_variable *var, int realtime)
{
	struct minivm_user *vmu;
	char *domain;
	char *username;
	char accbuf[BUFSIZ];

	if (option_debug > 2)
		ast_log(LOG_DEBUG, "Creating static account for [%s]\n", name);

	ast_copy_string(accbuf, name, sizeof(accbuf));
	username = accbuf;
	domain = strchr(accbuf, '@');
	if (domain) {
		*domain = '\0';
		domain++;
	}
	if (ast_strlen_zero(domain)) {
		ast_log(LOG_ERROR, "No domain given for mini-voicemail account %s. Not configured.\n", name);
		return 0;
	}

	if (option_debug > 2)
		ast_log(LOG_DEBUG, "Creating static account for user %s domain %s\n", username, domain);

	/* Allocate user account */
	vmu = calloc(1, sizeof(struct minivm_user));
	if (!vmu)
		return 0;
	
	ast_copy_string(vmu->domain, domain, sizeof(vmu->domain));
	ast_copy_string(vmu->username, username, sizeof(vmu->username));

	populate_defaults(vmu);

	if (option_debug > 2)
		ast_log(LOG_DEBUG, "...Configuring account %s\n", name);

	while (var) {
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "---- Configuring %s = %s for account %s\n", var->name, var->value, name);
		if (!strcasecmp(var->name, "serveremail")) {
			ast_copy_string(vmu->serveremail, var->value, sizeof(vmu->serveremail));
		} else if (!strcasecmp(var->name, "domain")) {
			ast_copy_string(vmu->domain, var->value, sizeof(vmu->domain));
		} else if (!strcasecmp(var->name, "language")) {
			ast_copy_string(vmu->language, var->value, sizeof(vmu->language));
		} else if (!strcasecmp(var->name, "zone")) {
			ast_copy_string(vmu->zonetag, var->value, sizeof(vmu->zonetag));
		} else if (!strcasecmp(var->name, "envelope")) {
			ast_set2_flag(vmu, ast_true(var->value), MVM_ENVELOPE);	
		} else if (!strcasecmp(var->name, "etemplate")) {
			ast_copy_string(vmu->etemplate, var->value, sizeof(vmu->etemplate));
		} else if (!strcasecmp(var->name, "ptemplate")) {
			ast_copy_string(vmu->ptemplate, var->value, sizeof(vmu->ptemplate));
		} else if (!strcasecmp(var->name, "fullname")) {
			ast_copy_string(vmu->fullname, var->value, sizeof(vmu->fullname));
		} else if (!strcasecmp(var->name, "pager")) {
			ast_copy_string(vmu->pager, var->value, sizeof(vmu->pager));
		} else if (!strcasecmp(var->name, "volgain")) {
			sscanf(var->value, "%lf", &vmu->volgain);
		} else {
			ast_log(LOG_ERROR, "Unknown configuration option for minivm account %s : %s\n", name, var->name);
		}
		var = var->next;
	}
	if (option_debug > 2)
		ast_log(LOG_DEBUG, "...Linking account %s\n", name);
	
	AST_LIST_LOCK(&minivm_users);
	AST_LIST_INSERT_TAIL(&minivm_users, vmu, list);
	AST_LIST_UNLOCK(&minivm_users);

	global_stats.voicemailaccounts++;

	if (option_debug > 1)
		ast_log(LOG_DEBUG, "MINIVM :: Created account %s@%s - tz %s etemplate %s %s\n", username, domain, ast_strlen_zero(vmu->zonetag) ? "" : vmu->zonetag, ast_strlen_zero(vmu->etemplate) ? "" : vmu->etemplate, realtime ? "(realtime)" : "");
	return 0;
}

/*! \brief Clear list of timezones */
static void timezone_destroy_list(void)
{
	struct minivm_zone *this;
	AST_LIST_LOCK(&minivm_zones);
	while ((this = AST_LIST_REMOVE_HEAD(&minivm_zones, list))) 
		free(this);
		
	AST_LIST_UNLOCK(&minivm_zones);
}

/*! \brief Add time zone to memory list */
static int timezone_add(char *zonename, char *config)
{

	struct minivm_zone *newzone;
	char *msg_format, *timezone;

	newzone = malloc(sizeof(struct minivm_zone));
	if (newzone == NULL)
		return 0;

	msg_format = ast_strdupa(config);
	if (msg_format == NULL) {
		ast_log(LOG_WARNING, "Out of memory.\n");
		free(newzone);
		return 0;
	}

	timezone = strsep(&msg_format, "|");
	if (!msg_format) {
		ast_log(LOG_WARNING, "Invalid timezone definition : %s\n", zonename);
		free(newzone);
		return 0;
	}
			
	ast_copy_string(newzone->name, zonename, sizeof(newzone->name));
	ast_copy_string(newzone->timezone, timezone, sizeof(newzone->timezone));
	ast_copy_string(newzone->msg_format, msg_format, sizeof(newzone->msg_format));

	AST_LIST_LOCK(&minivm_zones);
	AST_LIST_INSERT_TAIL(&minivm_zones, newzone, list);
	AST_LIST_UNLOCK(&minivm_zones);

	global_stats.timezones++;

	return 0;
}

/*! \brief Parse emailbody template from configuration file */
static char *parse_emailbody(char *configuration)
{
	char *tmpread, *tmpwrite;
	char *emailbody = strdup(configuration);

	/* substitute strings \t and \n into the apropriate characters */
	tmpread = tmpwrite = configuration;
	while ((tmpwrite = strchr(tmpread,'\\'))) {
	       int len = strlen("\n");
	       switch (tmpwrite[1]) {
	       case 'n':
		      strncpy(tmpwrite+len, tmpwrite+2, strlen(tmpwrite+2)+1);
		      strncpy(tmpwrite, "\n", len);
		      break;
	       case 't':
		      strncpy(tmpwrite+len, tmpwrite+2, strlen(tmpwrite+2)+1);
		      strncpy(tmpwrite, "\t", len);
		      break;
	       default:
		      ast_log(LOG_NOTICE, "Substitution routine does not support this character: %c\n", tmpwrite[1]);
	       }
	       tmpread = tmpwrite + len;
	}
	return emailbody;	
}

/*! \brief Apply general configuration options */
static int apply_general_options(struct ast_variable *var)
{
	int error = 0;

	while (var) {
		/* Mail command */
		if (!strcmp(var->name, "mailcmd")) {
			ast_copy_string(global_mailcmd, var->value, sizeof(global_mailcmd)); /* User setting */
		} else if (!strcmp(var->name, "maxsilence")) {
			global_maxsilence = atoi(var->value);
			if (global_maxsilence > 0)
				global_maxsilence *= 1000;
		} else if (!strcmp(var->name, "externnotify")) {
			
			/* External voicemail notify application */
			ast_copy_string(global_externnotify, var->value, sizeof(global_externnotify));
		} else if (!strcmp(var->name, "silencetreshold")) {
			/* Silence treshold */
			global_silencethreshold = atoi(var->value);
		} else if (!strcmp(var->name, "maxmessage")) {
			int x;
			if (sscanf(var->value, "%d", &x) == 1) {
				global_vmmaxmessage = x;
			} else {
				error ++;
				ast_log(LOG_WARNING, "Invalid max message time length\n");
			}
		} else if (!strcmp(var->name, "minmessage")) {
			int x;
			if (sscanf(var->value, "%d", &x) == 1) {
				global_vmminmessage = x;
				if (global_maxsilence <= global_vmminmessage)
					ast_log(LOG_WARNING, "maxsilence should be less than minmessage or you may get empty messages\n");
			} else {
				error ++;
				ast_log(LOG_WARNING, "Invalid min message time length\n");
			}
		} else if (!strcmp(var->name, "format")) {
			ast_copy_string(default_vmformat, var->value, sizeof(default_vmformat));
		} else if (!strcmp(var->name, "maxgreet")) {
			int x;
			if (sscanf(var->value, "%d", &x) == 1)
				maxgreet = x;
			else  {
				ast_log(LOG_WARNING, "Invalid max message greeting length\n");
				error ++;
			}
		} else if (!strcmp(var->name, "review")) {
			ast_set2_flag((&globalflags), ast_true(var->value), MVM_REVIEW);	
		} else if (!strcmp(var->name, "operator")) {
			ast_set2_flag((&globalflags), ast_true(var->value), MVM_OPERATOR);	
		}
		var = var->next;
	}
	return error;
}

/*! \brief Load minivoicemail configuration */
static int load_config(void)
{
	struct minivm_user *cur;
	struct minivm_zone *zcur;
	struct ast_config *cfg;
	struct ast_variable *var;
	char *cat;
	char *s;
	int error = 0;

	cfg = ast_config_load(VOICEMAIL_CONFIG);
	ast_mutex_lock(&minivmlock);

	AST_LIST_LOCK(&minivm_users);
	while ((cur = AST_LIST_REMOVE_HEAD(&minivm_users, list))) {
		ast_set_flag(cur, MVM_ALLOCED);	
		free_user(cur);
	}
	AST_LIST_UNLOCK(&minivm_users);

	/* Free all zones */
	AST_LIST_LOCK(&minivm_zones);
	while ((zcur = AST_LIST_REMOVE_HEAD(&minivm_zones, list))) {
		free_zone(zcur);
	}
	AST_LIST_UNLOCK(&minivm_zones);

	/* First, set some default settings */
	global_externnotify[0] = '\0';
	global_silencethreshold = 256;
	global_vmmaxmessage = 2000;
	global_vmminmessage = 0;
	strcpy(global_mailcmd, SENDMAIL);
	global_maxsilence = 0;
	global_saydurationminfo = 2;
	ast_copy_string(default_vmformat, "wav", sizeof(default_vmformat));
	ast_set2_flag((&globalflags), FALSE, MVM_REVIEW);	
	ast_set2_flag((&globalflags), FALSE, MVM_OPERATOR);	
	strcpy(global_charset, "ISO-8859-1");
	struct minivm_message *template;
	/* Reset statistics */
	memset(&global_stats, 0, sizeof(struct minivm_stats));
	global_stats.reset = time(NULL);

	if (emailbody) {
		free(emailbody);
		emailbody = NULL;
	}
	if (emailsubject) {
		free(emailsubject);
		emailsubject = NULL;
	}
	if (pagerbody) {
		free(pagerbody);
		pagerbody = NULL;
	}
	if (pagersubject) {
		free(pagersubject);
		pagersubject = NULL;
	}

	/* Make sure we could load configuration file */
	if (!cfg) {
		ast_log(LOG_WARNING, "Failed to load configuration file. Module activated with default settings.\n");
		return 0;
	}


	/* General settings */

	cat = ast_category_browse(cfg, NULL);
	while (cat) {
		if (option_debug > 2)
			ast_log(LOG_DEBUG, "Found configuration section [%s]\n", cat);
		if (!strcasecmp(cat, "general")) {
			/* Nothing right now */
			error += apply_general_options(ast_variable_browse(cfg, cat));
		} else if (!strncasecmp(cat, "template-", 9))  {
			/* Template */
			char *name = cat + 9;

			/* Now build and link template to list */
			error += message_template_build(name, ast_variable_browse(cfg, cat));
		} else {
			var = ast_variable_browse(cfg, cat);
			if (!strcasecmp(cat, "zonemessages")) {
				/* Timezones in this context */
				while (var) {
					timezone_add(var->name, var->value);
					var = var->next;
				}
			} else {
				/* Create mailbox from this */
				error += create_vmaccount(cat, var, FALSE);
			}
		}
		/* Find next section in configuration file */
		cat = ast_category_browse(cfg, cat);
	}

	/* Configure the default email template */
	message_template_build("email-default", NULL);
	template = message_template_find("email-default");

	//pbx_builtin_setvar_helper(ast, "MMVM_NAME", vmu->fullname);
	//pbx_builtin_setvar_helper(ast, "MMVM_DUR", dur);
	//pbx_builtin_setvar_helper(ast, "MMVM_DOMAIN", vmu->domain);
	//pbx_builtin_setvar_helper(ast, "MMVM_USERNAME", vmu->username);
	//pbx_builtin_setvar_helper(ast, "MMVM_CALLERID", ast_callerid_merge(callerid, sizeof(callerid), cidname, cidnum, "Unknown Caller"));
	//pbx_builtin_setvar_helper(ast, "MMVM_CIDNAME", (cidname ? cidname : "an unknown caller"));
	//pbx_builtin_setvar_helper(ast, "MMVM_CIDNUM", (cidnum ? cidnum : "an unknown caller"));
	//pbx_builtin_setvar_helper(ast, "MMVM_DATE", date);

	/* Load date format config for voicemail mail */
	if ((s = ast_variable_retrieve(cfg, "general", "emaildateformat"))) 
		ast_copy_string(template->dateformat, s, sizeof(template->dateformat));
	if ((s = ast_variable_retrieve(cfg, "general", "emailfromstring")))
		ast_copy_string(template->fromstring, s, sizeof(template->fromstring));
	if ((s = ast_variable_retrieve(cfg, "general", "emailcharset")))
		ast_copy_string(template->charset, s, sizeof(template->charset));
	else
		ast_copy_string(template->charset, "ISO-8859-1", sizeof(template->charset));
	if ((s = ast_variable_retrieve(cfg, "general", "emailsubject"))) 
		ast_copy_string(template->subject,s,sizeof(template->subject));
	else
		ast_copy_string(template->subject, "New message in mailbox ${MVM_USERNAME}@${MVM_DOMAIN}", sizeof(template->subject));
	if ((s = ast_variable_retrieve(cfg, "general", "emailbody"))) 
		template->body = parse_emailbody(s);

	message_template_build("pager-default", NULL);
	template = message_template_find("pager-default");
	if ((s = ast_variable_retrieve(cfg, "general", "pagerfromstring")))
		ast_copy_string(template->fromstring, s, sizeof(template->fromstring));
	if ((s = ast_variable_retrieve(cfg, "general", "pagercharset")))
		ast_copy_string(template->charset, s, sizeof(template->charset));
	else
		ast_copy_string(template->charset, "ISO-8859-1", sizeof(template->charset));
	if ((s = ast_variable_retrieve(cfg, "general", "pagersubject")))
		ast_copy_string(template->subject,s,sizeof(template->subject));
	else
		ast_copy_string(template->subject, "New message in mailbox ${MVM_USERNAME}@${MVM_DOMAIN}", sizeof(template->subject));
	if ((s = ast_variable_retrieve(cfg, "general", "pagerbody"))) 
		template->body = parse_emailbody(s);

	if (error)
		ast_log(LOG_ERROR, "--- A total of %d errors found in mini-voicemail configuration\n", error);

	ast_mutex_unlock(&minivmlock);
	ast_config_destroy(cfg);
	return 0;
}




static const char minivm_show_users_help[] =
"Usage: minivm show users\n"
"       Lists all mailboxes currently set up\n";

static const char minivm_show_zones_help[] =
"Usage: minivm show zones\n"
"       Lists zone message formats\n";

static const char minivm_show_templates_help[] =
"Usage: minivm show templates\n"
"       Lists message templates for e-mail, paging and IM\n";

static const char minivm_show_stats_help[] =
"Usage: minivm show stats\n"
"       List Mini-Voicemail counters\n";

static const char minivm_reload_help[] =
"Usage: minivm reload\n"
"       Reload mini-voicemail configuration and reset statistics\n";

/*! \brief CLI routine for listing templates */
static int handle_minivm_show_templates(int fd, int argc, char *argv[])
{
	struct minivm_message *this;
	char *output_format = "%-15s %-12s %-50s\n";
	int count = 0;

	if (argc > 3)
		return RESULT_SHOWUSAGE;

	AST_LIST_LOCK(&message_templates);
	if (AST_LIST_EMPTY(&message_templates)) {
		ast_cli(fd, "There are no message templates defined\n");
		AST_LIST_UNLOCK(&message_templates);
		return RESULT_FAILURE;
	}
	ast_cli(fd, output_format, "Template name", "Charset", "Subject");
	ast_cli(fd, output_format, "-------------", "-------", "-------");
	AST_LIST_TRAVERSE(&message_templates, this, list) {
		ast_cli(fd, output_format, this->name, this->charset ? this->charset : "-", this->subject ? this->subject : "-");
		count++;
	}
	AST_LIST_UNLOCK(&message_templates);
	ast_cli(fd, "\n * Total: %d minivoicemail message templates\n", count);
	return RESULT_SUCCESS;
}

static int handle_minivm_show_users(int fd, int argc, char *argv[])
{
	struct minivm_user *vmu;
	char *output_format = "%-23s %-15s %-15s %-10s %-10s\n";
	int count = 0;

	if ((argc < 3) || (argc > 5) || (argc == 4))
		return RESULT_SHOWUSAGE;
	if ((argc == 5) && strcmp(argv[3],"for"))
		return RESULT_SHOWUSAGE;

	AST_LIST_LOCK(&minivm_users);
	if (AST_LIST_EMPTY(&minivm_users)) {
		ast_cli(fd, "There are no voicemail users currently defined\n");
		AST_LIST_UNLOCK(&minivm_users);
		return RESULT_FAILURE;
	}
	ast_cli(fd, output_format, "User", "E-Template", "P-template", "Zone", "Format");
	ast_cli(fd, output_format, "----", "----------", "----------", "----", "------");
	AST_LIST_TRAVERSE(&minivm_users, vmu, list) {
		char tmp[256] = "";


		if ((argc == 3) || ((argc == 5) && !strcmp(argv[4], vmu->domain))) {
			count++;
			snprintf(tmp, sizeof(tmp), "%s@%s", vmu->username, vmu->domain);
			ast_cli(fd, output_format, tmp, vmu->etemplate ? vmu->etemplate : "-", 
				vmu->ptemplate ? vmu->ptemplate : "-",
				vmu->zonetag ? vmu->zonetag : "-", 
				vmu->attachfmt ? vmu->attachfmt : "-");
		}
	}
	AST_LIST_UNLOCK(&minivm_users);
	ast_cli(fd, "\n * Total: %d minivoicemail accounts\n", count);
	return RESULT_SUCCESS;
}

/*! \brief Show a list of voicemail zones in the CLI */
static int handle_minivm_show_zones(int fd, int argc, char *argv[])
{
	struct minivm_zone *zone;
	char *output_format = "%-15s %-20s %-45s\n";
	int res = RESULT_SUCCESS;

	if (argc != 3)
		return RESULT_SHOWUSAGE;

	AST_LIST_LOCK(&minivm_zones);
	if (!AST_LIST_EMPTY(&minivm_zones)) {
		ast_cli(fd, output_format, "Zone", "Timezone", "Message Format");
		ast_cli(fd, output_format, "----", "--------", "--------------");
		AST_LIST_TRAVERSE(&minivm_zones, zone, list) {
			ast_cli(fd, output_format, zone->name, zone->timezone, zone->msg_format);
		}
	} else {
		ast_cli(fd, "There are no voicemail zones currently defined\n");
		res = RESULT_FAILURE;
	}
	AST_LIST_UNLOCK(&minivm_zones);

	return res;
}

/* Forward declaration */
int reload(void);

/*! \brief Reload cofiguration */
static int handle_minivm_reload(int fd, int argc, char *argv[])
{
	reload();
	ast_cli(fd, "\n-- Mini voicemail re-configured \n");
	return RESULT_SUCCESS;
}

static char *complete_minivm_show_users(const char *line, const char *word, int pos, int state)
{
	int which = 0;
	int wordlen;
	struct minivm_user *vmu;
	const char *domain = "";

	/* 0 - show; 1 - voicemail; 2 - users; 3 - for; 4 - <domain> */
	if (pos > 4)
		return NULL;
	if (pos == 3)
		return (state == 0) ? strdup("for") : NULL;
	wordlen = strlen(word);
	AST_LIST_TRAVERSE(&minivm_users, vmu, list) {
		if (!strncasecmp(word, vmu->domain, wordlen)) {
			if (domain && strcmp(domain, vmu->domain) && ++which > state)
				return strdup(vmu->domain);
			/* ignore repeated domains ? */
			domain = vmu->domain;
		}
	}
	return NULL;
}

/*! \brief Show stats */
static int handle_minivm_show_stats(int fd, int argc, char *argv[])
{
	ast_cli(fd, "* Mini-Voicemail statistics\n");
	ast_cli(fd, "  -------------------------\n");
	ast_cli(fd, "\n");
	ast_cli(fd, "  Voicemail accounts:        %d\n", global_stats.voicemailaccounts);
	ast_cli(fd, "  Templates:                 %d\n", global_stats.templates);
	ast_cli(fd, "  Timezones:                 %d\n", global_stats.timezones);
	ast_cli(fd, "\n");
	return RESULT_SUCCESS;
}

static struct ast_cli_entry cli_voicemail[] = {
	{ { "minivm", "show", "users", NULL },
	handle_minivm_show_users, "List defined mini-voicemail boxes",
	minivm_show_users_help, complete_minivm_show_users, NULL },

	{ { "minivm", "list", "zones", NULL },
	handle_minivm_show_zones, "List zone message formats",
	minivm_show_zones_help, NULL, NULL },

	{ { "minivm", "list", "templates", NULL },
	handle_minivm_show_templates, "List message templates",
	minivm_show_templates_help, NULL, NULL },

	{ { "minivm", "reload", NULL, NULL },
	handle_minivm_reload, "Reload Mini-voicemail configuration",
	minivm_reload_help, NULL, NULL },

	{ { "minivm", "show", "stats", NULL },
	handle_minivm_show_stats, "Show som mini-voicemail stats",
	minivm_show_stats_help, NULL, NULL },
};


/*! \brief Load mini voicemail module */
int load_module(void)
{
	int res;

	res = ast_register_application(app, minivm_exec, synopsis_vm, descrip_vm);
	res = ast_register_application(app_greet, minivm_prompt_exec, synopsis_vm_greet, descrip_vm_greet);

	if (res)
		return(res);

	if ((res = load_config()))
		return(res);

	ast_cli_register_multiple(cli_voicemail, sizeof(cli_voicemail)/sizeof(cli_voicemail[0]));

	/* compute the location of the voicemail spool directory */
	snprintf(MVM_SPOOL_DIR, sizeof(MVM_SPOOL_DIR), "%s/voicemail/", ast_config_AST_SPOOL_DIR);

	return res;
}

/*! \brief Reload mini voicemail module */
int reload(void)
{
	/* Destroy lists to reconfigure */	
	message_destroy_list();		/* Destroy list of voicemail message templates */
	timezone_destroy_list();	/* Destroy list of timezones */
	vmaccounts_destroy_list();	/* Destroy list of voicemail accounts */
	return(load_config());
}

/*! \brief Unload mini voicemail module */
int unload_module(void)
{
	int res;
	
	res = ast_unregister_application(app);
	res = ast_unregister_application(app_greet);
	ast_cli_unregister_multiple(cli_voicemail, sizeof(cli_voicemail)/sizeof(cli_voicemail[0]));
	ast_uninstall_vm_functions();
	message_destroy_list();		/* Destroy list of voicemail message templates */
	timezone_destroy_list();	/* Destroy list of timezones */
	vmaccounts_destroy_list();	/* Destroy list of voicemail accounts */

	
	STANDARD_HANGUP_LOCALUSERS;

	return res;
}


int usecount(void)
{
	int res;
	STANDARD_USECOUNT(res);
	return res;
}

char *description(void)
{
	return tdesc;
}

char *key()
{
	return ASTERISK_GPL_KEY;
}

