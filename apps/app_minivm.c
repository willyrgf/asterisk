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
 * \brief Markodian Mail - A Minimal Voicemail System
 * 
 * based on the Comedian Mail voicemail system.
 * 
 * \par See also
 * \arg \ref Config_vm
 * \ingroup applications
 * \page App_minivm	Markodian Mail - A minimal voicemail system
 *	Just play prompts, and mails voicemail message by e-mail
 *	- General configuration in minivm.conf
 *	- Users in realtime or configuration file
 *		
 *	Voicemail accounts are identified 
 *	by userid and domain
 *
 *	Configuration :
 *
 *	[account_name]
 *	user=olle
 *	domain=edvina.net
 *	email=oej@edvina.net
 *	template=swedish.txt
 *	zone=se
 *	language=se
 *	notifyapp=/bin/pagebyjabber
 *	xmppuri=jabber:oej@asterisk.org
 *	fromaddress=Edvina Voicemail <voicemail@edvina.net>
 *	
 */

/*! \page App_minivm_todo Markodian Minimail - todo
 */

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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

/*--------------------- CUT HERE ---------------------------------
	This code stays for copy/paste 
	Will be removed finally
*/
#ifdef OLD_VOICEMAIL_WAS_PAINFUL_AND_WILL_BE_DELETED


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

static char *addesc = "Comedian Mail";
static char *synopsis_vm = "Leave a Voicemail message";

struct minivm_user *users;
struct minivm_user *usersl;
struct vm_zone *zones = NULL;
struct vm_zone *zonesl = NULL;
static int maxsilence;
static int maxmsg;
static int silencethreshold = 128;
static char serveremail[80];
static char mailcmd[160];	/* Configurable mail cmd */
static char externnotify[160]; 

static char vmfmts[80];
static int vmminmessage;
static int vmmaxmessage;
static int maxgreet;
static int skipms;

static struct ast_flags globalflags = {0};

static int global_saydurationminfo;

static char dialcontext[AST_MAX_CONTEXT];
static char callcontext[AST_MAX_CONTEXT];
static char exitcontext[AST_MAX_CONTEXT];

static char cidinternalcontexts[MAX_NUM_CID_CONTEXTS][64];


STANDARD_LOCAL_USER;

LOCAL_USER_DECL;


static void apply_option(struct minivm_user *vmu, const char *var, const char *value)
{
	int x;
	if (!strcasecmp(var, "attach")) {
		ast_set2_flag(vmu, ast_true(value), VM_ATTACH);	
	} else if (!strcasecmp(var, "serveremail")) {
		ast_copy_string(vmu->serveremail, value, sizeof(vmu->serveremail));
	} else if (!strcasecmp(var, "language")) {
		ast_copy_string(vmu->language, value, sizeof(vmu->language));
	} else if (!strcasecmp(var, "tz")) {
		ast_copy_string(vmu->zonetag, value, sizeof(vmu->zonetag));
	} else if (!strcasecmp(var, "delete") || !strcasecmp(var, "deletevoicemail")) {
		ast_set2_flag(vmu, ast_true(value), VM_DELETE);	
	} else if (!strcasecmp(var, "saycid")){
		ast_set2_flag(vmu, ast_true(value), VM_SAYCID);	
	} else if (!strcasecmp(var,"sendvoicemail")){
		ast_set2_flag(vmu, ast_true(value), VM_SVMAIL);	
	} else if (!strcasecmp(var, "envelope")){
		ast_set2_flag(vmu, ast_true(value), VM_ENVELOPE);	
	} else if (!strcasecmp(var, "options")) {
		apply_options(vmu, value);
	}
}

static int remove_file(char *dir, int msgnum)
{
	char fn[PATH_MAX];
	char full_fn[PATH_MAX];
	char msgnums[80];
	
	if (msgnum > -1) {
		snprintf(msgnums, sizeof(msgnums), "%d", msgnum);
		make_file(fn, sizeof(fn), dir, msgnum);
	} else
		ast_copy_string(fn, dir, sizeof(fn));
	ast_filedelete(fn, NULL);	
	snprintf(full_fn, sizeof(full_fn), "%s.txt", fn);
	unlink(full_fn);
	return 0;
}


static int get_date(char *s, int len)
{
	struct tm tm;
	time_t t;
	t = time(0);
	localtime_r(&t,&tm);
	return strftime(s, len, "%a %b %e %r %Z %Y", &tm);
}

static void free_user(struct minivm_user *vmu)
{
	if (ast_test_flag(vmu, VM_ALLOCED))
		free(vmu);
}

static void free_zone(struct vm_zone *z)
{
	free(z);
}

struct leave_vm_options {
	unsigned int flags;
	signed char record_gain;
};


#endif
/* ---------------------------- CUT HERE ------------------------------- */

/* Many of these options doesn't apply to minivm */
#define VM_REVIEW		(1 << 0)
#define VM_OPERATOR		(1 << 1)
#define VM_SAYCID		(1 << 2)
#define VM_SVMAIL		(1 << 3)
#define VM_ENVELOPE		(1 << 4)
#define VM_SAYDURATION		(1 << 5)
#define VM_SKIPAFTERCMD 	(1 << 6)
#define VM_FORCENAME		(1 << 7)	/*!< Have new users record their name */
#define VM_FORCEGREET		(1 << 8)	/*!< Have new users record their greetings */
#define VM_PBXSKIP		(1 << 9)
#define VM_DIRECFORWARD 	(1 << 10)	/*!< directory_forward */
#define VM_ATTACH		(1 << 11)
#define VM_DELETE		(1 << 12)
#define VM_ALLOCED		(1 << 13)
#define VM_SEARCH		(1 << 14)

/* Default mail command to mail voicemail. Change it with the
    mailcmd= command in voicemail.conf */
#define SENDMAIL "/usr/sbin/sendmail -t"
#define INTRO "vm-intro"
#define MAXMSG 100
#define MAXMSGLIMIT 9999
#define BASEMAXINLINE 256
#define BASELINELEN 72
#define BASEMAXINLINE 256
#define eol "\r\n"

#define MAX_DATETIME_FORMAT	512
#define MAX_NUM_CID_CONTEXTS 10

#define ERROR_LOCK_PATH		-100
#define COMMAND_TIMEOUT 5000
#define	VOICEMAIL_DIR_MODE	0700
#define	VOICEMAIL_FILE_MODE	0600
#define	CHUNKSIZE	65536

#define VOICEMAIL_CONFIG "minivm.conf"
#define VOICEMAIL_TEMPLATE_CONFIG "minivmtemplates.conf"
#define ASTERISK_USERNAME "asterisk"

static char *tdesc = "Comedian Mail (Voicemail System)";
static char *app = "VoiceMail";		 /* Leave a message */

/*! Structure for linked list of users 
*/
struct minivm_user {
	char username[AST_MAX_CONTEXT];	/*!< Mailbox username */
	char domain[AST_MAX_CONTEXT];	/*!< Voicemail domain */
	char password[80];		/*!< Secret pin code, numbers only */
	char fullname[80];		/*!< Full name, for directory app */
	char email[80];			/*!< E-mail address */
	char pager[80];			/*!< E-mail address to pager (no attachment) */
	char serveremail[80];		/*!< From: Mail address */
	char mailcmd[160];		/*!< Configurable mail command */
	char language[MAX_LANGUAGE];    /*!< Config: Language setting */
	char zonetag[80];		/*!< Time zone */
	char uniqueid[20];		/*!< Unique integer identifier */
	char exitopt[80];
	unsigned int flags;		/*!< VM_ flags */	
	int saydurationm;
	int maxmsg;			/*!< Maximum number of msgs per folder for this mailbox */
	AST_LIST_ENTRY(minivm_user) list;	
};

/*! \brief Linked list of e-mail templates in various languages */
struct minivm_email {
	char	templatename[80];	/*!< Template name */
	char	*body;			/*!< Body of this template */
	char	*subject;		/*!< Subject of e-mail */
	char	fromstring[100];
	char	emailtitle[100];
	char	charset[32];
	char	dateformat[80];
	int	attachment;		/*!< Attachment of media yes/no */
	AST_LIST_ENTRY(minivm_email) list;	/*!< List mechanics */
};

static AST_LIST_HEAD_STATIC(email_templates, minivm_email);	/*!< The list of e-mail templates */


/*! \brief Structure for base64 encoding */
struct b64_baseio {
	int iocp;
	int iolen;
	int linelength;
	int ateof;
	unsigned char iobuf[BASEMAXINLINE];
};



/*! Voicemail time zones */
struct minivm_zone {
	char name[80];	/* Name of this time zone */
	char timezone[80];
	char msg_format[512];
	struct minivm_zone *next;
};


AST_MUTEX_DEFINE_STATIC(minivmlock);
struct minivm_zone *zones = NULL;
struct minivm_zone *zonesl = NULL;

static int maxsilence;
static int maxmsg;
static int silencethreshold = 128;
static char serveremail[80];
static char mailcmd[160];	/* Configurable mail cmd */
static char externnotify[160]; 

static char vmfmts[80];
static int maxgreet;
static int skipms;

static struct ast_flags globalflags = {0};

static int global_saydurationminfo;

struct minivm_email mailtemplate;
struct minivm_email pagertemplate;
static char *emailbody = NULL;
static char *emailsubject = NULL;
static char *pagerbody = NULL;
static char *pagersubject = NULL;

static char fromstring[100];
static char pagerfromstring[100];
static char emailtitle[100];
static char global_charset[32];

static char global_emaildateformat[32] = "%A, %B %d, %Y at %r";

STANDARD_LOCAL_USER;

LOCAL_USER_DECL;

static void apply_options(struct minivm_user *vmu, const char *options);

/*! \brief  The user list: Users and friends ---*/
static AST_LIST_HEAD_STATIC(minivm_accounts, minivm_user);

/*! \brief Say number and wait for input */
static int say_and_wait(struct ast_channel *chan, int num, char *language)
{
	int d;
	d = ast_say_number(chan, num, AST_DIGIT_ANY, language, (char *) NULL);
	return d;
}


/*! \brief read buffer from file (base64 conversion) */
static int b64_inbuf(struct b64_baseio *bio, FILE *fi)
{
	int l;

	if (bio->ateof)
		return 0;

	if ((l = fread(bio->iobuf, 1, BASEMAXINLINE,fi)) <= 0) {
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
	if (bio->linelength >= BASELINELEN) {
		if (fputs(eol,so) == EOF)
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
	unsigned char dtable[BASEMAXINLINE];
	int i,hiteof= 0;
	FILE *fi;
	struct b64_baseio bio;

	memset(&bio, 0, sizeof(bio));
	bio.iocp = BASEMAXINLINE;

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
	if (fputs(eol, so) == EOF)
		return 0;

	fclose(fi);

	return 1;
}

/*! \brief Prepare for voicemail template by adding channel variables 
	to the channel
*/
static void prep_email_sub_vars(struct ast_channel *ast, struct minivm_user *vmu, const char *domain, const char *mailbox, const char *cidnum, const char *cidname, const char *dur, const char *date)
{
	char callerid[256];
	/* Prepare variables for substition in email body and subject */
	pbx_builtin_setvar_helper(ast, "VM_NAME", vmu->fullname);
	pbx_builtin_setvar_helper(ast, "VM_DUR", dur);
	pbx_builtin_setvar_helper(ast, "VM_DOMAIN", domain);
	pbx_builtin_setvar_helper(ast, "VM_MAILBOX", mailbox);
	pbx_builtin_setvar_helper(ast, "VM_CALLERID", ast_callerid_merge(callerid, sizeof(callerid), cidname, cidnum, "Unknown Caller"));
	pbx_builtin_setvar_helper(ast, "VM_CIDNAME", (cidname ? cidname : "an unknown caller"));
	pbx_builtin_setvar_helper(ast, "VM_CIDNUM", (cidnum ? cidnum : "an unknown caller"));
	pbx_builtin_setvar_helper(ast, "VM_DATE", date);
}

static void populate_defaults(struct minivm_user *vmu)
{
	ast_copy_flags(vmu, (&globalflags), AST_FLAGS_ALL);	
	if (global_saydurationminfo)
		vmu->saydurationm = global_saydurationminfo;
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
static int sendpage(char *srcemail, char *pager, int msgnum, char *context, char *mailbox, char *cidnum, char *cidname, int duration, struct minivm_user *vmu)
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

	if (pfd > -1) {
		p = fdopen(pfd, "w");
		if (!p) {
			close(pfd);
			pfd = -1;
		}
	}

	if (p) {
		gethostname(host, sizeof(host)-1);
		if (strchr(srcemail, '@'))
			ast_copy_string(who, srcemail, sizeof(who));
		else {
			snprintf(who, sizeof(who), "%s@%s", srcemail, host);
		}
		snprintf(dur, sizeof(dur), "%d:%02d", duration / 60, duration % 60);
		time(&t);

		/* Does this user have a timezone specified? */
		if (!ast_strlen_zero(vmu->zonetag)) {
			/* Find the zone in the list */
			struct minivm_zone *z = zones;
			while (z) {
				if (!strcmp(z->name, vmu->zonetag)) {
					the_zone = z;
					break;
				}
				z = z->next;
			}
		}

		if (the_zone)
			ast_localtime(&t,&tm,the_zone->timezone);
		else
			ast_localtime(&t,&tm,NULL);

		strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", &tm);
		fprintf(p, "Date: %s\n", date);

		if (*pagerfromstring) {
			struct ast_channel *ast = ast_channel_alloc(0);
			if (ast) {
				char *passdata;
				int vmlen = strlen(fromstring)*3 + 200;
				if ((passdata = alloca(vmlen))) {
					memset(passdata, 0, vmlen);
					prep_email_sub_vars(ast, vmu, context,mailbox,cidnum, cidname,dur,date);
					pbx_substitute_variables_helper(ast,pagerfromstring,passdata,vmlen);
					fprintf(p, "From: %s <%s>\n",passdata,who);
				} else 
					ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
				ast_channel_free(ast);
			} else ast_log(LOG_WARNING, "Cannot allocate the channel for variables substitution\n");
		} else
			fprintf(p, "From: Asterisk PBX <%s>\n", who);
		fprintf(p, "To: %s\n", pager);
	       if (pagersubject) {
		       struct ast_channel *ast = ast_channel_alloc(0);
		       if (ast) {
			       char *passdata;
			       int vmlen = strlen(pagersubject)*3 + 200;
			       if ((passdata = alloca(vmlen))) {
				       memset(passdata, 0, vmlen);
				       prep_email_sub_vars(ast,vmu,context,mailbox,cidnum, cidname,dur,date);
				       pbx_substitute_variables_helper(ast,pagersubject,passdata,vmlen);
				       fprintf(p, "Subject: %s\n\n",passdata);
			       } else ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
			       ast_channel_free(ast);
		       } else ast_log(LOG_WARNING, "Cannot allocate the channel for variables substitution\n");
	       } else
		       fprintf(p, "Subject: New VM\n\n");
		strftime(date, sizeof(date), "%A, %B %d, %Y at %r", &tm);
	        if (pagerbody) {
		       struct ast_channel *ast = ast_channel_alloc(0);
		       if (ast) {
			       char *passdata;
			       int vmlen = strlen(pagerbody)*3 + 200;
			       if ((passdata = alloca(vmlen))) {
				       memset(passdata, 0, vmlen);
				       prep_email_sub_vars(ast,vmu,context,mailbox,cidnum, cidname,dur,date);
				       pbx_substitute_variables_helper(ast,pagerbody,passdata,vmlen);
				       fprintf(p, "%s\n",passdata);
			       } else ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
			       ast_channel_free(ast);
		       } else ast_log(LOG_WARNING, "Cannot allocate the channel for variables substitution\n");
	       } else {
		       fprintf(p, "New %s long msg in box %s\n"
				       "from %s, on %s", dur, mailbox, (cidname ? cidname : (cidnum ? cidnum : "unknown")), date);
	       }
		fclose(p);
		snprintf(tmp2, sizeof(tmp2), "( %s < %s ; rm -f %s ) &", mailcmd, tmp, tmp);
		ast_safe_system(tmp2);
		ast_log(LOG_DEBUG, "Sent page to %s with command '%s'\n", pager, mailcmd);
	} else {
		ast_log(LOG_WARNING, "Unable to launch '%s'\n", mailcmd);
		return -1;
	}
	return 0;
}

static struct minivm_user *find_user_realtime(struct minivm_user *ivm, const char *domain, const char *mailbox);


/*! \brief Find user from static memory object list */
static struct minivm_user *find_user(struct minivm_user *ivm, const char *domain, const char *mailbox)
{
	struct minivm_user *vmu = NULL, *cur;

	ast_mutex_lock(&minivmlock);

	AST_LIST_LOCK(&minivm_accounts);
	AST_LIST_TRAVERSE(&minivm_accounts, cur, list) {
		/* Is this the voicemail account we're looking for? */
		if (domain && (!strcasecmp(domain, cur->domain)) && (!strcasecmp(mailbox, cur->username)))
			break;
	}
	AST_LIST_UNLOCK(&minivm_accounts);

	if (cur) {
		if (ivm)
			vmu = ivm;
		else
			/* Make a copy, so that on a reload, we have no race */
			vmu = malloc(sizeof(struct minivm_user));
		if (vmu) {
			memcpy(vmu, cur, sizeof(struct minivm_user));
			ast_set2_flag(vmu, !ivm, VM_ALLOCED);	
		}
	} else
		vmu = find_user_realtime(ivm, domain, mailbox);
	ast_mutex_unlock(&minivmlock);
	return vmu;
}

/*! \brief Find user in realtime storage 
	Returns pointer to minivm_user structure
*/
static struct minivm_user *find_user_realtime(struct minivm_user *ivm, const char *domain, const char *mailbox)
{
	struct ast_variable *var, *tmp;
	struct minivm_user *retval;

	if (ivm)
		retval = ivm;
	else {
		retval = ast_calloc(sizeof(struct minivm_user));
		if (!retval)
			return NULL;
		ast_set_flag(retval, VM_ALLOCED);	
	}


	if (mailbox) 
		ast_copy_string(retval->mailbox, mailbox, sizeof(retval->mailbox));

	populate_defaults(retval);
	if (!domain && ast_test_flag((&globalflags), VM_SEARCH))
		var = ast_load_realtime("voicemail", "mailbox", mailbox, NULL);
	else
		var = ast_load_realtime("voicemail", "mailbox", mailbox, "domain", domain, NULL);
	if (!var) {
		if (!ivm) 
			free(retval);
		return NULL;
	}
	tmp = var;
	while(tmp) {
		printf("%s => %s\n", tmp->name, tmp->value);
		if (!strcasecmp(tmp->name, "password")) {
			ast_copy_string(retval->password, tmp->value, sizeof(retval->password));
		} else if (!strcasecmp(tmp->name, "uniqueid")) {
			ast_copy_string(retval->uniqueid, tmp->value, sizeof(retval->uniqueid));
		} else if (!strcasecmp(tmp->name, "pager")) {
			ast_copy_string(retval->pager, tmp->value, sizeof(retval->pager));
		} else if (!strcasecmp(tmp->name, "email")) {
			ast_copy_string(retval->email, tmp->value, sizeof(retval->email));
		} else if (!strcasecmp(tmp->name, "fullname")) {
			ast_copy_string(retval->fullname, tmp->value, sizeof(retval->fullname));
		} else if (!strcasecmp(tmp->name, "context")) {
			ast_copy_string(retval->context, tmp->value, sizeof(retval->context));
		} else
			apply_option(retval, tmp->name, tmp->value);
		tmp = tmp->next;
	} 
	ast_variables_destroy(var);
	return retval;
}

/*! Send voicemail with audio file as an attachment */
static int sendmail(char *srcemail, struct minivm_user *vmu, int msgnum, char *context, char *mailbox, char *cidnum, char *cidname, char *attach, char *format, int duration, int attach_user_voicemail)
{
	FILE *p = NULL;
	int pfd;
	char date[256];
	char host[MAXHOSTNAMELEN];
	char who[256];
	char bound[256];
	char fname[PATH_MAX];
	char dur[PATH_MAX];
	char tmp[80] = "/tmp/astmail-XXXXXX";
	char tmp2[PATH_MAX];
	time_t t;
	struct tm tm;
	struct vm_zone *the_zone = NULL;
	int len_passdata;
	char *passdata2;
	struct ast_channel *ast;

	if (vmu && ast_strlen_zero(vmu->email)) {
		ast_log(LOG_WARNING, "E-mail address missing for mailbox [%s].  E-mail will not be sent.\n", vmu->mailbox);
		return(0);
	}
	if (!strcmp(format, "wav49"))
		format = "WAV";

	if (option_debug)
		ast_log(LOG_DEBUG, "Attaching file '%s', format '%s', uservm is '%d', global is %d\n", attach, format, attach_user_voicemail, ast_test_flag((&globalflags), VM_ATTACH));
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
		ast_log(LOG_WARNING, "Unable to launch '%s'\n", mailcmd);
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
		struct vm_zone *z;
		z = zones;
		while (z) {
			if (!strcmp(z->name, vmu->zonetag)) {
				the_zone = z;
				break;
			}
			z = z->next;
		}
	}

	time(&t);
	ast_localtime(&t, &tm, the_zone ? the_zone->timezone : NULL);
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", &tm);

	/* Start printing the email to the temporary file */
	fprintf(p, "Date: %s\n", date);

	/* Set date format for voicemail mail */
	strftime(date, sizeof(date), global_emaildateformat, &tm);

	/* Populate channel with channel variables for substitution */
	prep_email_sub_vars(ast, vmu, context,mailbox,cidnum, cidname, dur, date);

	if (! *fromstring) {
		fprintf(p, "From: Asterisk PBX <%s>\n", who);
	} else {
		char *passdata;
		int vmlen = strlen(fromstring)*3 + 200;
		if ((passdata = alloca(vmlen))) {
			memset(passdata, 0, vmlen);
			pbx_substitute_variables_helper(ast, fromstring, passdata, vmlen);
			len_passdata = strlen(passdata) * 2 + 1;
			passdata2 = alloca(len_passdata);
			fprintf(p, "From: %s <%s>\n", mailheader_quote(passdata, passdata2, len_passdata), who);
		} else 
			ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
	} 

	len_passdata = strlen(vmu->fullname) * 2 + 1;
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
	} else if (*emailtitle) {
		fprintf(p, emailtitle, msgnum + 1, mailbox) ;
		fprintf(p,"\n") ;
	} else if (ast_test_flag((&globalflags), VM_PBXSKIP))
		fprintf(p, "Subject: New message %d in mailbox %s\n", msgnum + 1, mailbox);
	else
		fprintf(p, "Subject: [PBX]: New message %d in mailbox %s\n", msgnum + 1, mailbox);
	fprintf(p, "Message-ID: <Asterisk-%d-%d-%s-%d@%s>\n", msgnum, (unsigned int)rand(), mailbox, getpid(), host);
	fprintf(p, "MIME-Version: 1.0\n");

	if (attach_user_voicemail) {
		/* Something unique. */
		snprintf(bound, sizeof(bound), "voicemail_%d%s%d%d", msgnum, mailbox, getpid(), (unsigned int)rand());

		fprintf(p, "Content-Type: multipart/mixed; boundary=\"%s\"\n\n\n", bound);

		fprintf(p, "--%s\n", bound);
	}
	fprintf(p, "Content-Type: text/plain; charset=%s\nContent-Transfer-Encoding: 8bit\n\n", global_charset);
	if (emailbody) {
		char *passdata;
		int vmlen = strlen(emailbody)*3 + 200;
		if ((passdata = alloca(vmlen))) {
			memset(passdata, 0, vmlen);
			pbx_substitute_variables_helper(ast,emailbody,passdata,vmlen);
			fprintf(p, "%s\n",passdata);
		} else ast_log(LOG_WARNING, "Cannot allocate workspace for variable substitution\n");
	} else {
		fprintf(p, "Dear %s:\n\n\tJust wanted to let you know you were just left a %s long message (number %d)\n"

			"in mailbox %s from %s, on %s so you might\n"
			"want to check it when you get a chance.  Thanks!\n\n\t\t\t\t--Asterisk\n\n", vmu->fullname, 
			dur, msgnum + 1, mailbox, (cidname ? cidname : (cidnum ? cidnum : "an unknown caller")), date);
	}
	if (attach_user_voicemail) {
		/* Eww. We want formats to tell us their own MIME type */
		char *ctype = "audio/x-";
		if (!strcasecmp(format, "ogg"))
			ctype = "application/";
		
		fprintf(p, "--%s\n", bound);
		fprintf(p, "Content-Type: %s%s; name=\"msg%04d.%s\"\n", ctype, format, msgnum, format);
		fprintf(p, "Content-Transfer-Encoding: base64\n");
		fprintf(p, "Content-Description: Voicemail sound attachment.\n");
		fprintf(p, "Content-Disposition: attachment; filename=\"msg%04d.%s\"\n\n", msgnum, format);

		snprintf(fname, sizeof(fname), "%s.%s", attach, format);
		base_encode(fname, p);
		fprintf(p, "\n\n--%s--\n.\n", bound);
	}
	fclose(p);
	snprintf(tmp2, sizeof(tmp2), "( %s < %s ; rm -f %s ) &", mailcmd, tmp, tmp);
	ast_safe_system(tmp2);
	if (option_debug)
		ast_log(LOG_DEBUG, "Sent mail to %s with command '%s'\n", vmu->email, mailcmd);
	ast_channel_free(ast);
	return 0;
}

/*! \brief Play intro message before recording voicemail 
	\note maybe this should be done in the dialplan, not
		in the application
*/
static int invent_message(struct ast_channel *chan, char *context, char *ext, int busy, char *ecodes)
{
	int res;
	char fn[PATH_MAX];
	char dest[PATH_MAX];

	snprintf(fn, sizeof(fn), "%s%s/%s/greet", VM_SPOOL_DIR, context, ext);

	if (!(res = create_dirpath(dest, sizeof(dest), context, ext, "greet"))) {
		ast_log(LOG_WARNING, "Failed to make directory(%s)\n", fn);
		return -1;
	}

	RETRIEVE(fn, -1);
	if (ast_fileexists(fn, NULL, NULL) > 0) {
		res = ast_streamfile(chan, fn, chan->language);
		if (res) {
			DISPOSE(fn, -1);
			return -1;
		}
		res = ast_waitstream(chan, ecodes);
		if (res) {
			DISPOSE(fn, -1);
			return res;
		}
	} else {
		/* Dispose just in case */
		DISPOSE(fn, -1);
		res = ast_streamfile(chan, "vm-theperson", chan->language);
		if (res)
			return -1;
		res = ast_waitstream(chan, ecodes);
		if (res)
			return res;
		res = ast_say_digit_str(chan, ext, ecodes, chan->language);
		if (res)
			return res;
	}
	if (busy)
		res = ast_streamfile(chan, "vm-isonphone", chan->language);
	else
		res = ast_streamfile(chan, "vm-isunavail", chan->language);
	if (res)
		return -1;
	res = ast_waitstream(chan, ecodes);
	return res;
}

/*! \brief Leave voicemail message, store into file
 	prepared for sending e-mail 
*/
static int leave_voicemail(struct ast_channel *chan, char *ext, struct leave_vm_options *options)
{
	char txtfile[PATH_MAX], tmptxtfile[PATH_MAX];
	char callerid[256];
	FILE *txt;
	int res = 0, txtdes;
	int msgnum;
	int duration = 0;
	int ausemacro = 0;
	int ousemacro = 0;
	int ouseexten = 0;
	char date[256];
	char dir[PATH_MAX], tmpdir[PATH_MAX];
	char dest[PATH_MAX];
	char fn[PATH_MAX];
	char prefile[PATH_MAX] = "";
	char tempfile[PATH_MAX] = "";
	char ext_context[256] = "";
	char fmt[80];
	char *context;
	char ecodes[16] = "#";
	char tmp[256] = "", *tmpptr;
	struct minivm_user *vmu;
	struct minivm_user svm;
	char *category = NULL;

	ast_copy_string(tmp, ext, sizeof(tmp));
	ext = tmp;
	context = strchr(tmp, '@');
	if (context) {
		*context = '\0';
		context++;
		tmpptr = strchr(context, '&');
	} else {
		tmpptr = strchr(ext, '&');
	}

	if (tmpptr) {
		*tmpptr = '\0';
		tmpptr++;
	}

	category = pbx_builtin_getvar_helper(chan, "VM_CATEGORY");

	if (!(vmu = find_user(&svm, context, ext))) {
		ast_log(LOG_WARNING, "No entry in voicemail config file for '%s@%s'\n", ext, context);
		if (ast_test_flag(options, OPT_PRIORITY_JUMP) || option_priority_jumping)
			ast_goto_if_exists(chan, chan->context, chan->exten, chan->priority + 101);
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
		return res;
	}
	/* Setup pre-file if appropriate */
	if (strcmp(vmu->context, "default"))
		snprintf(ext_context, sizeof(ext_context), "%s@%s", ext, vmu->context);
	else
		ast_copy_string(ext_context, vmu->context, sizeof(ext_context));

	if (ast_test_flag(options, OPT_BUSY_GREETING)) {
		res = create_dirpath(dest, sizeof(dest), vmu->context, ext, "busy");
		snprintf(prefile, sizeof(prefile), "%s%s/%s/busy", VM_SPOOL_DIR, vmu->context, ext);
	} else if (ast_test_flag(options, OPT_UNAVAIL_GREETING)) {
		res = create_dirpath(dest, sizeof(dest), vmu->context, ext, "unavail");
		snprintf(prefile, sizeof(prefile), "%s%s/%s/unavail", VM_SPOOL_DIR, vmu->context, ext);
	}
	snprintf(tempfile, sizeof(tempfile), "%s%s/%s/temp", VM_SPOOL_DIR, vmu->context, ext);
	if (!(res = create_dirpath(dest, sizeof(dest), vmu->context, ext, "temp"))) {
		ast_log(LOG_WARNING, "Failed to make directory (%s)\n", tempfile);
		return -1;
	}

	if (ast_fileexists(tempfile, NULL, NULL) > 0)
		ast_copy_string(prefile, tempfile, sizeof(prefile));

	/* It's easier just to try to make it than to check for its existence */
	create_dirpath(dir, sizeof(dir), vmu->context, ext, "INBOX");
	create_dirpath(tmpdir, sizeof(tmpdir), vmu->context, ext, "tmp");

	/* Check current or macro-calling context for special extensions */
	if (ast_test_flag(vmu, VM_OPERATOR)) {
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
		RETRIEVE(prefile, -1);
		if (ast_fileexists(prefile, NULL, NULL) > 0) {
			if (ast_streamfile(chan, prefile, chan->language) > -1) 
				res = ast_waitstream(chan, ecodes);
		} else {
			ast_log(LOG_DEBUG, "%s doesn't exist, doing what we can\n", prefile);
			res = invent_message(chan, vmu->context, ext, ast_test_flag(options, OPT_BUSY_GREETING), ecodes);
		}
		DISPOSE(prefile, -1);
		if (res < 0) {
			ast_log(LOG_DEBUG, "Hang up during prefile playback\n");
			free_user(vmu);
			pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
			return -1;
		}
	}
	if (res == '#') {
		/* On a '#' we skip the instructions */
		ast_set_flag(options, OPT_SILENT);
		res = 0;
	}
	if (!res && !ast_test_flag(options, OPT_SILENT)) {
		res = ast_streamfile(chan, INTRO, chan->language);
		if (!res)
			res = ast_waitstream(chan, ecodes);
		if (res == '#') {
			ast_set_flag(options, OPT_SILENT);
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
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "USEREXIT");
		return 0;
	}

	/* Check for a '0' here */
	if (res == '0') {
	transfer:
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
			pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "USEREXIT");
		}
		return 0;
	}
	if (res < 0) {
		free_user(vmu);
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
		return -1;
	}
	/* The meat of recording the message...  All the announcements and beeps have been played*/
	ast_copy_string(fmt, vmfmts, sizeof(fmt));

	if (ast_strlen_zero(fmt)) {
		ast_log(LOG_WARNING, "No format for saving voicemail?\n");
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
		free_user(vmu);
		return res;
	}
	msgnum = 0;

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
	txt = fdopen(txtdes, "w+");
	if (txt) {
		get_date(date, sizeof(date));
		
		fprintf(txt, 
			/* "Mailbox:domain:macrocontext:exten:priority:callerchan:callerid:origdate:origtime:category:duration" */
			"%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s\n"
			ext,
			chan->context,
			chan->macrocontext, 
			chan->exten,
			chan->priority,
			chan->name,
			ast_callerid_merge(callerid, sizeof(callerid), chan->cid.cid_name, chan->cid.cid_num, "Unknown"),
			date, (long)time(NULL),
			category ? category : "",
			"durationholder"); 
	} else
		ast_log(LOG_WARNING, "Error opening text file for output\n");

	res = play_record_review(chan, NULL, tmptxtfile, vmmaxmessage, fmt, 1, vmu, &duration, NULL, options->record_gain);

	if (txt) {
		if (duration < vmminmessage) {
			if (option_verbose > 2) 
				ast_verbose( VERBOSE_PREFIX_3 "Recording was %d seconds long but needs to be at least %d - abandoning\n", duration, vmminmessage);
			fclose(txt);
			ast_filedelete(tmptxtfile, NULL);
			unlink(tmptxtfile);
		} else {
			fprintf(txt, "duration=%d\n", duration);
			fclose(txt);
			if (vm_lock_path(dir)) {
				ast_log(LOG_ERROR, "Couldn't lock directory %s.  Voicemail will be lost.\n", dir);
				/* Delete files */
				ast_filedelete(tmptxtfile, NULL);
				unlink(tmptxtfile);
			} else if (ast_fileexists(tmptxtfile, NULL, NULL) <= 0) {
				if (option_debug) 
					ast_log(LOG_DEBUG, "The recorded media file is gone, so we should remove the .txt file too!\n");
				unlink(tmptxtfile);
				ast_unlock_path(dir);
			} else {
				for (;;) {
					make_file(fn, sizeof(fn), dir, msgnum);
					if (!EXISTS(dir, msgnum, fn, NULL))
						break;
					msgnum++;
				}

				/* assign a variable with the name of the voicemail file */	  
				pbx_builtin_setvar_helper(chan, "VM_MESSAGEFILE", fn);

				snprintf(txtfile, sizeof(txtfile), "%s.txt", fn);
				ast_filerename(tmptxtfile, fn, NULL);
				rename(tmptxtfile, txtfile);

				ast_unlock_path(dir);

				/* Are there to be more recipients of this message? */
				while (tmpptr) {
					struct minivm_user recipu, *recip;
					char *exten, *context;

					exten = strsep(&tmpptr, "&");
					context = strchr(exten, '@');
					if (context) {
						*context = '\0';
						context++;
					}
					if ((recip = find_user(&recipu, context, exten))) {
						copy_message(chan, vmu, 0, msgnum, duration, recip, fmt, dir);
						free_user(recip);
					}
				}
				if (ast_fileexists(fn, NULL, NULL) > 0) {
					STORE(dir, vmu->mailbox, vmu->context, msgnum);
					notify_new_message(chan, vmu, msgnum, duration, fmt, chan->cid.cid_num, chan->cid.cid_name);
					DISPOSE(dir, msgnum);
				}
			}
		}
	}

	if (res == '0') {
		goto transfer;
	} else if (res > 0)
		res = 0;

	if (duration < vmminmessage)
		/* XXX We should really give a prompt too short/option start again, with leave_vm_out called only after a timeout XXX */
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "FAILED");
	else
		pbx_builtin_setvar_helper(chan, "MINIVMSTATUS", "SUCCESS");
 leave_vm_out:
	free_user(vmu);
	
	return res;
}

/*! \brief Voicemail introduction - GREEK SYNTAX 

	In greek the plural for old/new is
	different so we need the following files	 
	We also need vm-denExeteMynhmata because 
	this syntax is different.
	
	- vm-Olds.wav	: "Palia"
	- vm-INBOXs.wav : "Nea"
	- vm-denExeteMynhmata : "den exete mynhmata"
 */
static int vm_intro_gr(struct ast_channel *chan, struct minivm_state *vms)
{
	int res = 0;

	if (vms->newmessages) {
		res = ast_play_and_wait(chan, "vm-youhave");
		if (!res) 
			res = ast_say_number(chan, vms->newmessages, AST_DIGIT_ANY, chan->language, NULL);
		if (!res) {
			if ((vms->newmessages == 1)) {
				res = ast_play_and_wait(chan, "vm-INBOX");
				if (!res)
			 		res = ast_play_and_wait(chan, "vm-message");
		 	} else {
				res = ast_play_and_wait(chan, "vm-INBOXs");
				if (!res)
					res = ast_play_and_wait(chan, "vm-messages");
		 	}
		}	  
	} else if (vms->oldmessages){
		res = ast_play_and_wait(chan, "vm-youhave");
		if (!res)
			res = ast_say_number(chan, vms->oldmessages, AST_DIGIT_ANY, chan->language, NULL);
		if ((vms->oldmessages == 1)){
			res = ast_play_and_wait(chan, "vm-Old");
			if (!res)
				res = ast_play_and_wait(chan, "vm-message");
		} else {
			res = ast_play_and_wait(chan, "vm-Olds");
		 	if (!res)
				res = ast_play_and_wait(chan, "vm-messages");
		}
	 } else if (!vms->oldmessages && !vms->newmessages) 
			res = ast_play_and_wait(chan, "vm-denExeteMynhmata"); 
	 return res;
}
	
/* Default English syntax */
static int vm_intro_en(struct ast_channel *chan,struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;
	res = ast_play_and_wait(chan, "vm-youhave");
	if (!res) {
		if (vms->newmessages) {
			res = say_and_wait(chan, vms->newmessages, chan->language);
			if (!res)
				res = ast_play_and_wait(chan, "vm-INBOX");
			if (vms->oldmessages && !res)
				res = ast_play_and_wait(chan, "vm-and");
			else if (!res) {
				if ((vms->newmessages == 1))
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
				
		}
		if (!res && vms->oldmessages) {
			res = say_and_wait(chan, vms->oldmessages, chan->language);
			if (!res)
				res = ast_play_and_wait(chan, "vm-Old");
			if (!res) {
				if (vms->oldmessages == 1)
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
		if (!res) {
			if (!vms->oldmessages && !vms->newmessages) {
				res = ast_play_and_wait(chan, "vm-no");
				if (!res)
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
	}
	return res;
}

/* ITALIAN syntax */
static int vm_intro_it(struct ast_channel *chan, struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;
	if (!vms->oldmessages && !vms->newmessages)
		res =	ast_play_and_wait(chan, "vm-no") ||
			ast_play_and_wait(chan, "vm-message");
	else
		res =	ast_play_and_wait(chan, "vm-youhave");
	if (!res && vms->newmessages) {
		res = (vms->newmessages == 1) ?
			ast_play_and_wait(chan, "digits/un") ||
			ast_play_and_wait(chan, "vm-nuovo") ||
			ast_play_and_wait(chan, "vm-message") :
			/* 2 or more new messages */
			say_and_wait(chan, vms->newmessages, chan->language) ||
			ast_play_and_wait(chan, "vm-nuovi") ||
			ast_play_and_wait(chan, "vm-messages");
		if (!res && vms->oldmessages)
			res =	ast_play_and_wait(chan, "vm-and");
	}
	if (!res && vms->oldmessages) {
		res = (vms->oldmessages == 1) ?
			ast_play_and_wait(chan, "digits/un") ||
			ast_play_and_wait(chan, "vm-vecchio") ||
			ast_play_and_wait(chan, "vm-message") :
			/* 2 or more old messages */
			say_and_wait(chan, vms->oldmessages, chan->language) ||
			ast_play_and_wait(chan, "vm-vecchi") ||
			ast_play_and_wait(chan, "vm-messages");
	}
	return res;
}

/* SWEDISH syntax */
static int vm_intro_se(struct ast_channel *chan, struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;

	res = ast_play_and_wait(chan, "vm-youhave");
	if (res)
		return res;

	if (!vms->oldmessages && !vms->newmessages) {
		res = ast_play_and_wait(chan, "vm-no");
		res = res ? res : ast_play_and_wait(chan, "vm-messages");
		return res;
	}

	if (vms->newmessages) {
		if ((vms->newmessages == 1)) {
			res = ast_play_and_wait(chan, "digits/ett");
			res = res ? res : ast_play_and_wait(chan, "vm-nytt");
			res = res ? res : ast_play_and_wait(chan, "vm-message");
		} else {
			res = say_and_wait(chan, vms->newmessages, chan->language);
			res = res ? res : ast_play_and_wait(chan, "vm-nya");
			res = res ? res : ast_play_and_wait(chan, "vm-messages");
		}
		if (!res && vms->oldmessages)
			res = ast_play_and_wait(chan, "vm-and");
	}
	if (!res && vms->oldmessages) {
		if (vms->oldmessages == 1) {
			res = ast_play_and_wait(chan, "digits/ett");
			res = res ? res : ast_play_and_wait(chan, "vm-gammalt");
			res = res ? res : ast_play_and_wait(chan, "vm-message");
		} else {
			res = say_and_wait(chan, vms->oldmessages, chan->language);
			res = res ? res : ast_play_and_wait(chan, "vm-gamla");
			res = res ? res : ast_play_and_wait(chan, "vm-messages");
		}
	}

	return res;
}

/* NORWEGIAN syntax */
static int vm_intro_no(struct ast_channel *chan,struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;

	res = ast_play_and_wait(chan, "vm-youhave");
	if (res)
		return res;

	if (!vms->oldmessages && !vms->newmessages) {
		res = ast_play_and_wait(chan, "vm-no");
		res = res ? res : ast_play_and_wait(chan, "vm-messages");
		return res;
	}

	if (vms->newmessages) {
		if ((vms->newmessages == 1)) {
			res = ast_play_and_wait(chan, "digits/1");
			res = res ? res : ast_play_and_wait(chan, "vm-ny");
			res = res ? res : ast_play_and_wait(chan, "vm-message");
		} else {
			res = say_and_wait(chan, vms->newmessages, chan->language);
			res = res ? res : ast_play_and_wait(chan, "vm-nye");
			res = res ? res : ast_play_and_wait(chan, "vm-messages");
		}
		if (!res && vms->oldmessages)
			res = ast_play_and_wait(chan, "vm-and");
	}
	if (!res && vms->oldmessages) {
		if (vms->oldmessages == 1) {
			res = ast_play_and_wait(chan, "digits/1");
			res = res ? res : ast_play_and_wait(chan, "vm-gamel");
			res = res ? res : ast_play_and_wait(chan, "vm-message");
		} else {
			res = say_and_wait(chan, vms->oldmessages, chan->language);
			res = res ? res : ast_play_and_wait(chan, "vm-gamle");
			res = res ? res : ast_play_and_wait(chan, "vm-messages");
		}
	}

	return res;
}

/* GERMAN syntax */
static int vm_intro_de(struct ast_channel *chan,struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;
	res = ast_play_and_wait(chan, "vm-youhave");
	if (!res) {
		if (vms->newmessages) {
			if ((vms->newmessages == 1))
				res = ast_play_and_wait(chan, "digits/1F");
			else
				res = say_and_wait(chan, vms->newmessages, chan->language);
			if (!res)
				res = ast_play_and_wait(chan, "vm-INBOX");
			if (vms->oldmessages && !res)
				res = ast_play_and_wait(chan, "vm-and");
			else if (!res) {
				if ((vms->newmessages == 1))
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
				
		}
		if (!res && vms->oldmessages) {
			if (vms->oldmessages == 1)
				res = ast_play_and_wait(chan, "digits/1F");
			else
				res = say_and_wait(chan, vms->oldmessages, chan->language);
			if (!res)
				res = ast_play_and_wait(chan, "vm-Old");
			if (!res) {
				if (vms->oldmessages == 1)
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
		if (!res) {
			if (!vms->oldmessages && !vms->newmessages) {
				res = ast_play_and_wait(chan, "vm-no");
				if (!res)
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
	}
	return res;
}

/* SPANISH syntax */
static int vm_intro_es(struct ast_channel *chan,struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;
	if (!vms->oldmessages && !vms->newmessages) {
		res = ast_play_and_wait(chan, "vm-youhaveno");
		if (!res)
			res = ast_play_and_wait(chan, "vm-messages");
	} else {
		res = ast_play_and_wait(chan, "vm-youhave");
	}
	if (!res) {
		if (vms->newmessages) {
			if (!res) {
				if ((vms->newmessages == 1)) {
					res = ast_play_and_wait(chan, "digits/1M");
					if (!res)
						res = ast_play_and_wait(chan, "vm-message");
					if (!res)
						res = ast_play_and_wait(chan, "vm-INBOXs");
				} else {
					res = say_and_wait(chan, vms->newmessages, chan->language);
					if (!res)
						res = ast_play_and_wait(chan, "vm-messages");
					if (!res)
						res = ast_play_and_wait(chan, "vm-INBOX");
				}
			}
			if (vms->oldmessages && !res)
				res = ast_play_and_wait(chan, "vm-and");
		}
		if (vms->oldmessages) {
			if (!res) {
				if (vms->oldmessages == 1) {
					res = ast_play_and_wait(chan, "digits/1M");
					if (!res)
						res = ast_play_and_wait(chan, "vm-message");
					if (!res)
						res = ast_play_and_wait(chan, "vm-Olds");
				} else {
					res = say_and_wait(chan, vms->oldmessages, chan->language);
					if (!res)
						res = ast_play_and_wait(chan, "vm-messages");
					if (!res)
						res = ast_play_and_wait(chan, "vm-Old");
				}
			}
		}
	}
return res;
}

/* FRENCH syntax */
static int vm_intro_fr(struct ast_channel *chan,struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;
	res = ast_play_and_wait(chan, "vm-youhave");
	if (!res) {
		if (vms->newmessages) {
			res = say_and_wait(chan, vms->newmessages, chan->language);
			if (!res)
				res = ast_play_and_wait(chan, "vm-INBOX");
			if (vms->oldmessages && !res)
				res = ast_play_and_wait(chan, "vm-and");
			else if (!res) {
				if ((vms->newmessages == 1))
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
				
		}
		if (!res && vms->oldmessages) {
			res = say_and_wait(chan, vms->oldmessages, chan->language);
			if (!res) {
				if (vms->oldmessages == 1)
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
			if (!res)
				res = ast_play_and_wait(chan, "vm-Old");
		}
		if (!res) {
			if (!vms->oldmessages && !vms->newmessages) {
				res = ast_play_and_wait(chan, "vm-no");
				if (!res)
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
	}
	return res;
}

/* DUTCH syntax */
static int vm_intro_nl(struct ast_channel *chan,struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;
	res = ast_play_and_wait(chan, "vm-youhave");
	if (!res) {
		if (vms->newmessages) {
			res = say_and_wait(chan, vms->newmessages, chan->language);
			if (!res) {
				if (vms->newmessages == 1)
					res = ast_play_and_wait(chan, "vm-INBOXs");
				else
					res = ast_play_and_wait(chan, "vm-INBOX");
			}
			if (vms->oldmessages && !res)
				res = ast_play_and_wait(chan, "vm-and");
			else if (!res) {
				if ((vms->newmessages == 1))
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
				
		}
		if (!res && vms->oldmessages) {
			res = say_and_wait(chan, vms->oldmessages, chan->language);
			if (!res) {
				if (vms->oldmessages == 1)
					res = ast_play_and_wait(chan, "vm-Olds");
				else
					res = ast_play_and_wait(chan, "vm-Old");
			}
			if (!res) {
				if (vms->oldmessages == 1)
					res = ast_play_and_wait(chan, "vm-message");
				else
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
		if (!res) {
			if (!vms->oldmessages && !vms->newmessages) {
				res = ast_play_and_wait(chan, "vm-no");
				if (!res)
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
	}
	return res;
}

/* PORTUGUESE syntax */
static int vm_intro_pt(struct ast_channel *chan,struct minivm_state *vms)
{
	/* Introduce messages they have */
	int res;
	res = ast_play_and_wait(chan, "vm-youhave");
	if (!res) {
		if (vms->newmessages) {
			res = ast_say_number(chan, vms->newmessages, AST_DIGIT_ANY, chan->language, "f");
			if (!res) {
				if ((vms->newmessages == 1)) {
					res = ast_play_and_wait(chan, "vm-message");
					if (!res)
						res = ast_play_and_wait(chan, "vm-INBOXs");
				} else {
					res = ast_play_and_wait(chan, "vm-messages");
					if (!res)
						res = ast_play_and_wait(chan, "vm-INBOX");
				}
			}
			if (vms->oldmessages && !res)
				res = ast_play_and_wait(chan, "vm-and");
		}
		if (!res && vms->oldmessages) {
			res = ast_say_number(chan, vms->oldmessages, AST_DIGIT_ANY, chan->language, "f");
			if (!res) {
				if (vms->oldmessages == 1) {
					res = ast_play_and_wait(chan, "vm-message");
					if (!res)
						res = ast_play_and_wait(chan, "vm-Olds");
				} else {
					res = ast_play_and_wait(chan, "vm-messages");
					if (!res)
						res = ast_play_and_wait(chan, "vm-Old");
				}
			}
		}
		if (!res) {
			if (!vms->oldmessages && !vms->newmessages) {
				res = ast_play_and_wait(chan, "vm-no");
				if (!res)
					res = ast_play_and_wait(chan, "vm-messages");
			}
		}
	}
	return res;
}


/* CZECH syntax */
/* in czech there must be declension of word new and message
 * czech   	: english 	   : czech	: english
 * --------------------------------------------------------
 * vm-youhave 	: you have 
 * vm-novou 	: one new 	   : vm-zpravu 	: message
 * vm-nove 	: 2-4 new	   : vm-zpravy 	: messages
 * vm-novych 	: 5-infinite new   : vm-zprav 	: messages
 * vm-starou	: one old
 * vm-stare	: 2-4 old 
 * vm-starych	: 5-infinite old
 * jednu	: one	- falling 4. 
 * vm-no	: no  ( no messages )
 */

static int vm_intro_cz(struct ast_channel *chan,struct minivm_state *vms)
{
	int res;
	res = ast_play_and_wait(chan, "vm-youhave");
	if (!res) {
		if (vms->newmessages) {
			if (vms->newmessages == 1) {
				res = ast_play_and_wait(chan, "digits/jednu");
			} else {
				res = say_and_wait(chan, vms->newmessages, chan->language);
			}
			if (!res) {
				if ((vms->newmessages == 1))
					res = ast_play_and_wait(chan, "vm-novou");
				if ((vms->newmessages) > 1 && (vms->newmessages < 5))
					res = ast_play_and_wait(chan, "vm-nove");
				if (vms->newmessages > 4)
					res = ast_play_and_wait(chan, "vm-novych");
			}
			if (vms->oldmessages && !res)
				res = ast_play_and_wait(chan, "vm-and");
			else if (!res) {
				if ((vms->newmessages == 1))
					res = ast_play_and_wait(chan, "vm-zpravu");
				if ((vms->newmessages) > 1 && (vms->newmessages < 5))
					res = ast_play_and_wait(chan, "vm-zpravy");
				if (vms->newmessages > 4)
					res = ast_play_and_wait(chan, "vm-zprav");
			}
		}
		if (!res && vms->oldmessages) {
			res = say_and_wait(chan, vms->oldmessages, chan->language);
			if (!res) {
				if ((vms->oldmessages == 1))
					res = ast_play_and_wait(chan, "vm-starou");
				if ((vms->oldmessages) > 1 && (vms->oldmessages < 5))
					res = ast_play_and_wait(chan, "vm-stare");
				if (vms->oldmessages > 4)
					res = ast_play_and_wait(chan, "vm-starych");
			}
			if (!res) {
				if ((vms->oldmessages == 1))
					res = ast_play_and_wait(chan, "vm-zpravu");
				if ((vms->oldmessages) > 1 && (vms->oldmessages < 5))
					res = ast_play_and_wait(chan, "vm-zpravy");
				if (vms->oldmessages > 4)
					res = ast_play_and_wait(chan, "vm-zprav");
			}
		}
		if (!res) {
			if (!vms->oldmessages && !vms->newmessages) {
				res = ast_play_and_wait(chan, "vm-no");
				if (!res)
					res = ast_play_and_wait(chan, "vm-zpravy");
			}
		}
	}
	return res;
}

static int vm_intro(struct ast_channel *chan, struct minivm_state *vms)
{
	/* Play voicemail intro - syntax is different for different languages */
	if (!strcasecmp(chan->language, "de")) {	/* GERMAN syntax */
		return vm_intro_de(chan, vms);
	} else if (!strcasecmp(chan->language, "es")) { /* SPANISH syntax */
		return vm_intro_es(chan, vms);
	} else if (!strcasecmp(chan->language, "it")) { /* ITALIAN syntax */
		return vm_intro_it(chan, vms);
	} else if (!strcasecmp(chan->language, "fr")) {	/* FRENCH syntax */
		return vm_intro_fr(chan, vms);
	} else if (!strcasecmp(chan->language, "nl")) {	/* DUTCH syntax */
		return vm_intro_nl(chan, vms);
	} else if (!strcasecmp(chan->language, "pt")) {	/* PORTUGUESE syntax */
		return vm_intro_pt(chan, vms);
	} else if (!strcasecmp(chan->language, "cz")) {	/* CZECH syntax */
		return vm_intro_cz(chan, vms);
	} else if (!strcasecmp(chan->language, "gr")) {	/* GREEK syntax */
		return vm_intro_gr(chan, vms);
	} else if (!strcasecmp(chan->language, "se")) {	/* SWEDISH syntax */
		return vm_intro_se(chan, vms);
	} else if (!strcasecmp(chan->language, "no")) {	/* NORWEGIAN syntax */
		return vm_intro_no(chan, vms);
	} else {					/* Default to ENGLISH */
		return vm_intro_en(chan, vms);
	}
}

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
		if (ast_app_parse_options(vm_app_options, &flags, opts, argv[1])) {
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
			} else {
				leave_options.record_gain = (signed char) gain;
			}
		}
	} else {
		/* old style options parsing */
		while (*argv[0]) {
			if (*argv[0] == 's') {
				ast_set_flag(&leave_options, OPT_SILENT);
				argv[0]++;
			} else if (*argv[0] == 'b') {
				ast_set_flag(&leave_options, OPT_BUSY_GREETING);
				argv[0]++;
			} else if (*argv[0] == 'u') {
				ast_set_flag(&leave_options, OPT_UNAVAIL_GREETING);
				argv[0]++;
			} else if (*argv[0] == 'j') {
				ast_set_flag(&leave_options, OPT_PRIORITY_JUMP);
				argv[0]++;
			} else 
				break;
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
	
	LOCAL_USER_REMOVE(u);

	return res;
}

/*! \brief Load minivoicemail configuration */
static int load_config(void)
{
	struct minivm_user *cur, *l;
	struct vm_zone *zcur, *zl;
	struct ast_config *cfg;
	char *cat;
	struct ast_variable *var;
	char *notifystr = NULL;
	char *astattach;
	char *astsearch;
	char *astsaycid;
	char *send_voicemail;
	char *astcallop;
	char *astreview;
	char *astskipcmd;
	char *asthearenv;
	char *astsaydurationinfo;
	char *astsaydurationminfo;
	char *silencestr;
	char *maxmsgstr;
	char *astdirfwd;
	char *thresholdstr;
	char *fmt;
	char *astemail;
 	char *astmailcmd = SENDMAIL;
	char *s,*q,*stringp;
	char *dialoutcxt = NULL;
	char *callbackcxt = NULL;	
	char *exitcxt = NULL;	
	char *extpc;
	char *emaildateformatstr;
	int x;

	cfg = ast_config_load(VOICEMAIL_CONFIG);
	ast_mutex_lock(&minivmlock);

	/* Free all users */
	cur = users;
	while (cur) {
		l = cur;
		cur = cur->next;
		ast_set_flag(l, VM_ALLOCED);	
		free_user(l);
	}

	/* Free all zones */
	zcur = zones;
	while (zcur) {
		zl = zcur;
		zcur = zcur->next;
		free_zone(zl);
	}
	zones = NULL;
	zonesl = NULL;
	users = NULL;
	usersl = NULL;
	memset(ext_pass_cmd, 0, sizeof(ext_pass_cmd));

	if (!cfg) {
		ast_mutex_unlock(&minivmlock);
		ast_log(LOG_WARNING, "Failed to load configuration file. Module not activated.\n");
		return 0;
	}

	/* General settings */

	/* Attach voice message to mail message ? */
	if (!(astattach = ast_variable_retrieve(cfg, "general", "attach"))) 
		astattach = "yes";

	ast_set2_flag((&globalflags), ast_true(astattach), VM_ATTACH);	

	if (!(astsearch = ast_variable_retrieve(cfg, "general", "searchcontexts")))
		astsearch = "no";
	ast_set2_flag((&globalflags), ast_true(astsearch), VM_SEARCH);

	/* Mail command */
	strcpy(mailcmd, SENDMAIL);
	if ((astmailcmd = ast_variable_retrieve(cfg, "general", "mailcmd")))
		ast_copy_string(mailcmd, astmailcmd, sizeof(mailcmd)); /* User setting */

	maxsilence = 0;
	if ((silencestr = ast_variable_retrieve(cfg, "general", "maxsilence"))) {
		maxsilence = atoi(silencestr);
		if (maxsilence > 0)
			maxsilence *= 1000;
	}
		
	/* Load date format config for voicemail mail */
	if ((emaildateformatstr = ast_variable_retrieve(cfg, "general", "emaildateformat"))) {
		ast_copy_string(global_emaildateformat, emaildateformatstr, sizeof(global_emaildateformat));
	}

	/* External password changing command */
	if ((extpc = ast_variable_retrieve(cfg, "general", "externpass"))) {
		ast_copy_string(ext_pass_cmd,extpc,sizeof(ext_pass_cmd));
	}

	/* External voicemail notify application */
	externnotify[0] = '\0';
	if ((notifystr = ast_variable_retrieve(cfg, "general", "externnotify"))) {
		ast_copy_string(externnotify, notifystr, sizeof(externnotify));
	}

	/* Silence treshold */
	silencethreshold = 256;
	if ((thresholdstr = ast_variable_retrieve(cfg, "general", "silencethreshold")))
		silencethreshold = atoi(thresholdstr);
		
	if (!(astemail = ast_variable_retrieve(cfg, "general", "serveremail"))) 
		astemail = ASTERISK_USERNAME;
	ast_copy_string(serveremail, astemail, sizeof(serveremail));
		
	vmmaxmessage = 0;
	if ((s = ast_variable_retrieve(cfg, "general", "maxmessage"))) {
		if (sscanf(s, "%d", &x) == 1) {
			vmmaxmessage = x;
		} else {
			ast_log(LOG_WARNING, "Invalid max message time length\n");
		}
	}

	vmminmessage = 0;
	if ((s = ast_variable_retrieve(cfg, "general", "minmessage"))) {
		if (sscanf(s, "%d", &x) == 1) {
			vmminmessage = x;
			if (maxsilence <= vmminmessage)
				ast_log(LOG_WARNING, "maxsilence should be less than minmessage or you may get empty messages\n");
		} else {
			ast_log(LOG_WARNING, "Invalid min message time length\n");
		}
	}
	fmt = ast_variable_retrieve(cfg, "general", "format");
	if (!fmt)
		fmt = "wav";	
	ast_copy_string(vmfmts, fmt, sizeof(vmfmts));

	skipms = 3000;
	if ((s = ast_variable_retrieve(cfg, "general", "maxgreet"))) {
		if (sscanf(s, "%d", &x) == 1) {
			maxgreet = x;
		} else {
			ast_log(LOG_WARNING, "Invalid max message greeting length\n");
		}
	}

	if ((s = ast_variable_retrieve(cfg, "general", "skipms"))) {
		if (sscanf(s, "%d", &x) == 1) {
			skipms = x;
		} else {
			ast_log(LOG_WARNING, "Invalid skipms value\n");
		}
	}


	if ((s = ast_variable_retrieve(cfg, "general", "cidinternalcontexts"))){
		ast_log(LOG_DEBUG,"VM_CID Internal context string: %s\n",s);
		stringp = ast_strdupa(s);
		for (x = 0 ; x < MAX_NUM_CID_CONTEXTS ; x++){
			if (!ast_strlen_zero(stringp)) {
				q = strsep(&stringp,",");
				while ((*q == ' ')||(*q == '\t')) /* Eat white space between contexts */
					q++;
				ast_copy_string(cidinternalcontexts[x], q, sizeof(cidinternalcontexts[x]));
				if (option_debug)
					ast_log(LOG_DEBUG,"VM_CID Internal context %d: %s\n", x, cidinternalcontexts[x]);
			} else {
				cidinternalcontexts[x][0] = '\0';
			}
		}
	}
	if (!(astreview = ast_variable_retrieve(cfg, "general", "review"))){
		if (option_debug)
			ast_log(LOG_DEBUG,"VM Review Option disabled globally\n");
		astreview = "no";
	}
	ast_set2_flag((&globalflags), ast_true(astreview), VM_REVIEW);	

	if (!(astcallop = ast_variable_retrieve(cfg, "general", "operator"))){
		if (option_debug)
			ast_log(LOG_DEBUG,"VM Operator break disabled globally\n");
		astcallop = "no";
	}
	ast_set2_flag((&globalflags), ast_true(astcallop), VM_OPERATOR);	

	if (!(astsaycid = ast_variable_retrieve(cfg, "general", "saycid"))) {
		if (option_debug)
			ast_log(LOG_DEBUG,"VM CID Info before msg disabled globally\n");
		astsaycid = "no";
	} 
	ast_set2_flag((&globalflags), ast_true(astsaycid), VM_SAYCID);	

	if (!(send_voicemail = ast_variable_retrieve(cfg,"general", "sendvoicemail"))){
		if (option_debug)
			ast_log(LOG_DEBUG,"Send Voicemail msg disabled globally\n");
		send_voicemail = "no";
	}
	ast_set2_flag((&globalflags), ast_true(send_voicemail), VM_SVMAIL);
	
	if (!(asthearenv = ast_variable_retrieve(cfg, "general", "envelope"))) {
		if (option_debug)
			ast_log(LOG_DEBUG,"ENVELOPE before msg enabled globally\n");
		asthearenv = "yes";
	}
	ast_set2_flag((&globalflags), ast_true(asthearenv), VM_ENVELOPE);	

	if (!(astsaydurationinfo = ast_variable_retrieve(cfg, "general", "sayduration"))) {
		ast_log(LOG_DEBUG,"Duration info before msg enabled globally\n");
		astsaydurationinfo = "yes";
	}
	ast_set2_flag((&globalflags), ast_true(astsaydurationinfo), VM_SAYDURATION);	

	global_saydurationminfo = 2;
	if ((astsaydurationminfo = ast_variable_retrieve(cfg, "general", "saydurationm"))) {
		if (sscanf(astsaydurationminfo, "%d", &x) == 1) {
			global_saydurationminfo = x;
		} else {
			ast_log(LOG_WARNING, "Invalid min duration for say duration\n");
		}
	}

	cat = ast_category_browse(cfg, NULL);
	while (cat) {
		if (strcasecmp(cat, "general")) {
			var = ast_variable_browse(cfg, cat);
			if (strcasecmp(cat, "zonemessages")) {
				/* Process mailboxes in this context */
				while (var) {
					append_mailbox(cat, var->name, var->value);
					var = var->next;
				}
			} else {
				/* Timezones in this context */
				while (var) {
					struct vm_zone *z;
					z = malloc(sizeof(struct vm_zone));
					if (z != NULL) {
						char *msg_format, *timezone;
						msg_format = ast_strdupa(var->value);
						if (msg_format != NULL) {
							timezone = strsep(&msg_format, "|");
							if (msg_format) {
								ast_copy_string(z->name, var->name, sizeof(z->name));
								ast_copy_string(z->timezone, timezone, sizeof(z->timezone));
								ast_copy_string(z->msg_format, msg_format, sizeof(z->msg_format));
								z->next = NULL;
								if (zones) {
									zonesl->next = z;
									zonesl = z;
								} else {
									zones = z;
									zonesl = z;
								}
							} else {
								ast_log(LOG_WARNING, "Invalid timezone definition at line %d\n", var->lineno);
								free(z);
							}
						} else {
							ast_log(LOG_WARNING, "Out of memory while reading voicemail config\n");
							free(z);
							ast_mutex_unlock(&minivmlock);
							ast_config_destroy(cfg);
							return -1;
						}
					} else {
						ast_log(LOG_WARNING, "Out of memory while reading voicemail config\n");
						ast_mutex_unlock(&minivmlock);
						ast_config_destroy(cfg);
						return -1;
					}
					var = var->next;
				}
			}
		}
		cat = ast_category_browse(cfg, cat);
	}
	memset(fromstring,0,sizeof(fromstring));
	memset(pagerfromstring,0,sizeof(pagerfromstring));
	memset(emailtitle,0,sizeof(emailtitle));
	strcpy(global_charset, "ISO-8859-1");
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
	if ((s=ast_variable_retrieve(cfg, "general", "fromstring")))
		ast_copy_string(fromstring,s,sizeof(fromstring));
	if ((s=ast_variable_retrieve(cfg, "general", "pagerfromstring")))
		ast_copy_string(pagerfromstring,s,sizeof(pagerfromstring));
	if ((s=ast_variable_retrieve(cfg, "general", "charset")))
		ast_copy_string(global_charset, s, sizeof(charset));
	if ((s=ast_variable_retrieve(cfg, "general", "emailtitle"))) {
		ast_log(LOG_NOTICE, "Keyword 'emailtitle' is DEPRECATED, please use 'emailsubject' instead.\n");
		ast_copy_string(emailtitle,s,sizeof(emailtitle));
	}
	if ((s=ast_variable_retrieve(cfg, "general", "emailsubject")))
		emailsubject = strdup(s);
	if ((s=ast_variable_retrieve(cfg, "general", "emailbody"))) {
		char *tmpread, *tmpwrite;
		emailbody = strdup(s);

		/* substitute strings \t and \n into the apropriate characters */
		tmpread = tmpwrite = emailbody;
		while ((tmpwrite = strchr(tmpread,'\\'))) {
		       int len = strlen("\n");
		       switch (tmpwrite[1]) {
		       case 'n':
			      strncpy(tmpwrite+len,tmpwrite+2,strlen(tmpwrite+2)+1);
			      strncpy(tmpwrite,"\n",len);
			      break;
		       case 't':
			      strncpy(tmpwrite+len,tmpwrite+2,strlen(tmpwrite+2)+1);
			      strncpy(tmpwrite,"\t",len);
			      break;
		       default:
			      ast_log(LOG_NOTICE, "Substitution routine does not support this character: %c\n",tmpwrite[1]);
		       }
		       tmpread = tmpwrite+len;
	       }
	}
	if ((s=ast_variable_retrieve(cfg, "general", "pagersubject")))
	       pagersubject = strdup(s);
	if ((s = ast_variable_retrieve(cfg, "general", "pagerbody"))) {
	       char *tmpread, *tmpwrite;
	       pagerbody = strdup(s);

	       /* substitute strings \t and \n into the apropriate characters */
	       tmpread = tmpwrite = pagerbody;
		while ((tmpwrite = strchr(tmpread,'\\'))) {
			int len = strlen("\n");
			switch (tmpwrite[1]) {
			case 'n':
				strncpy(tmpwrite+len,tmpwrite+2,strlen(tmpwrite+2)+1);
				strncpy(tmpwrite,"\n",len);
				break;
			case 't':
				strncpy(tmpwrite+len,tmpwrite+2,strlen(tmpwrite+2)+1);
				strncpy(tmpwrite,"\t",len);
				break;
			default:
				ast_log(LOG_NOTICE, "Substitution routine does not support this character: %c\n",tmpwrite[1]);
			}
			tmpread = tmpwrite+len;
		}
	}
	ast_mutex_unlock(&minivmlock);
	ast_config_destroy(cfg);
	return 0;
}

/*! \brief Reload mini voicemail module */
int reload(void)
{
	return(load_config());
}

/*! \brief Unload mini voicemail module */
int unload_module(void)
{
	int res;
	
	res = ast_unregister_application(app);
	res |= ast_unregister_application(app2);
	res |= ast_unregister_application(app3);
	res |= ast_unregister_application(app4);
	res |= ast_cli_unregister(&show_voicemail_users_cli);
	res |= ast_cli_unregister(&show_voicemail_zones_cli);
	ast_uninstall_vm_functions();
	
	STANDARD_HANGUP_LOCALUSERS;

	return res;
}

/*! \brief Load mini voicemail module */
int load_module(void)
{
	int res;
	res = ast_register_application(app, vm_exec, synopsis_vm, descrip_vm);
	res |= ast_register_application(app2, vm_execmain, synopsis_vmain, descrip_vmain);
	res |= ast_register_application(app3, vm_box_exists, synopsis_vm_box_exists, descrip_vm_box_exists);
	res |= ast_register_application(app4, vmauthenticate, synopsis_vmauthenticate, descrip_vmauthenticate);
	if (res)
		return(res);

	if ((res=load_config())) {
		return(res);
	}

	ast_cli_register(&show_voicemail_users_cli);
	ast_cli_register(&show_voicemail_zones_cli);

	/* compute the location of the voicemail spool directory */
	snprintf(VM_SPOOL_DIR, sizeof(VM_SPOOL_DIR), "%s/voicemail/", ast_config_AST_SPOOL_DIR);

	ast_install_vm_functions(has_voicemail, messagecount);

#if defined(USE_ODBC_STORAGE) && !defined(EXTENDED_ODBC_STORAGE)
	ast_log(LOG_WARNING, "The current ODBC storage table format will be changed soon."
				"Please update your tables as per the README and edit the apps/Makefile "
				"and uncomment the line containing EXTENDED_ODBC_STORAGE to enable the "
				"new table format.\n");
#endif

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

