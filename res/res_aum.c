/*
 * Asterisk -- An open source telephony toolkit.
 *
 * 
 * Asterisk User Management Resource
 *
 * Copyright (C) 2005, Edvina AB, Sollentuna, Sweden.
 *
 * Olle E. Johansson <oej@edvina.net>
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
 * \brief AUM - Asterisk User Management
 *
 * \author Olle E. Johansson <oej@edvina.net>
 *
 * \arg For information about aum, see \ref AUM_desc
 *
 */
 
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <iconv.h>	/* String conversion routines */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 1.19 $")

#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/config.h"
#include "asterisk/channel.h"
#include "asterisk/callerid.h"
#include "asterisk/astobj.h"
#include "asterisk/pbx.h"
#include "asterisk/acl.h"
#include "asterisk/options.h"
#include "asterisk/module.h"
#include "asterisk/app.h"
#include "asterisk/cli.h"
#include "asterisk/manager.h"
#include "asterisk/utils.h"
#include "asterisk/linkedlists.h"
#include "asterisk/aum.h"

/*! AUM user lock */
AST_MUTEX_DEFINE_STATIC(aum_userlock);
/*! AUM group lock */
AST_MUTEX_DEFINE_STATIC(aum_grouplock);

STANDARD_LOCAL_USER;

LOCAL_USER_DECL;

/*! \page AUM_desc Asterisk User Managment - AUM - module 
	\par What is AUM?
	The AUM module implements common user management. A user
	can have one or several voicemail accounts, phones, IM accounts
	and other properties. A common user module mamkes it easier
	to manage passwords, e-mail addresses and properties that belong
	to the person who manages a device.

	\par
	In AUM-enabled Asterisk modules (channels, applications, functions)
	you can refer to the AUMid and thus fetch configuration data from
	the AUM module for common properties.

	\par Currently these modules support AUM:
		- none 

	\par Modules that may benefit from implementing AUM
		- all channel drivers
		- app_disa.c
		- app_voicemail.c
		- app_meetme.c
		- manager.c
		- The Asterisk CLI
		- Parking

	\par The AUM User object
	The AUM user object consist of one general structure and
	linked lists for addresses, contexts and groups.
	When installed, the user inherit properties from the groups.
	\arg \ref aum_user The user object
	\arg \ref aum_group The group object

	\par
	The user has a presence state that can be checked with
	a dial plan function. Presence can be changed from a SIP phone
	with publish or linked to an IM account (if there's code support
	for it).

	\par The AUM Address Object
	The address object consists of a type and a text string.
	The type can be a phone number, SIP uri, IAX number or 
	cell phone number.
	
	We will not add an address type for each service provider
	out there. Instead, there are five "custom" addresses. These
	will be configurable so that they can have different labels,
	depending upon your configuration.

	\par The AUM group object
	Group objects are "master" objects that the User inherits
	properties from.

	There are dial plan functions to check if a user belongs
	to a user group or not.
	
	\par The AUM context object
	...
	\par The AUM string object
	The AUM string object is an encapsulation of a normal C character string,
	terminated with a zero character. It is a linked list of strings 
	where each string is clearly marked with character set.
	If a different character set is asked for, the string handling functions
	will convert and add a new string in a linked list from the first one.

	- String objects are created with aum_string_alloc()
	- String objects are destroyed with aum_string_destroy()

	\par Ideas for AUM presence
	
	Basically, we need to have a few classical PBX presence indicators
	with major status and substatus
	- Away
		- Meeting
		- Sick
		- Travelling
	- Meeting
	- Busy
	- Not reachable (system error, network error)
	- Custom 
		- Custom
	- Agent specific statuses

	For each user, a chain of events need to maintained, current and
	future events. The handling of past events is up to another system.
	
	- For each user, we need to keep track of next planned change.
	- For planned event changes, check whether the time is mandatory
	  (should be executed) or a suggestion (don't time out, just keep
	  current status while waiting for status change).
	  Example:
		- Meeting is planned to 13:00, but ran over to 14:15
		- I am busy to 10:45, open my phone after that.
	
	- We need to store events somewhere (event silo) between reloads
	- Events can come in trough dial plan or manager
	- Current user status can be changed through dialplan functions,
	  manager or IM channels/gateways (Jabber, SIP, other)
	- We need to synch status levels with other IM (SIMPLE/Jabber/XMPP)

	\par Realtime usage
	AUM uses ARA - the realtime architecture - to load users and groups.
	The realtime handles for AUM is
	- \b aumusers	For users
	- \b aumgroups  For the realtime groups
	
	AUM will cache realtime users in memory after we load them.
	Every time a realtime user is accessed, it's moved to top of
	the cache. When we reach the maximum number of cached users,
	AUM mwill delete from the bottom of the cache while adding the
	missing user to the top.
	
	(Actually, the cache is implemented upside down, but I guess
	that does not matter.)

	The AUM cache size will be configurable in the general
	section of aum.conf

	\par Channel usage
	For channels, they can register a device that belongs to
	a user in combination with a callback function. It that callback
	is registred, it will be called each time a user state changes.

	\par Things to do
	- Implement all core AUM api functions from aum.h
		- Revise the list
	- Implement needed function in config engine (if needed)
	- Implement manager functions for AUM
		- Read presence
		- Change presence
	- Implement dial plan functions
		- belong_to_group
		- check_presence
		- get_email_address
		- get_sip_address
	- Implement AUM in channel drivers
		- Implement in chan_sip.c
		- Implement in chan_iax2.c
	- Implement AUM in applications
		- Implement AUM in app_disa.c
		- Implement AUM in app_voicemail.c
	- Implement AUM functions
		- Callback to register devices with AUM - $AUMUSERPHONE()
	- Check if we can merge AUM with 
		- mogorman's jabber patch
		- file's SIP messaging patch
	- Can we use aum_groups as callgroups/pickupgroups?
	- Internationalization issues
		- Learn how to use utf-8 in source code and convert between different
	  	strings (firstname, lastname, sip uri etc)
		- Figure out what character set is used in config and relatime
 	- Investigate the possibility of a chan_user as a proxy channel (ssokol's idea)
	- Implement channel registration and callbacks
	- Continue with other projects
	- \b Remember: It's only software
*/

/*------------------------------- Declarations of static functions ---------*/
enum modulereloadreason {	/* Should be in module.h or something */
        MODULE__LOAD,
        MODULE__RELOAD,
        MODULE_CLI_RELOAD,
        MODULE_MANAGER_RELOAD,
};

static void *aum_allocate(size_t size);
static void aum_free(void *obj);
static void aum_destroy_user(struct aum_user *user);
static void aum_destroy_group(struct aum_group *group);
static struct aum_user *aum_build_user(char *username, struct ast_variable *x, int realtime);
static struct aum_group *aum_build_group(char *groupname, struct ast_variable *x, int realtime);
const char *modulereloadreason2txt(enum modulereloadreason reason);
static const char *aum_addrtype2txt(enum aum_address_type type);
static enum aum_address_type get_addr_type_from_config_option(enum aum_config_options option);
static const char *context_type2str(enum aum_context_type type);


/*! ----------------------------------------
\brief AUM General Configuration 
*/
/*! \brief Configuration file name */
char *aum_config_file = "aum.conf";

/*! \brief AUM debugging */
int aum_debug = 0;

/* Counters */
int aum_static_users;		/*!< Number of in-memory users */
int aum_real_users;		/*!< Number of active realtime users */
int aum_real_groups;		/*!< Number of active realtime groups */
int aum_static_groups;		/*!< Number of in-memory groups */
int aum_real_groups_enabled = 0;	/*!< TRUE If realtime groups are enabled */
int aum_real_users_enabled = 0;		/*!< TRUE if realtime users are enabled */

long aum_memory_used = 0;		/*!< Used memory for the AUM module */

iconv_t	ichandler_utf8_to_iso88591;	/*!< libiconv handler from utf8 to iso8859-1 */
iconv_t	ichandler_iso88591_to_utf8;	/*!< libiconv handler from iso8859- to utf8 */

/*! \brief the AUM Group list */
static struct s_aum_grouplist {
	ASTOBJ_CONTAINER_COMPONENTS(struct aum_group);
} aum_grouplist;

/*! \brief the AUM User list */
static struct s_aum_userlist {
	ASTOBJ_CONTAINER_COMPONENTS(struct aum_user);
} aum_userlist;

/*! \brief The realtime user cache */
struct aum_usercache_struct {
	struct aum_user *user;
	AST_LIST_ENTRY(aum_usercache_struct) list;
};

static int aum_usercache_count = 0;	/*!< Current number of users in user cache */
static int aum_usercache_max;		/*!< Maximum number of users in cache */
#define DEFAULT_USERCACHE_MAX	50

static AST_LIST_HEAD_STATIC(aum_usercache, aum_usercache_struct);	/*!< The user cache for realtime */

/*! brief Different config options for address formats */
static struct aum_address_config_struct aum_address_config[] = {
	{AUM_ADDR_EMAIL, 	"email", 	"E-mail",	AUM_CNF_ADDR_EMAIL},
	{AUM_ADDR_EMAIL, 	"mailto", 	"E-mail",	AUM_CNF_ADDR_EMAIL},
	{AUM_ADDR_XMPP,		"xmpp", 	"XMPP/Jabber",	AUM_CNF_ADDR_XMPP},
	{AUM_ADDR_XMPP,		"jabber", 	"XMPP/Jabber",	AUM_CNF_ADDR_XMPP},	/*! Alias for xmpp */
	{AUM_ADDR_SIP,		"sip", 		"SIP",		AUM_CNF_ADDR_SIP},	
	{AUM_ADDR_MSN,		"msn", 		"MSN",		AUM_CNF_ADDR_MSN},
	{AUM_ADDR_AOL,		"aol", 		"AOL",		AUM_CNF_ADDR_AOL},
	{AUM_ADDR_TEL,		"tel", 		"Tel",		AUM_CNF_ADDR_TEL},
	{AUM_ADDR_TEL,		"phone", 	"Tel",		AUM_CNF_ADDR_TEL},
	{AUM_ADDR_TEL,		"e164", 	"Tel",		AUM_CNF_ADDR_TEL},
	{AUM_ADDR_CELL_TEL,	"cell", 	"Cell",		AUM_CNF_ADDR_CELL_TEL},
	{AUM_ADDR_CELL_TEL,	"mobile", 	"Cell",		AUM_CNF_ADDR_CELL_TEL},
	{AUM_ADDR_IAX2,		"iax", 		"IAX2",		AUM_CNF_ADDR_IAX2},
	{AUM_ADDR_IAX2,		"iax2", 	"IAX2",		AUM_CNF_ADDR_IAX2},
	{AUM_ADDR_FWD,		"fwd", 		"FWD",		AUM_CNF_ADDR_FWD},
	{AUM_ADDR_IAXTEL,	"iaxtel", 	"IAXtel",	AUM_CNF_ADDR_IAXTEL},
	{AUM_ADDR_FAX,		"fax", 		"Fax",		AUM_CNF_ADDR_FAX},
	{AUM_ADDR_WEB,		"homepage", 	"Web",		AUM_CNF_ADDR_WEB},
	{AUM_ADDR_WEB,		"url", 		"Web",		AUM_CNF_ADDR_WEB},
	{AUM_ADDR_WEB,		"http", 	"Web",		AUM_CNF_ADDR_WEB},
	{AUM_ADDR_CUST0,	"cust0", 	"Custom 0",	AUM_CNF_ADDR_CUST0},
	{AUM_ADDR_CUST1,	"cust1", 	"Custom 1",	AUM_CNF_ADDR_CUST1},
	{AUM_ADDR_CUST2,	"cust2", 	"Custom 2",	AUM_CNF_ADDR_CUST2},
	{AUM_ADDR_CUST3,	"cust3", 	"Custom 3",	AUM_CNF_ADDR_CUST3},
	{AUM_ADDR_CUST4,	"cust4", 	"Custom 4",	AUM_CNF_ADDR_CUST4},
};

static struct aum_context_table aum_context_text[] = {
	{AUM_CONTEXT_NONE,		"None" },
	{AUM_CONTEXT_DEF_CB,		"Callback" },
	{AUM_CONTEXT_DEF_INCOMING,	"Incoming" },
	{AUM_CONTEXT_VOICEMAIL,		"Voicemail" },
	{AUM_CONTEXT_DISA,		"Disa" },
	{AUM_CONTEXT_SIPSUBSCRIBE,	"SIPsubscribe" },
};


const char *modulereloadreason2txt(enum modulereloadreason reason)
{
	switch (reason) {
	case MODULE__LOAD:	return "LOAD (Channel module load)";
		break;
	case MODULE__RELOAD:	return "RELOAD (Channel module reload)";
		break;
	case MODULE_CLI_RELOAD:	return "CLIRELOAD (Channel module reload by CLI command)";
		break;
	default:        	return "MANAGERRELOAD (Channel module reload by manager)";
		break;
        };
};

/*! \brief Convert address type to display string */
static const char *aum_addrtype2txt(enum aum_address_type type) {
	int x;
	for (x = 0; x < (sizeof(aum_address_config) / sizeof(struct aum_address_config_struct)); x++) {
		if (aum_address_config[x].type == type)
			return aum_address_config[x].display;
	}
	return "";
}

/*----------------------------- CLI COMMANDS ----------------------*/
/*! \brief  print_group: Print call group and pickup group ---*/
static void  print_group(int fd, unsigned int group, int crlf) 
{
	char buf[256];
	ast_cli(fd, crlf ? "%s\r\n" : "%s\n", ast_print_group(buf, sizeof(buf), group) );
}


/*! \brief CLI command description */
static char cli_aum_show_stats_usage[] = 
"Usage: aum show stats\n"
"	Displays some AUM statistics.\n";

/*! \brief CLI command "aum show stats" */
static int cli_aum_show_stats(int fd, int argc, char *argv[])
{

	if (argc != 3)
		return RESULT_SHOWUSAGE;
	ast_cli(fd, "AUM Statistics\n");
	ast_cli(fd, "--------------\n\n");
	ast_cli(fd, "  Allocated memory:      %-10.10ld\n", aum_memory_used);
	ast_cli(fd, "  Users - static:        %-10.10d\n", aum_static_users);
	ast_cli(fd, "  Groups - static:       %-10.10d\n", aum_static_groups);
	if (aum_real_users_enabled)
		ast_cli(fd, "  Users - realtime:      %-10.10d\n", aum_real_users);
	if (aum_real_groups_enabled)
		ast_cli(fd, "  Groups - realtime:     %-10.10d\n", aum_real_groups);
	if (aum_real_users_enabled)
		ast_cli(fd, "  Realtime cache:        %d objects (%-10.10d kb) %d %% full\n", aum_usercache_count, (aum_usercache_count * (sizeof(struct aum_user) + sizeof(struct aum_usercache_struct)) / 1000), (int) (aum_usercache_count / aum_usercache_max * 100 ) );
	ast_cli(fd, "\n\n");
	
	return RESULT_SUCCESS;
}

/*! \brief CLI command description */
static char cli_aum_show_users_usage[] = 
"Usage: aum show users\n"
"	Lists all configured AUM users.\n"
"	For details on a specific user, use \"aum show user <name>\"\n";

/*! \brief CLI command "aum show users" */
static int cli_aum_show_users(int fd, int argc, char *argv[])
{
	int numusers = 0;

	if (argc != 3)
		return RESULT_SHOWUSAGE;

	if (argc != 3)
		return RESULT_SHOWUSAGE;
	
	ASTOBJ_CONTAINER_TRAVERSE(&aum_userlist, 1, {
		ASTOBJ_RDLOCK(iterator);
		if (!ast_test_flag(iterator, AUM_USER_FLAG_REALTIME)) {
			ast_cli(fd, " %-20.20s: %-10.10s %-15.15s %-10.10s %s\n", iterator->name, iterator->first_name, iterator->last_name, iterator->numuserid, ast_test_flag(iterator, AUM_USER_FLAG_DISABLED) ? "* DISABLED *" : "");
			numusers ++;
		}
		ASTOBJ_UNLOCK(iterator);
	} );
	ast_cli(fd, "-- Number of users: %d\n", numusers);
	
	return RESULT_SUCCESS;
}

static char cli_aum_load_rtuser_usage[] = 
"Usage: aum load rtuser <user>\n"
"	Loads a user from realtime storage into the AUM realtime cache.\n"
"	For a list of all static users, use \"aum show users\"\n";

/*! \brief Load an realtime user */
static int cli_aum_load_rtuser(int fd, int argc, char *argv[])
{
	struct aum_user *user;
	if (!aum_real_users_enabled) {
		ast_cli(fd, "Realtime AUM is not enabled in extconfig.conf.\n");
		return RESULT_SUCCESS;
	}
	if (argc != 4)
		return RESULT_SHOWUSAGE;

	if (option_debug)
		ast_log(LOG_DEBUG, "Trying to find realtime user %s to show... \n", argv[3]);

	user = find_aum_user(argv[3], TRUE);
	if (!user) {
		ast_cli(fd, "- AUM user %s not found\n", argv[3]);
		return RESULT_SUCCESS;
	}
	if (ast_test_flag(user, AUM_USER_FLAG_REALTIME)) {
		ast_cli(fd, "User %s is not a realtime user\n", argv[3]);
		return RESULT_SUCCESS;
	}
	ast_cli(fd, "* Userid %s loaded in realtime cache. \n", user->name);
	ast_cli(fd, "  Realtime cache:        %d objects (%-10.10d kb) %d %% full\n", aum_usercache_count, (aum_usercache_count * (sizeof(struct aum_user) + sizeof(struct aum_usercache_struct)) / 1000), (int) (aum_usercache_count / aum_usercache_max * 100 ) );
	ast_cli(fd, "\n");

	return RESULT_SUCCESS;
}

/*! \brief CLI command description */
static char cli_aum_show_user_usage[] = 
"Usage: aum show user <user>\n"
"	Lists details about one AUM user, either static or a realtime user in the realtime cache.\n"
"	To load a user in the realtime cache, use \"aum load rtuser\"\n"
"	For a list of all static users, use \"aum show users\"\n";

/*! \brief CLI command "aum show user" */
static int cli_aum_show_user(int fd, int argc, char *argv[])
{
	struct aum_group_member *member;
	struct aum_context *context;
	struct aum_address *addr;
	struct aum_user *user;

	if (argc != 4)
		return RESULT_SHOWUSAGE;
	ast_log(LOG_DEBUG, "Trying to find user %s to show... \n", argv[3]);

	user = find_aum_user(argv[3], FALSE);
	if (!user) {
		ast_cli(fd, "- AUM user %s not found\n", argv[3]);
		return RESULT_SUCCESS;
	}
	ast_cli(fd, "* Userid:        %s\n", user->name);

	if (ast_test_flag(user, AUM_USER_FLAG_REALTIME))
		ast_cli(fd, " Usertype:   Realtime (cached)\n");
	else
		ast_cli(fd, " Usertype:   Static\n");

	if (ast_test_flag(user, AUM_USER_FLAG_DISABLED))
		ast_cli(fd, " Status:     Disabled\n");
	else
		ast_cli(fd, " Status:     Enabled\n");

	if (!ast_strlen_zero(user->title))
		ast_cli(fd, " Title:      %s\n", user->title);
	if (!ast_strlen_zero(user->last_name))
		ast_cli(fd, " Name:       %s %s\n", user->first_name, user->last_name);
	
	AST_LIST_TRAVERSE(&user->groups, member, list) {
		ast_cli(fd, " Member of:  %s\n", member->group->name);
	};

	AST_LIST_TRAVERSE(&user->address, addr, list) {
		ast_cli(fd, " Address:    %s - %s\n", aum_addrtype2txt(addr->type), addr->address);
	};

	AST_LIST_TRAVERSE(&user->contexts, context, list) {
		ast_cli(fd, " %s Context : %s\n", context_type2str(context->type), context->context);
	};
	ast_cli(fd, "  Callgroup:     ");
	print_group(fd, user->callgroup, 0);
	ast_cli(fd, "  Pickupgroup:   ");
	print_group(fd, user->pickupgroup, 0);
	ast_cli(fd, " Numeric ID :    %s\n", user->numuserid);
	ast_cli(fd, " Secret :        %s\n", !ast_strlen_zero(user->secret) ? "<set>" : "<not set>");
	ast_cli(fd, " Music class:    %s\n", user->musicclass);
	ast_cli(fd, " Language:       %s\n", user->language);
	ast_cli(fd, " Mailbox:        %s\n", user->mailbox);
	ast_cli(fd, " ACL:            %s\n", (user->acl?"Yes (IP address restriction)":"No"));
	if (user->chanvars) {
		struct ast_variable *v;
 		ast_cli(fd, "  Variables    :\n");
		for (v = user->chanvars ; v ; v = v->next)
 			ast_cli(fd, "                 %s = %s\n", v->name, v->value);
	}
	ast_cli(fd,"\n");
	
	return RESULT_SUCCESS;
}

/*! \brief CLI command description */
static char cli_aum_show_group_usage[] = 
"Usage: aum show group <group>\n"
"	Lists details about one AUM group.\n"
"	For a list of all static groups, use \"aum show groups\"\n";

/*! \brief CLI command "aum show group" */
static int cli_aum_show_group(int fd, int argc, char *argv[])
{
	struct aum_address *addr;
	struct aum_context *context;
	struct aum_group *group;
	struct aum_group_member *member;
	int groupmembers = 0;

	if (argc != 4)
		return RESULT_SHOWUSAGE;
	ast_log(LOG_DEBUG, "Trying to find group %s to show... \n", argv[3]);

	group = find_aum_group_by_name(argv[3]);
	if (!group) {
		ast_cli(fd, "- AUM group %s not found\n", argv[3]);
		return RESULT_SUCCESS;
	}
	ast_cli(fd, "* Group:         %s\n", group->name);
	AST_LIST_TRAVERSE(&group->members, member, list) {
		groupmembers++;
	};
	ast_cli(fd, " Number of members: %d\n", groupmembers);

	//if (ast_test_flag(group, AUM_USER_FLAG_REALTIME))
		//ast_cli(fd, " Usertype:   Realtime (cached)\n");
	//else
		//ast_cli(fd, " Usertype:   Static\n");

	//if (ast_test_flag(group, AUM_USER_FLAG_DISABLED))
		//ast_cli(fd, " Status:     Disabled\n");
	//else
		//ast_cli(fd, " Status:     Enabled\n");

	if (!ast_strlen_zero(group->description))
		ast_cli(fd, " Description:       %s\n", group->description);
	
	AST_LIST_TRAVERSE(&group->contexts, context, list) {
		ast_cli(fd, " %s Context : %s\n", context_type2str(context->type), context->context);
	};
	ast_cli(fd, "  Callgroups:    ");
	print_group(fd, group->callgroup, 0);
	ast_cli(fd, "  Pickupgroups:  ");
	print_group(fd, group->pickupgroup, 0);
	ast_cli(fd, " Music class:    %s\n", group->musicclass);
	ast_cli(fd, " Language:       %s\n", group->language);
	ast_cli(fd, " ACL:            %s\n", (group->acl?"Yes (IP address restriction)":"No"));
	if (group->chanvars) {
		struct ast_variable *v;
 		ast_cli(fd, "  Variables    :\n");
		for (v = group->chanvars ; v ; v = v->next)
 			ast_cli(fd, "                 %s = %s\n", v->name, v->value);
	}
	ast_cli(fd,"\n");
	
	return RESULT_SUCCESS;
}

/*! \brief CLI command description */
static char cli_aum_show_groups_usage[] = 
"Usage: aum show groups\n"
"	Lists all configured AUM groups.\n"
"	For details on a specific group, use \"aum show group <name>\"\n";


/*! \brief CLI command "aum show groups" */
static int cli_aum_show_groups(int fd, int argc, char *argv[])
{
	int numgroups = 0;

	if (argc != 3)
		return RESULT_SHOWUSAGE;
	
	ASTOBJ_CONTAINER_TRAVERSE(&aum_grouplist, 1, {
		ASTOBJ_RDLOCK(iterator);
		ast_cli(fd, " %-20.20s %55s\n", iterator->name, (iterator->description ? iterator->description : "") );
		numgroups ++;
		ASTOBJ_UNLOCK(iterator);
	} );

	ast_cli(fd, "-- %d AUM groups\n\n", numgroups);

	return RESULT_SUCCESS;
}



/*! \brief CLI entries for the AUM module */
static struct ast_cli_entry my_clis[] = {
	{ { "aum", "show", "groups", NULL }, cli_aum_show_groups, "List AUM groups", cli_aum_show_groups_usage },
	{ { "aum", "show", "group", NULL }, cli_aum_show_group, "List details of AUM group", cli_aum_show_group_usage },
	{ { "aum", "show", "users", NULL }, cli_aum_show_users, "List AUM users", cli_aum_show_users_usage },
	{ { "aum", "show", "user", NULL }, cli_aum_show_user, "List details of AUM user", cli_aum_show_user_usage },
	{ { "aum", "show", "stats", NULL }, cli_aum_show_stats, "Display AUM statistics", cli_aum_show_stats_usage },
	{ { "aum", "load", "rtuser", NULL }, cli_aum_load_rtuser, "Load realtime AUM user in cache", cli_aum_load_rtuser_usage },
};

/*----------------------------- DIALPLAN FUNCTIONS ---------------------*/
static char *func_aumuser_read(struct ast_channel *chan, char *cmd, char *data, char *buf, size_t len)
{
	struct aum_user *user;
	char *s, *args[2];
	char *username, *param;
	int error = 0;
	char *res = NULL;

	buf[0] = '\0';	/* Reset buffer */

	if (!data) {
		error = 1;
	} else {
		s = ast_strdupa((char *) data);
		if (!s) {
			error = 1;
		} else {
			ast_app_separate_args(s, '|', args, 2);
			username = args[0];
			param = args[1];
			if (!param)
				error = 1;
		}
	}

	if (error) {
		ast_log(LOG_ERROR, "This function requires two parameters.\n");
		return (char*) NULL;
	}
	user = find_aum_user(username, FALSE);
	if (!user) {
		ast_log(LOG_ERROR, "AUM user ID %s not found.\n", username);
		return (char*) NULL;
	}
	if (!strcasecmp(param, "email")) {
		res = aum_find_email_full(user);
	} else if (!strcasecmp(param, "xmpp")) {
		res = aum_find_address(user, AUM_ADDR_XMPP);
	} else if (!strcasecmp(param, "sip")) {
		res = aum_find_address(user, AUM_ADDR_SIP);
	} else if (!strcasecmp(param, "tel")) {
		res = aum_find_address(user, AUM_ADDR_TEL);
	} else if (!strcasecmp(param, "iax2")) {
		res = aum_find_address(user, AUM_ADDR_IAX2);
	} else if (!strcasecmp(param, "fwd")) {
		res = aum_find_address(user, AUM_ADDR_FWD);
	} else if (!strcasecmp(param, "cust0")) {
		res = aum_find_address(user, AUM_ADDR_CUST0);
	} else if (!strcasecmp(param, "cust1")) {
		res = aum_find_address(user, AUM_ADDR_CUST1);
	} else if (!strcasecmp(param, "cust2")) {
		res = aum_find_address(user, AUM_ADDR_CUST2);
	} else if (!strcasecmp(param, "cust3")) {
		res = aum_find_address(user, AUM_ADDR_CUST3);
	} else if (!strcasecmp(param, "cust4")) {
		res = aum_find_address(user, AUM_ADDR_CUST4);
	} else if (!strcasecmp(param, "numuserid")) {
		res = user->numuserid;
	} else if (!strcasecmp(param, "pincode")) {
		res = user->pincode;
	} else if (!strcasecmp(param, "firstname")) {
		res = user->first_name;
	} else if (!strcasecmp(param, "lastname")) {
		res = user->first_name;
	} else if (!strcasecmp(param, "title")) {
		res = user->title;
	} else if (!strcasecmp(param, "musicclass")) {
		res = user->musicclass;
	} else if (!strcasecmp(param, "language")) {
		res = user->language;
	} else if (!strcasecmp(param, "accountcode")) {
		res = user->accountcode;
	} else if (!strcasecmp(param, "cidnum")) {
		 res = user->cid_num;
	} else if (!strcasecmp(param, "cidname")) {
		 res = user->cid_name;
	} else if (!strcasecmp(param, "name")) {
		 snprintf(buf, sizeof(buf), "%s %s", user->first_name, user->last_name);
	} else if (!strcasecmp(param, "vmbox")) {
		 snprintf(buf, sizeof(buf), "%s@%s", user->mailbox, aum_find_user_context(user, AUM_CONTEXT_VOICEMAIL));
	} else {
		ast_log(LOG_ERROR, "Unknown parameter: %s\n", param);
		return (char*) NULL;
	}

	if (res)
		ast_copy_string(buf, res, len);
	return buf;
}

/*! Dial plan function AUM-USER */
struct ast_custom_function aum_user_function = {
	.name = "AUM-USER",
	.synopsis = "Gets AUM User information",
	.syntax = "AUM-USER(<userid>,<param>)",
	.read = func_aumuser_read,
	.desc = "Valid parameters are:\n"
	"- name			First and last name\n"
	"- firstname		First name\n"
	"- lastname		Last name\n"
	"- email		Email address\n"
	"- xmpp			XMPP/Jabber address\n"
	"- sip			SIP address\n"
	"- tel			Telephone number\n"
	"- iax2			IAX2 address\n"
	"- fwd			FWD number\n"
	"- numuserid		Numeric User ID\n"
	"- pincode		User's Pincode\n"
	"- musicclass		Default music class (MOH)\n"
	"- accountcode		Account code\n"
	"- vmbox		Voicemail box for user (mbox@vmcontext)\n"
	"- cidnum		Caller ID number\n"
	"- cidname		Caller ID name\n"
	"\n",
};

/*-------------------------AUM_STRING SUPPORT--------------------------*/
static struct aum_string_convert aum_string_labels[] = {
	{ AUM_CHAR_ASCII,	"ASCII"	},
	{ AUM_CHAR_ISO8859_1,	"ISO8859-1"	},
	{ AUM_CHAR_ISO8859_2,	"ISO8859-2"	},
	{ AUM_CHAR_ISO8859_3,	"ISO8859-3"	},
	{ AUM_CHAR_UTF8,	"UTF8"	},
};

aum_string *aum_string_alloc(char *string, enum aum_string_charset charset)
{
	aum_string *temp = NULL;
	if (!string || charset == AUM_CHAR_UNKNOWN)
		return temp;	/* Null */

	temp = (aum_string *) aum_allocate(sizeof(aum_string));
	temp->charset = charset;
	temp->string = strdup(string);
	temp->size = sizeof(temp->string);
	aum_memory_used += (long) temp->size;

	return temp;	
}

void aum_string_destroy(aum_string *string)
{
	aum_free(string->string);
	aum_free(string);
}

aum_string *aum_string_add_charset_variant(aum_string *string, enum aum_string_charset charset)
{
	aum_string *temp = string;
	aum_string *new = (aum_string *) NULL;
	char buf[BUFSIZ];
	size_t newsize = 0, insize, outsize;
	enum aum_string_charset fromcharset;
	char *inbuf;

	while (temp && temp->charset != charset)
		temp = (aum_string *) temp->next;

	if (temp)	/* We got a string already */
		return temp;
	
	fromcharset = string->charset;
	insize = sizeof(string->string);
	outsize = sizeof(buf);
	inbuf = string->string;
	if (fromcharset == AUM_CHAR_UTF8) {
		switch (charset) {
			case AUM_CHAR_ISO8859_1:
				newsize = iconv(ichandler_utf8_to_iso88591, &inbuf, &insize, &buf, &outsize);
				break;
			case AUM_CHAR_ASCII:
				ast_log(LOG_DEBUG, "Don't know how to convert from utf to ascii yet...\n");
				break;
			default:
				ast_log(LOG_DEBUG, "Don't know how to convert from utf to unknown charset yet...\n");
				break;
		}
	} else if (fromcharset == AUM_CHAR_ISO8859_1) {
		switch (charset) {
			case AUM_CHAR_UTF8:
				newsize = iconv(ichandler_iso88591_to_utf8, &inbuf, &insize, &buf, &outsize);
				break;
			case AUM_CHAR_ASCII:
				ast_log(LOG_DEBUG, "Don't know how to convert from ISO8859-1 to ascii yet...\n");
				break;
			default:
				ast_log(LOG_DEBUG, "Don't know how to convert from utf to unknown charset yet...\n");
				break;
		}
	}
	if (newsize == (size_t) -1)	/* Could not convert */
		/* If errno == EILSEQ	Illegal multibyte sequence */
		/* If errno == EINVAL	Invalid multibyte sequence */
		/* If errno == E2BIG	Output buffer too small */
		return temp;		/* ??? */

	new = aum_string_alloc(buf, charset);	/* Allocate object */

	/* Link it in */
	temp = string->next;
	string->next = new;
	new->next = temp;

	return new;
	
}


/*------------------------- CONFIGURATION ------------------------------*/
static struct aum_config_struct aum_config[] = {
	{ AUM_CNF_ADDR_EMAIL,	"email" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_XMPP,	"xmpp" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_XMPP,	"jabber" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_SIP,	"sip" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_IAX2,	"iax" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_AOL,	"aol" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_MSN,	"msn" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_TEL,	"tel" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_CELL_TEL,"cell" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_FAX,	"fax" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_CUST0,	"cust0" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_CUST1,	"cust1" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_CUST2,	"cust2" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_CUST3,	"cust3" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_ADDR_CUST4,	"cust4" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_PIN,		"pin" 		,AUM_CONFOBJ_USER },
	{ AUM_CNF_VMAILBOX,	"mailbox" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_GROUP,	"group" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_CALLBACKEXT,	"extension" 	,AUM_CONFOBJ_USER },	/*!< Default extension */
	{ AUM_CNF_DEFCONTEXT,	"context" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_SUBSCRIBECONTEXT,	"subscribecontext" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_DISACONTEXT,	"disacontext" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_PARKING,	"parking" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_CID,		"callerid" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_CALLERPRES,	"callerpres" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_ACCOUNTCODE,	"accountcode" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_MANAGERACCESS,"managerperm" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_SECRET,	"secret" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_IAX2KEY,	"iax2key" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_MUSICCLASS,	"musicclass" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_LDAPDN,	"ldapdn" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_FIRSTNAME,	"firstname" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_LASTNAME,	"lastname" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_TITLE,	"title" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_LANGUAGE,	"language" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_SOUNDNAME,	"audioname" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_CHANVAR,	"chanvar" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_PERMIT,	"permit" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_DENY,		"deny" 		,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_NUMID,	"numericid" 	,AUM_CONFOBJ_USER },
	{ AUM_CNF_SIPDOMAIN,	"sipdomain" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_CALLGROUP,	"callgroup" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_PICKUPGROUP,	"pickupgroup" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_GROUPVAR,	"changroup" 	,AUM_CONFOBJ_USER & AUM_CONFOBJ_GROUP },
	{ AUM_CNF_GROUPDESC,	"description" 	,AUM_CONFOBJ_GROUP },
	{ AUM_CNF_TYPE,		"type" 		,AUM_CONFOBJ_GENERAL },
	{ AUM_CNF_DEBUG,	"debug" 	,AUM_CONFOBJ_GENERAL },
};


/*! \brief Add AUM user to a group */
static int add_user_to_group(struct aum_group *group, struct aum_user *user)
{
	struct aum_group_member *member;

	if (!group || !user)
		return -1;	/* Error */

	member = aum_allocate(sizeof(struct aum_group_member)); 
	if (!member)
		return -1;	/* Memory allocation */
	
	/* Link list from user to groups */
	member->group = group;
	AST_LIST_INSERT_TAIL(&user->groups, member, list);

	member = aum_allocate(sizeof(struct aum_group_member)); 
	if (!member)
		return -2;	/* Group membership failed */

	/* Link list from groups to users */
	member->user = user;
	AST_LIST_INSERT_TAIL(&group->members, member, list);
	return 0;		/* Success */
}


/*! \brief Parse configuration file label, check if it's valid in this 
     object context and return label */
static enum aum_config_options aum_config_parse(char *label, enum aum_config_objects object)
{
	int x;

	for (x = 0; x < (sizeof(aum_config) / sizeof(struct aum_config_struct)); x++) {
		if (!strcmp(aum_config[x].label, label)) {
			if (aum_config[x].valid & object)
				return aum_config[x].option;
			else
				return AUM_CNF_NOT_VALID_FOR_OBJECT;
		}
	};
	return AUM_CNF_NOT_FOUND;
}

/*! \brief Allocate and calculate total memory used */
static void *aum_allocate(size_t size)
{
	void *obj = malloc(size);
	if (obj) {
		aum_memory_used += (long) size;
		memset(obj, 0, size);
	} else
		ast_log(LOG_ERROR, "Out of memory in AUM allocation. Memory used: %ld\n", aum_memory_used);

	return obj;
}

/*! \brief Free allocated memory */
static void aum_free(void *obj)
{
	size_t sajz = sizeof(*obj);
	aum_memory_used -= (long) sajz;
	free(obj);
}

/*! \brief Get address type from configuration option */
static enum aum_address_type get_addr_type_from_config_option(enum aum_config_options option)
{
	int x;
	for (x = 0; x < (sizeof(aum_address_config) / sizeof(struct aum_address_config_struct)); x++) {
		if (aum_address_config[x].configoption == option)
			return aum_address_config[x].type;
	}
	return AUM_ADDR_NONE;
}

/*! \brief Get context description from context type */
static const char *context_type2str(enum aum_context_type type)
{
	int x;
	for (x = 0; x < (sizeof(aum_context_text) / sizeof(struct aum_context_table)); x++) {
		if (aum_context_text[x].type == type)
			return aum_context_text[x].desc;
	}
	
	return (const char *) "";
}

/*! \brief Build address object from config file */
static struct aum_address *build_address(enum aum_address_type type, enum aum_config_options option, char *address)
{
	struct aum_address *add_obj = (struct aum_address *) NULL;

	if (type==AUM_ADDR_NONE && option == AUM_CNF_NONE)
		return add_obj;

	if (type == AUM_ADDR_NONE)
		type = get_addr_type_from_config_option(option);

	
	/* Allocate object and reset memory */
	add_obj = aum_allocate(sizeof(struct aum_address));
	if (!add_obj)
		return add_obj;
	ast_copy_string(add_obj->address, address, sizeof(add_obj->address));
 	add_obj->type = type;
	add_obj->active = 1;	

	if (option_debug > 1)
		ast_log(LOG_DEBUG, "=== Added address %s \n", address);

	return add_obj;
}

/*! \brief Buld context object */
static struct aum_context *build_context(enum aum_context_type type, enum aum_config_options option, char *context)
{
	struct aum_context *newcontext = (struct aum_context *) NULL;

	if (type==AUM_CONTEXT_NONE && option == AUM_CNF_NONE)
		return newcontext;

	if (type == AUM_CONTEXT_NONE) {
		switch (option) {
		case AUM_CNF_PARKING:
			type = AUM_CONTEXT_PARKING;
			break;
		case AUM_CNF_DISACONTEXT:
			type = AUM_CONTEXT_DISA;
			break;
		case AUM_CNF_SUBSCRIBECONTEXT:
			type = AUM_CONTEXT_SIPSUBSCRIBE;
			break;
		case AUM_CNF_DEFCONTEXT:
			type = AUM_CONTEXT_DEF_INCOMING;
			break;
		default:
			type = AUM_CONTEXT_NONE;
			break;
		}
	}

	newcontext = aum_allocate(sizeof(struct aum_context));
	if (!newcontext)
		return newcontext;
	ast_copy_string(newcontext->context, context, sizeof(newcontext->context));
	newcontext->type = type;

	if (option_debug > 1)
		ast_log(LOG_DEBUG, "=== Added context %s \n", context);

	return newcontext;
}


/*! \brief Release all cached realtime users */
static void aum_rtcache_freeall(void) {
	struct aum_usercache_struct *temp;

	AST_LIST_LOCK(&aum_usercache);

	if (!AST_LIST_EMPTY(&aum_usercache) ) {
		AST_LIST_LOCK(&aum_usercache);
		while ((temp = AST_LIST_REMOVE_HEAD(&aum_usercache, list))) {
			aum_destroy_user(temp->user);
			free(temp);
		}
		AST_LIST_UNLOCK(&aum_usercache);
	}
	aum_real_users = 0;
}

/*! \brief Add realtime user to top of the cache  (actually, the end of the list)
	If the cache is full, the user at the top of the cache is
	simply removed from memory
	\param user AUM user to add to the bottom
*/
static void aum_rtcache_add(struct aum_user *user) {
	struct aum_usercache_struct *temp;
	struct aum_usercache_struct *aums;

	aums = aum_allocate(sizeof(struct aum_usercache_struct));
	if (!aums)
		return;		/* Allocation error */
	
	aums->user = user;
	
	/* Check whether we need to clean up before adding to list */
	if (aum_usercache_count == aum_usercache_max) {
		/* Remove user from cache and delete */
		AST_LIST_LOCK(&aum_usercache);
		temp = AST_LIST_REMOVE_HEAD(&aum_usercache, list);
		AST_LIST_UNLOCK(&aum_usercache);
		aum_destroy_user(temp->user);
		free(temp);
		aum_usercache_count--;
		aum_real_users-- ;
	}

	/* Move it into the list */
	AST_LIST_LOCK(&aum_usercache);
	AST_LIST_INSERT_TAIL(&aum_usercache, aums, list);
	AST_LIST_UNLOCK(&aum_usercache);
	aum_usercache_count++;

	return;
}

/*! \brief Move realtime cache object to bottom of cache (we remove from top)
	Called when a user object is accessed
*/
static void aum_rtcache_movetotop(struct aum_user *user) {
	struct aum_usercache_struct *temp;
	struct aum_usercache_struct *top_of_the_class = (struct aum_usercache_struct *) NULL;

	AST_LIST_LOCK(&aum_usercache);
	/* Find user in cache */
	AST_LIST_TRAVERSE_SAFE_BEGIN(&aum_usercache, temp, list) {
		if (temp->user == user) {
			top_of_the_class = temp;
			/* Remove from current position in list */
			AST_LIST_REMOVE_CURRENT(&aum_usercache, list);
		}
	};
	AST_LIST_TRAVERSE_SAFE_END;
	/* Add her to top */
	if (top_of_the_class) 
		AST_LIST_INSERT_TAIL(&aum_usercache, top_of_the_class, list);

	AST_LIST_UNLOCK(&aum_usercache);

	/* Return */
}

/*!< Add channel variable to list 
 * 	\param var	AST_variable, list pointer
 * 	\param name	Name of variable
 * 	\param value	Value -	if value is NULL name is supposed to contain both name and value with = sign between them
 * 	\return 	Head of variable list
 */
static struct ast_variable *add_variable_to_list(struct ast_variable *var, char *name, char *value)
{
	char *varname = name;
	char *varval = value;
	struct ast_variable *tmpvar = (struct ast_variable *) NULL;

	if (!value) {	/* No value, both are to be found in name */
		varname = ast_strdupa(name);
		if (varname && (varval = strchr(varname,'='))) {
			*varval = '\0';
			varval++;
		}
	}

	if (varname && varval)
	if (!(tmpvar = ast_variable_new(varname, varval))) 
		return var;

	tmpvar->next = var;

	return tmpvar;
}

/*! \brief Parse configuration file and build AUM in-memory user

	All static users are stored in memory for fast access
	Some memory parts are loaded on demand and cached

	\param	username	Name of new user
	\param	x		Configuration entries
	\param realtime		True if realtime group (Not implemented yet)
*/
static struct aum_user *aum_build_user(char *username, struct ast_variable *x, int realtime)
{
	struct aum_user *user;
	struct aum_address *address;
	struct aum_context *context;
	enum aum_config_options option;

	/* Check if username exists already, do not check realtime again */
	if (find_aum_user(username, FALSE)) {
		ast_log(LOG_WARNING, "Ignoring duplicate user %s\n", username);
		return NULL;
	}

	/* Allocate user */
	user = aum_allocate(sizeof(struct aum_user));
	if (!user) {
		ast_log(LOG_WARNING, "Can't allocate AUM user memory\n");
		return NULL;
	}

	ASTOBJ_INIT(user);
	AST_LIST_HEAD_INIT(&user->address);
	AST_LIST_HEAD_INIT(&user->groups);
	ast_copy_string(user->name, username, sizeof(user->name));
	ast_log(LOG_VERBOSE, "-- Building user: %s\n", username);
	while (x) {
		ast_log(LOG_DEBUG, "---- User attribute: %s = %s\n", x->name, x->value);
		option = aum_config_parse(x->name, AUM_CONFOBJ_USER);
		switch (option) {
		case AUM_CNF_ADDR_EMAIL:
		case AUM_CNF_ADDR_XMPP:
		case AUM_CNF_ADDR_SIP:
		case AUM_CNF_ADDR_IAX2:
		case AUM_CNF_ADDR_AOL:
		case AUM_CNF_ADDR_MSN:
		case AUM_CNF_ADDR_TEL:
		case AUM_CNF_ADDR_CELL_TEL:
		case AUM_CNF_ADDR_FAX:
		case AUM_CNF_ADDR_FWD:
		case AUM_CNF_ADDR_IAXTEL:
		case AUM_CNF_ADDR_WEB:
		case AUM_CNF_ADDR_CUST0:
		case AUM_CNF_ADDR_CUST1:
		case AUM_CNF_ADDR_CUST2:
		case AUM_CNF_ADDR_CUST3:
		case AUM_CNF_ADDR_CUST4:
			address = build_address(AUM_ADDR_NONE, option, x->value);
			/* Link this address to user list */
			if (address)
				AST_LIST_INSERT_TAIL(&user->address, address, list);
			else
				ast_log(LOG_ERROR, "Address %s not added for user %s\n", x->value, username);
			break;
		case AUM_CNF_VMAILBOX:
			break;
		case AUM_CNF_GROUP:
			if (add_user_to_group(find_aum_group_by_name(x->value), user) < 0)
				ast_log(LOG_ERROR, "Could not add user %s to group %s\n", user->name, x->value);
			break;
		case AUM_CNF_CALLBACKEXT:
			break;
		case AUM_CNF_DEFCONTEXT:
		case AUM_CNF_SUBSCRIBECONTEXT:
		case AUM_CNF_DISACONTEXT:
		case AUM_CNF_PARKING:
			break;
			context = build_context(AUM_CONTEXT_NONE, option, x->value);
			if (context)
				AST_LIST_INSERT_TAIL(&user->contexts, context, list);
			else
				ast_log(LOG_ERROR, "Context %s not added for user %s\n", x->value, username);
			break;
		case AUM_CNF_DEFEXTEN:
			ast_copy_string(user->default_exten, x->value, sizeof(user->default_exten));
			break;
		case AUM_CNF_CID:
			ast_callerid_split(x->value, user->cid_name, sizeof(user->cid_name), user->cid_num, sizeof(user->cid_num));
			break;
		case AUM_CNF_CALLERPRES:
			user->calling_pres = ast_parse_caller_presentation(x->value);
			if (user->calling_pres == -1)
				user->calling_pres = atoi(x->value);
				
			break;
		case AUM_CNF_TIMEZONE:
			break;
		case AUM_CNF_CALLGROUP:
			user->callgroup = ast_get_group(x->value);
			break;
		case AUM_CNF_PICKUPGROUP:
			user->pickupgroup = ast_get_group(x->value);
			break;
		case AUM_CNF_ACCOUNTCODE:
			ast_copy_string(user->accountcode, x->value, sizeof(user->accountcode));
			break;
		case AUM_CNF_MANAGERACCESS:
			break;
		case AUM_CNF_SECRET:
			ast_copy_string(user->secret, x->value, sizeof(user->secret));
			break;
		case AUM_CNF_PIN:
			ast_copy_string(user->pincode, x->value, sizeof(user->pincode));
			break;
		case AUM_CNF_IAX2KEY:
			ast_copy_string(user->pincode, x->value, sizeof(user->pincode));
			break;
		case AUM_CNF_MUSICCLASS:
			ast_copy_string(user->musicclass, x->value, sizeof(user->musicclass));
			break;
		case AUM_CNF_LDAPDN:
			break;
		case AUM_CNF_FIRSTNAME:
			ast_copy_string(user->first_name, x->value, sizeof(user->first_name));
			break;
		case AUM_CNF_LASTNAME:
			ast_copy_string(user->last_name, x->value, sizeof(user->last_name));
			break;
		case AUM_CNF_TITLE:
			ast_copy_string(user->title, x->value, sizeof(user->title));
			break;
		case AUM_CNF_SOUNDNAME:
			break;
		case AUM_CNF_CHANVAR:
			/* Set peer channel variable */
			user->chanvars = add_variable_to_list(user->chanvars, x->value, NULL);
			break;
		case AUM_CNF_GROUPVAR:	/* Channel group to set */
			// chanvars GROUP
			break;
		case AUM_CNF_PERMIT:
		case AUM_CNF_DENY:
			// ACL
			user->acl = ast_append_ha(x->name, x->value, user->acl);
			break;
		case AUM_CNF_NUMID:
			ast_copy_string(user->numuserid, x->value, sizeof(user->numuserid));
			break;
		case AUM_CNF_DEBUG:	/* GENERAL setting only */
			break;
		case AUM_CNF_GROUPDESC:	/* Only for groups */
			break;
		case AUM_CNF_TYPE:	/* NO op */
			break;
		case AUM_CNF_LANGUAGE:
			ast_copy_string(user->language, x->value, sizeof(user->language));
			break;
		case AUM_CNF_SIPDOMAIN:
			break;
		case AUM_CNF_NOT_FOUND:
			ast_log(LOG_NOTICE, "Configuration label unknown in AUM configuration: %s\n", x->name);
			break;
		case AUM_CNF_NOT_VALID_FOR_OBJECT:
			ast_log(LOG_NOTICE, "Configuration label not valid for user objects in AUM configuration: %s\n", x->name);
			break;
		case AUM_CNF_NONE:	/* Should not be here */
			break;

		}
		
		x = x->next;
	}
	ASTOBJ_CONTAINER_LINK(&aum_userlist, user);
	if (realtime) 
		aum_rtcache_add(user);

	if (realtime)
		aum_real_users++;
	else
		aum_static_users++;

	//ASTOBJ_UNMARK(user);
	ast_log(LOG_VERBOSE, "-- == Finished building user: %s\n", username);
	return 0;
}


/*! \brief Parse configuration file and build AUM in-memory group 

	All groups are stored in memory for fast access

	Some memory parts are loaded on demand and cached
	\param	groupname	Name of new group
	\param	x		Configuration entries
	\param realtime		True if realtime group (Not implemented yet)
*/
static struct aum_group *aum_build_group(char *groupname, struct ast_variable *x, int realtime)
{
	struct aum_group *group;
	struct aum_context *context;
	enum aum_config_options option;

	group = aum_allocate(sizeof(struct aum_group));
	if (!group) {
		ast_log(LOG_WARNING, "Can't allocate AUM group memory\n");
		return 0;
	}
	if (realtime)
		aum_real_groups++;
	else
		aum_static_groups++;

	ast_log(LOG_DEBUG, "==== Initiating ASTOBJ for new group %s\n", groupname);
	ASTOBJ_INIT(group);
	ast_log(LOG_DEBUG, "==== Initiating AST_LIST for members of new group %s\n", groupname);
	AST_LIST_HEAD_INIT_NOLOCK(&group->members);
	ast_copy_string(group->name, groupname, sizeof(group->name));
	ast_log(LOG_DEBUG, "-- Building group: %s\n", groupname);
	while (x) {
		ast_log(LOG_DEBUG, "---- Group attribute: %s = %s\n", x->name, x->value);
		option = aum_config_parse(x->name, AUM_CONFOBJ_GROUP);
		switch (option) {
		case AUM_CNF_GROUPDESC:
			group->description = strdup(x->value);
			break;
		case AUM_CNF_DEFCONTEXT:
		case AUM_CNF_SUBSCRIBECONTEXT:
		case AUM_CNF_DISACONTEXT:
		case AUM_CNF_PARKING:
			break;
			context = build_context(AUM_CONTEXT_NONE, option, x->value);
			if (context)
				AST_LIST_INSERT_TAIL(&group->contexts, context, list);
			else
				ast_log(LOG_ERROR, "Context %s not added for group %s\n", x->value, groupname);
			break;
		case AUM_CNF_NOT_FOUND:
			ast_log(LOG_NOTICE, "Configuration label unknown in AUM configuration: %s\n", x->name);
			break;
		case AUM_CNF_NOT_VALID_FOR_OBJECT:
			ast_log(LOG_NOTICE, "Configuration label not valid for group objects in AUM configuration: %s\n", x->name);
			break;
		default: /* Oops, we're not prepared for this yet */
			ast_log(LOG_NOTICE, "Configuration label not valid for group objects in AUM configuration: %s\n", x->name);
			break;
		}
		x = x->next;
	}
	ASTOBJ_CONTAINER_LINK(&aum_grouplist, group);
	ASTOBJ_UNMARK(group);
	ast_log(LOG_VERBOSE, "-- == Finished building group: %s\n", groupname);
	return 0;
}

/*! \brief Get group from realtime storage 
	Checks the \b aumgroups realtime family from extconfig.conf 
	\param groupname group to load
 */
static struct aum_group *aum_group_realtime_load(char *groupname)
{
	struct aum_group *group = (struct aum_group *) NULL;
	struct ast_variable *var;
	
	var = ast_load_realtime("aumgroups", "name", groupname, NULL);
	if (!var)
		return (struct aum_group *) NULL;

	/* Group found in realtime, now build it in memory */
	group = aum_build_group(groupname, var, 1);
	if (group) {
		ASTOBJ_CONTAINER_LINK(&aum_grouplist, group);
		aum_real_groups++;
		ast_set_flag(group, AUM_GROUP_FLAG_REALTIME);
	}
	ast_variables_destroy(var);
	return group;
}


/*! \brief Get user object from realtime storage 
	Checks the \b aumusers realtime family from extconfig.conf 
	\param field name to match on
	\param value the value of the field
	
*/
static struct aum_user *aum_user_realtime_loadbyfield(char *field, char *value)
{
	struct aum_user *user = (struct aum_user *) NULL;
	struct ast_variable *var, *text;
	char *username = value;
	
	var = ast_load_realtime("aumusers", field, value, NULL);
	if (!var)
		return (struct aum_user *) NULL;

	/* User found in realtime, now build it in memory */

	/* Find username from realtime if it's not the argument */
	if (strcasecmp(field, "name")) {
		text = var;
		while (text) {
			if (!strcasecmp("name", text->name)) {
				username = text->value;
				break;
			}
			text = text->next;
		}
	
	}

	user = aum_build_user(username, var, TRUE);
	if (user) {
		ASTOBJ_CONTAINER_LINK(&aum_userlist, user);
		aum_real_users++;
		ast_set_flag(user, AUM_USER_FLAG_REALTIME);
	}
	ast_variables_destroy(var);
	return user;
}

/*! \brief Get user from realtime storage 
	Checks the \b aumusers realtime family from extconfig.conf 
	\param username user to load
 */
static struct aum_user *aum_user_realtime_load(char *username)
{
	return aum_user_realtime_loadbyfield("name", username);
}

/*! \brief Get user from realtime storage 
	Checks the \b aumusers realtime family from extconfig.conf 
	\param username user to load
 */
static struct aum_user *aum_user_realtime_load_by_numuserid(char *numuserid)
{
	return aum_user_realtime_loadbyfield("numuserid", numuserid);
}


/*! \brief Remove user from a group's member list */
static void remove_user_from_group(struct aum_group *group, struct aum_user *user)
{
	struct aum_group_member *member;

	if (!group || !user)
		return;

	AST_LIST_TRAVERSE(&group->members, member, list) {
		if (member->user == user) {
			AST_LIST_LOCK(&group->members);
			AST_LIST_REMOVE(&group->members, member, list);
			free(member);
			AST_LIST_UNLOCK(&group->members);
		}
	};
}

/*! \brief Remove group from a user's group list */
static void remove_group_from_user(struct aum_group *group, struct aum_user *user)
{
	struct aum_group_member *member;

	if (!group || !user)
		return;

	AST_LIST_TRAVERSE(&user->groups, member, list) {
		if (member->group == group) {
			AST_LIST_LOCK(&user->groups);
			AST_LIST_REMOVE(&user->groups, member, list);
			free(member);
			AST_LIST_UNLOCK(&user->groups);
		}
	};

	if (ast_test_flag(user, AUM_USER_FLAG_REALTIME))
		aum_rtcache_movetotop(user);
}

/*! \brief Destroy AUM group object */
static void aum_destroy_group(struct aum_group *group)
{
	/* Release all suballocations */
	if (group->description)
		free(group->description);

	/* Release member list */
	if (!AST_LIST_EMPTY(&group->members) ) {
		struct aum_group_member *member;
		AST_LIST_LOCK(&group->members);
		while ((member = AST_LIST_REMOVE_HEAD(&group->members, list))) {
			/* Check if the user still considers itself a member of this group */
			if (!AST_LIST_EMPTY(&member->user->groups))
				remove_group_from_user(group, member->user);
			free(member);
		}
		AST_LIST_UNLOCK(&group->members);
	}

	/* clear channel variables */
	if (group->chanvars) 
		ast_variables_destroy(group->chanvars);

	/* Release the group itself */
	aum_free(group);
}


/*! \brief Destroy AUM user object */
static void aum_destroy_user(struct aum_user *user)
{
	/* Release all suballocations */

	/* Release user list */
	if (!AST_LIST_EMPTY(&user->address) ) {
		struct aum_address *addr;
		AST_LIST_LOCK(&user->address);
		while ((addr = AST_LIST_REMOVE_HEAD(&user->address, list)))
			free(addr);
		AST_LIST_UNLOCK(&user->address);
	}

	/* If we belong to groups remove us as members */
	/* Remove group memberships */
	if (!AST_LIST_EMPTY(&user->groups) ) {
		struct aum_group_member *group;
		AST_LIST_LOCK(&user->groups);
		while ((group = AST_LIST_REMOVE_HEAD(&user->groups, list)))
			if (!AST_LIST_EMPTY(&group->group->members))
				remove_user_from_group(group->group, user);
			free(group);
		AST_LIST_UNLOCK(&user->groups);
	}

	/* Release context list */
	if (!AST_LIST_EMPTY(&user->contexts) ) {
		struct aum_context *context;
		AST_LIST_LOCK(&user->contexts);
		while ((context = AST_LIST_REMOVE_HEAD(&user->contexts, list)))
			free(context);
		AST_LIST_UNLOCK(&user->contexts);
	}

	/* clear channel variables */
	if (user->chanvars)
		ast_variables_destroy(user->chanvars);

	/* Clear the ACL */		
	ast_free_ha(user->acl);

	/* Release the user itself */
	aum_free(user);
}



/*! \brief  reload_config: Re-read aum.conf config file ---*/
/*	This function reloads all config data for users and groups
 */
static int reload_config(enum modulereloadreason reason)
{
	struct ast_config *cfg;
	struct ast_variable *v, *x;
	struct aum_user *user;
	char *cat;
	struct aum_group *group = NULL;
	enum aum_config_options option;

	aum_real_groups_enabled = ast_check_realtime("aumgroups");
	aum_real_users_enabled = ast_check_realtime("aumgroups");

	cfg = ast_config_load(aum_config_file);

	/* We *must* have a config file otherwise stop immediately */
	if (!cfg) {
		ast_log(LOG_NOTICE, "Unable to load config %s\n", aum_config_file);
		return -1;
	}
	if (option_debug)
		ast_log(LOG_DEBUG, "Loading configuration for the Asterisk User Management module\n");
	

	/* Initialize some reasonable defaults at AUM reload */
	aum_debug = 0;
	aum_real_groups = 0;
	aum_static_groups = 0;
	aum_real_users = 0;
	aum_static_users = 0;
	aum_usercache_max = DEFAULT_USERCACHE_MAX;
	ASTOBJ_CONTAINER_INIT(&aum_grouplist);
	ASTOBJ_CONTAINER_INIT(&aum_userlist);

	/* Read the [general] config section of aum.conf (or from realtime config) */
	ast_log(LOG_DEBUG, "===== Starting to read general section\n");
	x = ast_variable_browse(cfg, "general");
	while(x) {
		option = aum_config_parse(x->name, AUM_CONFOBJ_USER);
		switch (option) {
		case AUM_CNF_DEBUG:
			aum_debug = ast_true(x->value);
			break;
		case AUM_CNF_GROUPDESC:
			group->description = ast_strdupa(x->name);
			break;
		case AUM_CNF_NOT_FOUND:
			ast_log(LOG_NOTICE, "Configuration label unknown in AUM configuration: %s\n", x->name);
			break;
		case AUM_CNF_NOT_VALID_FOR_OBJECT:
		default:
			ast_log(LOG_NOTICE, "Configuration label not valid for group objects in AUM configuration: %s\n", x->name);
			break;
		}
		x = x->next;
	}
	/* Load group names */
	ast_log(LOG_DEBUG, "===== Starting to read [groups] section\n");
	v = ast_variable_browse(cfg, "groups");
	ast_log(LOG_DEBUG, "- Found group section \n");
	while (v) {
		ast_log(LOG_DEBUG, "- Found new group: %s=%s\n", v->name, v->value);
		if (!strcmp(v->name, "group")) {
			/* get the group */
			x = ast_variable_browse(cfg, v->value);
			if (x) {
				ast_log(LOG_DEBUG, "- Trying to build new group: %s\n", v->value);
				group = aum_build_group(v->value, x, 0);	/* Build the group */
				if (group) {
					ast_log(LOG_VERBOSE, "- Built new group:%s\n", v->value);
					ASTOBJ_CONTAINER_LINK(&aum_grouplist, group);
				}
			}
		}
		v = v->next;
	}
	
	ast_log(LOG_DEBUG, "===== Starting to read [users] section\n");

	/* Load the rest of the sections - group details and users */
	cat = ast_category_browse(cfg, NULL);
	while (cat) {
		char *sectiontype;

		ast_log(LOG_DEBUG, "Found new user/group section: %s\n", cat);
		sectiontype= ast_variable_retrieve(cfg, cat, "type");
		if (!strcmp(cat, "groups") || ( sectiontype && !strcmp(sectiontype, "group"))) {
			ast_log(LOG_DEBUG, "==== Skipping group section (already configured, hopefully)\n");
		} else {
			x = ast_variable_browse(cfg, cat);
			if (x) {
				user = aum_build_user(cat, x, 0);	/* Build the user */
				if (user) {
					ASTOBJ_CONTAINER_LINK(&aum_userlist, user);
				}
			}
		}
		/* Get next [section] */
		cat = ast_category_browse(cfg, cat);
	}


	/* Release configuration from memory */
	ast_config_destroy(cfg);

	/* Done, tell the manager */
	manager_event(EVENT_FLAG_SYSTEM, "ModuleReload", "Module: res_aum.so\r\nReloadReason: %s\r\nAUMUserCount: %d\r\nAUMGroupCount: %d\r\n\r\n\r\n", modulereloadreason2txt(reason), aum_static_users, aum_static_groups);

	return 0;
}

/*---------------------------- API functions (public, declared in aum.h ----------------*/
char *find_aum_user_context(struct aum_user *user, enum aum_context_type type)
{
	struct aum_context *con;

	if (!user || type == AUM_CONTEXT_NONE)
		return NULL;

	AST_LIST_TRAVERSE(&user->contexts, con, list) {
		if (con->type == type)
			return con->context;
	};
	return (char *) NULL;
}

struct aum_address *find_address_for_user(struct aum_user *user, enum aum_address_type type, struct aum_address *start)
{
	struct aum_address *addr;
	int activesearch = 0;
	if (!start)
		activesearch = 1;

	if (!user || type == AUM_ADDR_NONE)
		return NULL;

	AST_LIST_TRAVERSE(&user->address, addr, list) {
		if (activesearch && addr->type == type)
			return addr;
		if (!activesearch && start == addr)
			activesearch = 1;
	};
	return NULL;
}

char *aum_find_address(struct aum_user *user, enum aum_address_type type)
{
	struct aum_address *addr;
	addr = find_address_for_user(user, type, NULL);
	return addr->address;
}

char *aum_find_email(char *userid) {
	return aum_find_address(find_aum_user(userid, TRUE), AUM_ADDR_EMAIL);
}

char *aum_find_email_full(struct aum_user *user) {
	return aum_find_address(user, AUM_ADDR_EMAIL);
}

struct aum_address *find_user_address(struct aum_user *user, enum aum_address_type type, char *address)
{
	struct aum_address *addr;

	if (ast_strlen_zero(address))
		return NULL;

	AST_LIST_TRAVERSE(&user->address, addr, list) {
		if (addr->type == type && !strcmp(addr->address, address) )
			return addr;
	};
	return (struct aum_address *) NULL;
	
}

struct aum_user *find_user_by_address(enum aum_address_type type, char *address)
{
	if (ast_strlen_zero(address))
		return NULL;

	ASTOBJ_CONTAINER_TRAVERSE(&aum_userlist, 1, {
		ASTOBJ_RDLOCK(iterator);
		if(find_user_address(iterator, type, address)) {
			ASTOBJ_UNLOCK(iterator);
			return iterator;
		}
		ASTOBJ_UNLOCK(iterator);
	} );
	return NULL;
}

struct aum_user *find_aum_user_by_numuserid(char *numuserid)
{
	ASTOBJ_CONTAINER_TRAVERSE(&aum_userlist, 1, {
		ASTOBJ_RDLOCK(iterator);
		if(!strcmp(iterator->numuserid, numuserid)) {
			ASTOBJ_UNLOCK(iterator);
			return iterator;
		}
		ASTOBJ_UNLOCK(iterator);
	} );
	return NULL;
}


struct aum_group *find_aum_group_by_name(char *groupname)
{
	struct aum_group *res;
	if (ast_strlen_zero(groupname))
		return NULL;
	res = ASTOBJ_CONTAINER_FIND(&aum_grouplist, groupname);	

	if (!res && aum_real_groups_enabled) {
		res = aum_group_realtime_load(groupname);
	}
	return res;
		
}

struct aum_user *find_aum_user(char *userid, int realtime)
{
	struct aum_user *res;

	/* Search among static and cached realtime users */
	res = ASTOBJ_CONTAINER_FIND(&aum_userlist, userid);	
	if (!res && realtime && aum_real_users_enabled) {
		res = aum_user_realtime_load(userid);
	} else if (res && ast_test_flag(res, AUM_USER_FLAG_REALTIME))
		/* Move user to top of cache */
		aum_rtcache_movetotop(res);
	return res;
}

struct aum_user *find_aum_user_email(char *email)
{
	return find_user_by_address(AUM_ADDR_EMAIL, email);
}

int aum_group_test_full(struct aum_user *user, struct aum_group *group)
{
	struct aum_group_member *member;
	AST_LIST_TRAVERSE(&user->groups, member, list) {
		if (member->group == group)
			return 1;
	};
	return 0;
}

int aum_group_test(struct aum_user *user, char *groupname) 
{
	return aum_group_test_full(user, find_aum_group_by_name(groupname));
}

/*! \brief Initialize charset conversion handlers */
static void initialize_charset_conversion(void)
{
	ichandler_utf8_to_iso88591 = iconv_open("utf8", "ISO-8859-1");
	ichandler_iso88591_to_utf8 = iconv_open("ISO-8859-1", "utf8");
}


/*---------------------------- Asterisk module interface ---------------------------------*/

/*! Load aum module */
int load_module(void)
{
	initialize_charset_conversion();
	reload_config(MODULE__LOAD);
	aum_rtcache_freeall();

	/* Check if realtime is enabled */
	aum_real_users_enabled = ast_check_realtime("aumusers");
	aum_real_groups_enabled = ast_check_realtime("aumgroups");

	/* Register CLI */
	ast_cli_register_multiple(my_clis, sizeof(my_clis)/ sizeof(my_clis[0]));
	ast_custom_function_register(&aum_user_function);

	return 0;
}

/*! Unload module from memory, dangerous right now */
int unload_module(void)
{
	/* Unregister apps, functions, manager actions, switches */
	ast_cli_unregister_multiple(my_clis, sizeof(my_clis)/ sizeof(my_clis[0]));
	ast_custom_function_unregister(&aum_user_function);
	aum_rtcache_freeall();

	/* Deallocate iconv conversion descriptors */
	iconv_close(ichandler_utf8_to_iso88591);
	iconv_close(ichandler_iso88591_to_utf8);
	return 0;
}

/*! Description for show modules CLI */
char *description(void)
{
	return "Asterisk User Management";
}

int usecount(void)
{
	int res;
	STANDARD_USECOUNT(res);
	return res;
}

char *key()
{
	return ASTERISK_GPL_KEY;
}
