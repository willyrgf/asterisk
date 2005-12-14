/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Asterisk User Management interface
 *
 * Copyright (C) 2005, Edvina AB, Sollentuna, Sweden
 *
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

/*!\note This is just skeletons, that I'm trying to put flesh and	
	clothes on... Mail input to oej@edvina.net
*/

/*!\file
 * \brief Asterisk User Managment - AUM - API
 * \arg Implemented in res_aum.c
 * \par For information on AUM, please see
 *  	\arg AUM_desc
 */

#ifndef _ASTERISK_AUM_H
#define _ASTERISK_AUM_H

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/*--------------------------- AUM STRING HANDLING -------------------------------- */
/*! Character set definition for some strings */
enum aum_string_charset {
	AUM_CHAR_UNKNOWN = 0,
	AUM_CHAR_ASCII,			/*!< 7 bit ASCII */
	AUM_CHAR_ISO8859_1,		/*!< ISO 8859-1, 8 bits */
	AUM_CHAR_ISO8859_2,		/*!< ISO 8859-2, 8 bits */
	AUM_CHAR_ISO8859_3,		/*!< ISO 8859-3, 8 bits */
	AUM_CHAR_UTF8,			/*!< Unicode ISO 9660, UTF 8 encoding */
};

struct aum_string_convert {
	enum aum_string_charset	charset;	/*!< Character set */
	const char *label;			/*!< Label used in strings in config files */
};

/*! String object for international strings. 
	\note Use the aum_string functions to assign values, get strings in alternative 
	character sets and free the chain of strings 
	OEJ: This is a simple linked list. Wonder if the AST_LIST is needed here?
*/
struct aum_string_struct {
	char 		*string;	/*!< Allocated string, needs to be free()d after use */
	size_t		size;		/*!< Allocated size, if allocated (Won't free unless we have size */
	enum aum_string_charset charset;	/*!< Character set for this string */
	struct aum_string *next;	/*!< Pointers to alternative encodings of the same string */
};

typedef struct aum_string_struct aum_string;

/*! \brief Address types for address objects in AUM */
enum aum_address_type {
	AUM_ADDR_EMAIL 	= (1 << 0),	/*!< E-mail - string like "username@domain.se" */
	AUM_ADDR_XMPP	= (1 << 1),	/*!< XMPP uri */
	AUM_ADDR_SIP	= (1 << 2),	/*!< SIP uri */
	AUM_ADDR_MSN	= (1 << 3),	/*!< MSN user identifier "username@hotmail.com" */
	AUM_ADDR_AOL	= (1 << 4),	/*!< AOL/ICQ user ID */
	AUM_ADDR_TEL	= (1 << 5),	/*!< E.164 phone number (TEL-uri format, local allowed (depends on your configuration) */
	AUM_ADDR_CELL_TEL = (1 << 6),	/*!< Cell phone E.164 phone number (TEL-uri format, local allowed (depends on your configuration) */
	AUM_ADDR_IAX2	= (1 << 7),	/*!< IAX2 callable uri, like "guest@myasterisk.com/12345"	*/
	AUM_ADDR_FWD	= (1 << 8),	/*!< Free World Dialup User ID */
	AUM_ADDR_IAXTEL	= (1 << 9),	/*!< IAXtel Dialup User ID */
	AUM_ADDR_FAX	= (1 << 10),	/*!< Preferred fax number (E.164 Tel URI) */
	AUM_ADDR_WEB	= (1 << 11),	/*!< HOMEPAGE */
	AUM_ADDR_NONE	= (1 << 30),	/*!< Return value */
};

/*! \brief Things you can configure in AUM */
enum aum_config_objects {
	AUM_CONFOBJ_GENERAL	= (1 << 0),	/*!< General configuration options */
	AUM_CONFOBJ_USER	= (1 << 1),	/*!< User configuration */ 
	AUM_CONFOBJ_GROUP	= (1 << 2),	/*!< Group configuration */
};

/*! \brief AUM configuration options */
enum aum_config_options {
	AUM_CNF_NONE,			/*!< Unknown configuration directive */
	AUM_CNF_NOT_VALID_FOR_OBJECT,	/*!< Not valid for this object */
	AUM_CNF_NOT_FOUND,		/*!< No match found */
	AUM_CNF_ADDR_EMAIL,		/*!< Email address */
	AUM_CNF_ADDR_XMPP,		/*!< XMPP/Jabber address */
	AUM_CNF_ADDR_SIP,		/*!< SIP AOR: SIP uri to reach this user */
	AUM_CNF_ADDR_IAX2,		/*!< IAX2 URI */
	AUM_CNF_ADDR_AOL,		/*!< AOL IM */
	AUM_CNF_ADDR_MSN,		/*!< MSN Contat for IM */
	AUM_CNF_ADDR_TEL,		/*!< Telephone numer in E.164 format */
	AUM_CNF_ADDR_CELL_TEL,		/*!< Cell phone number */
	AUM_CNF_ADDR_FAX,		/*!< Fax number (PSTN) */
	AUM_CNF_ADDR_FWD,		/*!< Free World Dialup account */
	AUM_CNF_ADDR_IAXTEL,		/*!< IAXtel account ID */
	AUM_CNF_ADDR_WEB,		/*!< Home page */
	AUM_CNF_VMAILBOX,		/*!< Voicemail mailbox exten@context */
	AUM_CNF_GROUP,			/*!< Group membership */
	AUM_CNF_CALLBACKEXT,		/*!< Default extension */
	AUM_CNF_PARKING,		/*!< Default parking context */
	AUM_CNF_DISACONTEXT,		/*!< DISA context for disa() access */
	AUM_CNF_SIPDOMAIN,		/*!< SIP DOMAIN this user belongs to (virtual PBX) */
	AUM_CNF_SUBSCRIBECONTEXT,	/*!< SIP subscription context */
	AUM_CNF_DEFEXTEN,		/*!< Default extension */
	AUM_CNF_DEFCONTEXT,		/*!< Default context */
	AUM_CNF_CID,			/*!< Caller ID */
	AUM_CNF_CALLERPRES,		/*!< Caller ID presentation when making calls */
	AUM_CNF_ACCOUNTCODE,		/*!< Account code for this user */
	AUM_CNF_MANAGERACCESS,		/*!< Manager access something */
	AUM_CNF_SECRET,			/*!< Secret (password) */
	AUM_CNF_PIN,			/*!< Pin code for authorization by DTMF */
	AUM_CNF_CALLGROUP,		/*!< Calling group */
	AUM_CNF_PICKUPGROUP,		/*!< Pickup group */
	AUM_CNF_IAX2KEY,		/*!< Name of IAX key */
	AUM_CNF_MUSICCLASS,		/*!< Default music class when this user puts someone on hold */
	AUM_CNF_LDAPDN,			/*!< LDAP handle for this user */
	AUM_CNF_FIRSTNAME,		/*!< First name */
	AUM_CNF_LASTNAME,		/*!< Last name*/
	AUM_CNF_TITLE,			/*!< Title */
	AUM_CNF_LANGUAGE,		/*!< Language */
	AUM_CNF_SOUNDNAME,		/*!< Sound file */
	AUM_CNF_CHANVAR,		/*!< Channel variables */
	AUM_CNF_PERMIT,			/*!< ACL permit */
	AUM_CNF_DENY,			/*!< ACL deny */
	AUM_CNF_NUMID,			/*!< Numerical ID for this user */
	AUM_CNF_TIMEZONE,		/*!< Timezone, mostly used for voice mail */
	AUM_CNF_GROUPVAR,		/*!< */
	AUM_CNF_TYPE,			/*!< Type of config - group, user */
	AUM_CNF_GROUPDESC,		/*!< Group description */
	AUM_CNF_DEBUG,			/*!< AUM debug option */
};

/*! \brief AUM configuration definition structure */
struct aum_config_struct {
	enum aum_config_options option;
	char 			*label;
	enum aum_config_objects valid;
};

/*! \brief AUM Address object */
struct aum_address {
 	enum aum_address_type type;		/*!< Address type */
	enum aum_string_charset charset;		/*!< character set */
	char address[180];			/*!< The actual address */
	int active;
	AST_LIST_ENTRY(aum_address) list;	/*!< List mechanics */
};

/*! \brief AUM Address configuration helper */
struct aum_address_config_struct {
	enum aum_address_type	type;
	char 			*label;
	char 			*display;
	enum aum_config_options configoption;
};

/*! \brief Context types for AUM user objects */
enum aum_context_type {
	AUM_CONTEXT_NONE = 0,	/*!< No Context (Return value for functions) */
	AUM_CONTEXT_DEF_CB,	/*!< Default callback context for reaching this user */
	AUM_CONTEXT_DEF_INCOMING,	/*!< Default incoming context for this user */
	AUM_CONTEXT_VOICEMAIL,	/*!< Default voicemail context */
	AUM_CONTEXT_DISA,	/*!< Default DISA context */
	AUM_CONTEXT_SIPSUBSCRIBE,	/*!< Default context for SIP subscriptions */
	AUM_CONTEXT_PARKING,	/*!< Default parking context */
};

/*! \brief Explanations of contexts */
struct aum_context_table {
	enum aum_context_type	type;
	const char *desc;
};

/*! \brief Presence states for AUM user objects */
enum aum_presence_state {	/* This follows XMPP roughly */
	AUM_PRES_NOT_AVAILABLE,	/*!< No presence available */
	AUM_PRES_AVAILABLE,	/*!< Reachable, on line */
	AUM_PRES_MEETING,	/*!< Meeting */
	AUM_PRES_ONCALL,	/*!< On call */
	AUM_PRES_DND,		/*!< Do not disturb */
	AUM_PRES_EXT_AWAY,	/*!< Extended away */
};

/*! \brief Presence providers */
enum aum_presence_prov {
	AUM_PRESPROV_XMPP,	/*!< Jabber/XMPP */	
	AUM_PRESPROV_MSN,	/*!< MSN Messenger */
	AUM_PRESPROV_SIMPLE,	/*!< SIP Simple */
	AUM_PRESPROV_AMI,	/*!< AMI - Asterisk manager interface */
	AUM_PRESPROV_DIALPLAN,	/*!< Dialplan functions */
	AUM_PRESPROV_CLI,	/*!< CLI functions */
};

/*! \brief Presence structures for AUM presence objects */
struct aum_presence {
	enum aum_presence_state	state;		/*!< State of this user */
	enum aum_presence_prov provider;	/*!< Provider of presence */
	AST_LIST_ENTRY(aum_presence) list;	/*!< List mechanics */
};

enum devicereg {
	AUM_DEVICE_REG_CHANNEL,			/* Added by channel, persistent object */
	AUM_DEVICE_REG_MANAGER,			/*!< Added by manager, non persistant */
	AUM_DEVICE_REG_CLI,			/*!< Added by the CLI, non persistant */
};

/*! \brief List of phones that belongs to this user
 * For now, kept in memory. Not persistent across reloads... Could use
 * ASTdb... 
 */
struct aum_device {
	char *devicename;			/*!< tech/devicename */
	struct ast_flags flags;			/*!< flags class AUM_DEVICE_* */
	/*! Placeholder for callback to channel to change state */
	int (* const change_devstate)(char *device, enum aum_presence_state);
	enum devicereg registrar;		/*!< Device registrar */
	AST_LIST_ENTRY(aum_device) list;
};

/*! \brief Context structure 
	\note Until further notice, Asterisk contexts are ASCII
*/
struct aum_context {
	enum aum_context_type type;		/*!< Context type */
	char context[AST_MAX_CONTEXT];		/*!< Context name */
	AST_LIST_ENTRY(aum_context) list;	/*!< List mechanics */
};


/*! \brief Group memberships */
struct aum_group_member {
	int priority;				/*!< Not defined yet... */
	union {
		struct aum_group *group;	/*!< For users, pointer to groups */
		struct aum_user *user;		/*!< For groups, pointer to users */
	};
	AST_LIST_ENTRY(aum_group_member) list;	/*!< List mechanics */
};

/*! \brief Flags for aum_user flag field */
enum aum_user_flags {
	AUM_USER_FLAG_REALTIME = (1 << 0),	/*!< User loaded from realtime */
	AUM_USER_FLAG_DISABLED = (1 << 1),	/*!< User disabled */
};

/*! \brief Flags for aum_group flag field */
enum aum_group_flags {
	AUM_GROUP_FLAG_REALTIME = (1 << 0),	/*!< Group loaded from realtime */
	AUM_GROUP_FLAG_DISABLED = (1 << 1),	/*!< Group disabled */
};


/*! \brief Declaration of grouplist structure for inclusion in objects */
AST_LIST_HEAD(aum_user_grouplist, aum_group_member);
AST_LIST_HEAD(aum_user_addrlist, aum_address);
AST_LIST_HEAD(aum_user_contextlist, aum_context);
AST_LIST_HEAD(aum_presencelist, aum_presence);
AST_LIST_HEAD(aum_devicelist, aum_device);

/*! \brief Main AUM user object
	\par This is the main AUM object
	- contains linked list of addresses
	- contains linked list of contexts of addresses
	- contains linked list of group memberships
*/
struct aum_user {
	ASTOBJ_COMPONENTS(struct aum_user);	/*!< Generic pointers - name being one. Name is not a user name, but a user ID code.
							Only a-z and 0-9, has to begin
							with character. Not significant in any way, just a handle us 
						*/
	unsigned int flags;		/*!< Flags for various stuff, see AUM_USER_FLAG_* */
	char mailbox[AST_MAX_EXTENSION];	/*!< Default mailbox */
	char default_exten[AST_MAX_EXTENSION];	/*!< Default extension for this user (for callbacks) */
	char cid_num[256];		/*!< Default caller ID num (E.164 type) */
	char cid_name[256];		/*!< Default caller ID name */
	int calling_pres;		/*!< Default Caller ID presentation */
	char accountcode[AST_MAX_ACCOUNT_CODE];	/*!< Default Account code */
	char sip_username[256];		/*!< SIP user name (utf8) */
	char musicclass[MAX_MUSICCLASS];	/*!< Default musicclass for this user */
	char first_name[80];		/*!< First name (ISO 8859-1) */
	char last_name[80];		/*!< Last name (ISO 8859-1) */
	char title[20];			/*!< Title */
	char language[MAX_LANGUAGE];	/*!< Default language */
	char iax2privatekey[20];	/*!< Private key for this user */
	char zonetag[80];		/*!< Time zone */
	char numuserid[80];		/*!< Numeric user ID for this user */
	char pincode[80];		/*!< Numeric pincode for this user */
	char secret[80];		/*!< Secret for this user */
	char ldapdn[180];		/*!< LDAP DN */
	char registrar[20];		/*!< Who added this object? */
	ast_group_t callgroup;			/*!< Calling group for calls */
	ast_group_t pickupgroup;		/*!< Pickup group */
	struct ast_variable *chanvars;	/*!< Default channel variables */
	struct aum_presencelist	presence;	/*! Presence states */
	struct aum_user_contextlist contexts;	/*!< Linked list of contexts this user use */
	struct aum_user_grouplist groups;	/*!< Linked list of groups we are members to */
	struct aum_user_addrlist address;	/*!< Linked list of addresses of various types */
	struct aum_devicelist devices;		/*!< Linked list of devices active for this user */
	struct ast_ha	*acl;			/*!< Access control list for user */
						/*!< The highest priority is used as primary group for setting default values */
	int managerperm;			/*!< If sat, this user can log in to manager with these permissions */
};

/*! \brief the AUM group definition */
struct aum_group {
	ASTOBJ_COMPONENTS(struct aum_group);	/*! Generic pointers and name field */
	unsigned int flags;			/*!< Flags for various stuff, see AUM_GROUP_FLAG_* */
	char sipdomain[120];			/*!< Should be AST_MAX_DOMAIN something */
	char incoming_did[AST_MAX_EXTENSION];	/*!< Main DID for this group */
	char language[MAX_LANGUAGE];		/*!< Default language for group */
	char musicclass[MAX_MUSICCLASS];	/*!< Default musicclass for this group */
	ast_group_t callgroup;			/*!< Calling group for calls */
	ast_group_t pickupgroup;		/*!< Pickup group */
	int managerperm;			/*!< This group's permissions in manager */
	struct aum_user_contextlist contexts;	/*!< Linked list of contexts this group use */
	struct ast_variable *chanvars;
	struct ast_ha	*acl;			/*!< Access control list for user */
	char *description;			/*!< Description */
	struct aum_user_grouplist members;	/*!< Members list */
	char registrar[20];		/*!< Who added this object? */
};

/*--------------------------- GLOBAL FUNCTIONS ----------------------*/

/*! \brief Find AUM user 
	\param userid Unique user ID for this user 
	\param realtime TRUE forces lookup and loading of realtime users in memory
	\return NULL if not found, otherwise pointer to structure 
*/
struct aum_user *find_aum_user(char *userid, int realtime);

/*! \brief Find an address for an AUM user 
	\param user	AUM user object pointer
	\param type	AUM address type (enum)
	\param start	AUM Address pointer for where to start the search in the linked list. NULL if from beginning
	\return		Pointer to AUM address object if found, otherwise NULL 
*/
struct aum_address *find_address_for_user(struct aum_user *user, enum aum_address_type type, struct aum_address *start);

/*! \brief Find address object for specified address
	\param user	AUM user object pointer
	\param type	AUM address type (enum aum_address_type)
	\param address	Address
	\return 	Pointer to AUM address object if found, otherwise NULL
*/
struct aum_address *find_user_aum_address(struct aum_user *user, enum aum_address_type type, char *address);

/*! \brief Find user by any AUM address type address (xmpp, sip, email, iax2 etc)
	\param type	AUM address type (enum)
	\param address	Address as a text string
*/
struct aum_user *find_user_by_address(enum aum_address_type type, char *address);

/*! \brief Find AUM user by e-mail
	\param email Email address for this user
	\return NULL if not found, otherwise pointer to structure 
*/
struct aum_user *find_aum_user_email(char *email);

/*! \brief Find AUM user by numeric user id
	\param numuid Searched numeric user ID
	\return NULL if not found, otherwise pointer to structure
*/
struct aum_user *find_aum_user_by_numuserid(char *numuserid);

/*! \brief Find AUM user group by group name 
	\param Group name in text
	\result struct aum_group pointer to group
*/
struct aum_group *find_aum_group_by_name(char *groupname);

/*! \brief Find out if user belongs to group 
	\param user AUM user object
	\param group Group name
*/
int aum_group_test(struct aum_user *user, char *groupname);

/*! \brief Find out if user belongs to group by group object
	\param user AUM user object
	\param group Group name
*/
int aum_group_test_full(struct aum_user *user, struct aum_group *group);

/*! \brief Find e-mail address for AUM user
	\param user AUM user id
	\return E-mail address with highest priority, NULL if not found
*/
char *aum_find_email(char *userid);

/*! \brief Find e-mail address for AUM user by AUM struct pointer
	\param user AUM struct pointer
	\return E-mail address with highest priority, NULL if not found
*/
char *aum_find_email_full(struct aum_user *user);

/*! \brief Find jabber/XMPP address for AUM user
	\param user AUM user id
	\return Jabber/XMPP uri with highest priority, NULL if not found
*/
char *aum_find_xmpp(char *userid);

/*! \brief Find jabber/XMPP address for AUM user by AUM struct pointer
	\param user AUM struct pointer
	\return Jabber/XMPP uri with highest priority, NULL if not found
*/
char *aum_find_xmpp_full(struct aum_user *user);

/*! \brief Find any address of given type 
	\param user AUM struct pointer
	\param type AUM address type
	\return Character string with highest priority, NULL if not found
*/
char *aum_find_address(struct aum_user *user, enum aum_address_type type);

/*! \brief Find a context for a user
	\param user AUM struct pointer
	\param type AUM context type (enum)
	\return character string pointer if context found, NULL if not found
*/
char *aum_find_user_context(struct aum_user *user, enum aum_context_type type);

/*! \brief Find parking context for a user 
	\param user AUM user struct pointer
*/
#define aum_find_user_parking(user)	aum_find_user_context(user, AUM_CONTEXT_PARKING);

/*--------- AUM String handling functions ----------------------*/
/*! \brief Allocate AUM string - remember to deallocate
	\param string	Input character string
	\param charset	aum_string_charset enum
	\return 	aum_string object
*/
aum_string *aum_string_alloc(char *string, enum aum_string_charset charset);

/*! \brief Convert string, allocate new aum_string object and link it at end of list
	\param string	Input aum_string
	\param charset	aum_string_charset enum
	\return 	aum_string object
*/
aum_string *aum_string_add_charset_variant(aum_string *string, enum aum_string_charset charset);

/*! \brief Get string in specific character set. If not found, convert to that charset and return string
	\param string	Input aum_string
	\param charset	aum_string_charset enum
	\return 	character string (char *)
*/
char *aum_string_output(aum_string *string, enum aum_string_charset charset);

/*! \brief Parse character set in front of string, create string
	\param string	string optionally with charset in front of string, separated with |
	\param defaultcharset	Default character set, if not specified
	\return 	aum_string object, allocated by this function
	
*/
aum_string *aum_string_add(char *string, enum aum_string_charset defaultcharset);

/*! \brief Destroy all strings beginning with this one */
void aum_string_destroy(aum_string *string);

#endif /* _ASTERISK_MD5_H */
