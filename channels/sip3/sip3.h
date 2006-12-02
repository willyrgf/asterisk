/*
 * Asterisk -- A telephony toolkit for Linux.
 *
 * Implementation of SIP - The Session Initiation protocol
 *
 * Version 3 of the SIP channel
 * 
 * Copyright (C) 2003-2006, Digium Inc
 * and Edvina AB (for the chan_sip3 additions/changes)
 *
 * Mark Spencer <markster@linux-support.net>
 * and Olle E. Johansson <oej@edvina.net>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 *
 *
 * For more information about chan_sip3: \ref chan_sip3_00index
 */
 
#ifndef _SIP3_H
#define _SIP3_H

/* remove this line, and I can't be responsible for what happens to your
   favourite PBX ... :-) 
*/
#define THIS_IS_A_TEST	"Pineapples are sweet"

#ifndef FALSE
#define FALSE    0
#endif

#ifndef TRUE
#define TRUE     1
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


#define VIDEO_CODEC_MASK        0x1fc0000 /*!< Video codecs from H.261 thru AST_FORMAT_MAX_VIDEO */
#ifndef IPTOS_MINCOST
#define IPTOS_MINCOST           0x02
#endif

#define DEFAULT_DEFAULT_EXPIRY  120
#define DEFAULT_MIN_EXPIRY      60
#define DEFAULT_MAX_EXPIRY      3600
#define DEFAULT_REGISTRATION_TIMEOUT 20
#define DEFAULT_MAX_FORWARDS    "70"

/* These strings needs to be localized */
#define CALLERID_UNKNOWN	"Unknown"

/*! \brief Magic marker for registration contacts */
#define REG_MAGICMARKER		"ASTZVXW"

/* guard limit must be larger than guard secs */
/* guard min must be < 1000, and should be >= 250 */
#define EXPIRY_GUARD_SECS       15                /*!< How long before expiry do we reregister */
#define EXPIRY_GUARD_LIMIT      30                /*!< Below here, we use EXPIRY_GUARD_PCT instead of 
                                                   EXPIRY_GUARD_SECS */
#define EXPIRY_GUARD_MIN        500                /*!< This is the minimum guard time applied. If 
                                                   GUARD_PCT turns out to be lower than this, it 
                                                   will use this time instead.
                                                   This is in milliseconds. */
#define EXPIRY_GUARD_PCT        0.20                /*!< Percentage of expires timeout to use when 
                                                    below EXPIRY_GUARD_LIMIT */
#define DEFAULT_EXPIRY 900                          /*!< Expire slowly */

#define DEFAULT_QUALIFY_MAXMS                2000             /*!< Qualification: Must be faster than 2 seconds by default */
#define DEFAULT_QUALIFY_FREQ_OK      60 * 1000        /*!< Qualification: How often to check for the host to be up */
			
#define DEFAULT_QUALIFY_FREQ_NOTOK   10 * 1000        /*!< Qualification: How often to check, if the host is down... */

#define DEFAULT_RETRANS              1000             /*!< How frequently to retransmit Default: 2 * 500 ms in RFC 3261 */
#define MAX_RETRANS                  6                /*!< Try only 6 times for retransmissions, a total of 7 transmissions */
#define SIP_TIMER_T1_DEFAULT		500		/*!< Timer T1 default value (from rfc 3261) */
#define SIP_TRANS_TIMEOUT            32000            /*!< SIP request timeout (rfc 3261) 64*T1 
                                                      \todo Use known T1 for timeout (peerpoke)
                                                      */
#define DEFAULT_TRANS_TIMEOUT        -1               /* Use default SIP transaction timeout */
#define MAX_AUTHTRIES                3                /*!< Try authentication three times, then fail */

#define SIP_MAX_HEADERS              64               /*!< Max amount of SIP headers to read */
#define SIP_MAX_LINES                64               /*!< Max amount of lines in SIP attachment (like SDP) */
#define SIP_MAX_PACKET               4096             /*!< Also from RFC 3261 (2543), should sub headers tho */

#define INITIAL_CSEQ                 101              /*!< our initial sip sequence number */

#define RTP 	1
#define NO_RTP	0

/*!  Define SIP option tags, used in Require: and Supported: headers 
 	We need to be aware of these properties in the phones to use 
	the replace: header. We should not do that without knowing
	that the other end supports it... 
	This is nothing we can configure, we learn by the dialog
	Supported: header on the REGISTER (peer) or the INVITE
	(other devices)
	We are not using many of these today, but will in the future.
	This is documented in RFC 3261
*/
#define SUPPORTED		1
#define NOT_SUPPORTED		0

#define SIP_OPT_REPLACES	(1 << 0)
#define SIP_OPT_100REL		(1 << 1)
#define SIP_OPT_TIMER		(1 << 2)
#define SIP_OPT_EARLY_SESSION	(1 << 3)
#define SIP_OPT_JOIN		(1 << 4)
#define SIP_OPT_PATH		(1 << 5)
#define SIP_OPT_PREF		(1 << 6)
#define SIP_OPT_PRECONDITION	(1 << 7)
#define SIP_OPT_PRIVACY		(1 << 8)
#define SIP_OPT_SDP_ANAT	(1 << 9)
#define SIP_OPT_SEC_AGREE	(1 << 10)
#define SIP_OPT_EVENTLIST	(1 << 11)
#define SIP_OPT_GRUU		(1 << 12)
#define SIP_OPT_TARGET_DIALOG	(1 << 13)
#define SIP_OPT_NOREFERSUB	(1 << 14)
#define SIP_OPT_HISTINFO	(1 << 15)
#define SIP_OPT_RESPRIORITY	(1 << 16)


/*! \brief SIP Methods we support */
#define ALLOWED_METHODS "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY"

/*! \brief SIP Extensions we support */
#define SUPPORTED_EXTENSIONS "replaces" 


/* Default values, set and reset in reload_config before reading configuration */
/* These are default values in the source. There are other recommended values in the
   sip.conf.sample for new installations. These may differ to keep backwards compatibility,
   yet encouraging new behaviour on new installations 
 */
#define DEFAULT_LISTEN_SIP_PORT	5060	/*!< From RFC 3261 (former 2543) */
#define STANDARD_SIP_PORT	5060	/*!< From RFC 3261 (former 2543) */
#define DEFAULT_CONTEXT		"default"
#define DEFAULT_MOHINTERPRET    "default"
#define DEFAULT_MOHSUGGEST      ""
#define DEFAULT_VMEXTEN 	"asterisk"
#define DEFAULT_CALLERID 	"asterisk"
#define DEFAULT_NOTIFYMIME 	"application/simple-message-summary"
#define DEFAULT_MWITIME 	10
#define DEFAULT_ALLOWGUEST	TRUE
#define DEFAULT_SRVLOOKUP	FALSE		/*!< Recommended setting is ON */
#define DEFAULT_COMPACTHEADERS	FALSE
#define DEFAULT_TOS_SIP         0               /*!< Call signalling packets should be marked as DSCP CS3, but the default is 0 to be compatible with previous versions. */
#define DEFAULT_TOS_AUDIO       0               /*!< Audio packets should be marked as DSCP EF (Expedited Forwarding), but the default is 0 to be compatible with previous versions. */
#define DEFAULT_TOS_VIDEO       0               /*!< Video packets should be marked as DSCP AF41, but the default is 0 to be compatible with previous versions. */
#define DEFAULT_TOS_PRESENCE    0               /*!< Presence notifications does not need SIP priority */
#define DEFAULT_ALLOW_EXT_DOM	TRUE
#define DEFAULT_REALM		"asterisk"
#define DEFAULT_NOTIFYRINGING	TRUE
#define DEFAULT_AUTOCREATEPEER	FALSE
#define DEFAULT_QUALIFY		FALSE
#define DEFAULT_T1MIN		100		/*!< 100 MS for minimal roundtrip time */
#define DEFAULT_MAX_CALL_BITRATE (384)		/*!< Max bitrate for video */
#ifndef DEFAULT_USERAGENT
#define DEFAULT_USERAGENT "Asterisk PBX"	/*!< Default Useragent: header unless re-defined in sip.conf */
#endif

#define DEC_CALL_LIMIT	0
#define INC_CALL_LIMIT	1
#define DEC_CALL_RINGING 2
#define INC_CALL_RINGING 3

/* --------- ENUM declarations */

/*! \brief Variants for sending responses with transmit_response_with_attachment() */
enum responseattach {
	WITH_MINEXPIRY,
	WITH_DATE,
	WITH_ALLOW,
	WITH_SDP,
	WITH_T38_SDP,
};

/*! \brief Authorization scheme for call transfers 
\note Not a bitfield flag, since there are plans for other modes,
	like "only allow transfers for authenticated devices" */
enum transfermodes {
	TRANSFER_OPENFORALL,            /*!< Allow all SIP transfers */
	TRANSFER_CLOSED,                /*!< Allow no SIP transfers */
};

typedef enum {
	AST_FALSE = 0,
	AST_TRUE = 1,
	AST_HAVENOCLUEANDDONOTCARE = -1,
} sip_boolean;

enum sip_result {
	AST_SUCCESS = 0,
	AST_FAILURE = -1,
};

/* Do _NOT_ make any changes to this enum, or the array following it;
   if you think you are doing the right thing, you are probably
   not doing the right thing. If you think there are changes
   needed, get someone else to review them first _before_
   submitting a patch. If these two lists do not match properly
   bad things will happen.
*/

enum objecttype {
	SIP_USER = (1 << 0),		/* USER places calls to the PBX */
	SIP_PEER = (1 << 1),		/* Peer receives calls from PBX (and places calls) */
};


enum xmittype {
	XMIT_CRITICAL = 2,              /*!< Transmit critical SIP message reliably, with re-transmits.
                                              If it fails, it's critical and will cause a teardown of the session */
	XMIT_RELIABLE = 1,              /*!< Transmit SIP message reliably, with re-transmits */
	XMIT_UNRELIABLE = 0,            /*!< Transmit SIP message without bothering with re-transmits */
};

enum parse_register_result {
	PARSE_REGISTER_FAILED_MINEXPIRY,
	PARSE_REGISTER_FAILED,
	PARSE_REGISTER_UPDATE,
	PARSE_REGISTER_QUERY,
};

enum subscriptiontype { 
	NONE = 0,
	XPIDF_XML,
	DIALOG_INFO_XML,
	CPIM_PIDF_XML,
	PIDF_XML,
	MWI_NOTIFICATION
};

/*! \brief SIP Request methods known by Asterisk */
enum sipmethod {
	SIP_UNKNOWN,		/* Unknown response */
	SIP_RESPONSE,		/* Not request, response to outbound request */
	SIP_REGISTER,
	SIP_OPTIONS,
	SIP_NOTIFY,
	SIP_INVITE,
	SIP_ACK,
	SIP_PRACK,		/* Not supported at all */
	SIP_BYE,
	SIP_REFER,
	SIP_SUBSCRIBE,
	SIP_MESSAGE,
	SIP_UPDATE,		/* We can send UPDATE; but not accept it */
	SIP_INFO,
	SIP_CANCEL,
	SIP_PUBLISH,		/* Not supported at all */
};

/*! \brief Authentication types - proxy or www authentication 
	\note Endpoints, like Asterisk, should always use WWW authentication to
	allow multiple authentications in the same call - to the proxy and
	to the end point.
*/
enum sip_auth_type {
	PROXY_AUTH = 407,
	WWW_AUTH = 401,
};

/*! \brief Authentication result from check_auth* functions */
enum check_auth_result {
	AUTH_SUCCESSFUL = 0,
	AUTH_CHALLENGE_SENT = 1,
	AUTH_SECRET_FAILED = -1,
	AUTH_USERNAME_MISMATCH = -2,
	AUTH_NOT_FOUND = -3,	/* Returned by register_verify */
	AUTH_FAKE_AUTH = -4,
	AUTH_UNKNOWN_DOMAIN = -5,
};

/*! \brief States for outbound registrations (with register= lines in sip.conf */
enum sipregistrystate {
	REG_STATE_UNREGISTERED = 0,	/*!< We are not registred */
	REG_STATE_REGSENT,	/*!< Registration request sent */
	REG_STATE_AUTHSENT,	/*!< We have tried to authenticate */
	REG_STATE_REGISTERED,	/*!< Registred and done */
	REG_STATE_REJECTED,	/*!< Registration rejected */
	REG_STATE_TIMEOUT,	/*!< Registration timed out */
	REG_STATE_NOAUTH,	/*!< We have no accepted credentials */
	REG_STATE_FAILED,	/*!< Registration failed after several tries */
};


/*! \brief Modes for SIP domain handling in the PBX */
enum domain_mode {
	SIP_DOMAIN_AUTO,		/*!< This domain is auto-configured */
	SIP_DOMAIN_CONFIG,		/*!< This domain is from configuration */
};

/*! \brief T38 States for a call */
enum t38state {
        T38_DISABLED = 0,                /*!< Not enabled */
        T38_LOCAL_DIRECT,                /*!< Offered from local */
        T38_LOCAL_REINVITE,              /*!< Offered from local - REINVITE */
        T38_PEER_DIRECT,                 /*!< Offered from peer */
        T38_PEER_REINVITE,               /*!< Offered from peer - REINVITE */
        T38_ENABLED                      /*!< Negotiated (enabled) */
};


/*! \brief Parameters to know status of transfer */
enum referstatus {
        REFER_IDLE,                    /*!< No REFER is in progress */
        REFER_SENT,                    /*!< Sent REFER to transferee */
        REFER_RECEIVED,                /*!< Received REFER from transferer */
        REFER_CONFIRMED,               /*!< Refer confirmed with a 100 TRYING */
        REFER_ACCEPTED,                /*!< Accepted by transferee */
        REFER_RINGING,                 /*!< Target Ringing */
        REFER_200OK,                   /*!< Answered by transfer target */
        REFER_FAILED,                  /*!< REFER declined - go on */
        REFER_NOAUTH                   /*!< We had no auth for REFER */
};

/*!<  SIP RFC 3261 states for the INVITE transaction */
enum invitetrans_state {
        INV_STATE_CALLING = 1,      /*!< Early state. Invite sent (only for client) */
        INV_STATE_PROCEEDING = 2,   /*!< Sent/Got 1xx message */
        INV_STATE_PROCEEDING_EARLY_MEDIA = 3,   /*!< Sent/Got 18x message */
        INV_STATE_COMPLETED = 3,    /*!< Sent/Got 300-699 message, Waiting for ACK, Then CONFIRMED */
        INV_STATE_CONFIRMED = 4,    /*!< For server transactions: We got an ACK (no more retries) */
        INV_STATE_TERMINATED = 5,   /*!< Sent/Got Transaction completed, finished, over and out buddy 
					- We might have a call or not  - check p->owner->_state */
        INV_STATE_CANCELLED = 6,    /*!< Sent/Got CANCEL or BYE in non-TERMINATED state */
};

/*! \brief Transaction state for non-invite transactions */
enum transaction_state {
	TRANS_TRYING,		/*!< Client: initiated transaction */
	TRANS_PROCEEDING,	/*!< Client: Provisional response received */
	TRANS_COMPLETED,	/*!< Final response received/sent */
	TRANS_TERMINATED,	/*!< We're done, no more re-transmits */
};

enum dialogstate {
	DIALOG_STATE_TRYING,		/*!< Sent invite, no response yet. Please answer :-) 
					\ref AST_STATE_RING, AST_STATE_DOWN, AST_STATE_RESERVED
						AST_STATE_OFFHOOK, AST_STATE_DIALING
					*/
	DIALOG_STATE_PROCEEDING,	/*!< Got 1xx reply without tag - something is alive! 
					\ref AST_STATE_RINGING
					*/
	DIALOG_STATE_EARLY,		/*!< We have early media or 1xx reply WITH tag
					If we get another with a different tag, it's another
					dialog (create a new pvt and, well, live with it 
					\ref AST_STATE_UP ???
					*/
	DIALOG_STATE_CONFIRMED,		/*!< 2xx received, we have something going on, buddy 
					\ref AST_STATE_UP
					*/
	DIALOG_STATE_CONFIRMED_HOLD,	/*!< We are in CONFIRMED state on HOLD 
					This is an ASTERISK state 
					\ref AST_STATE_UP */
	DIALOG_STATE_TERMINATED, 	/*!< This call is down - timeout, hangup, replaced 
					\ref AST_STATE_DOWN
					*/
	DIALOG_STATE_TERMINATED_AUTH,	/*!< Asterisk state for dialog that need to restart in
						TRYING for authentication */
	
};


/* -------- Structure declarations */

/* Define struct sip_history_head */
AST_LIST_HEAD_NOLOCK(sip_history_head, sip_history);

/*! \brief sip_request: The data grabbed from the UDP socket */
struct sip_request {
	int method;             /*!< Method of this request or response */
	enum transaction_state state;	/*!< State of this transaction */
	char *rlPart1; 	        /*!< SIP Method Name or "SIP/2.0" protocol version */
	char *rlPart2; 	        /*!< The Request URI or Response Status */
	const char *cseqheader;	/*!< Pointer to the cseq header */
	const char *callid;	/*!< Pointer to the call ID header */
	const char *via;	/*!< Pointer to the Via header */
	const char *to;		/*!< Pointer to the To header */
	const char *from;	/*!< Pointer to the from header */
	int len;                /*!< Length */
	int headers;            /*!< # of SIP Headers */
	unsigned int flags;     /*!< SIP_PKT Flags for this packet */
	char *header[SIP_MAX_HEADERS];	/*!< Pointers to the headers */
	int lines;              /*!< Body Content */
	char *line[SIP_MAX_LINES];	/*!< Pointer to content (attachment) lines */
	unsigned int sdp_start; /*!< the line number where the SDP begins */
	unsigned int sdp_end;   /*!< the line number where the SDP ends */

	/* New stuff to be implemented */
	// struct sip_request *nextrans;	/*!< Next transaction */
	// struct sip_request *nextmess;	/*!< Next message within *this* transaction */

	/* Retransmission data */
	struct sip_request *next;	/*!< For linked list of packets, use this */
	int retrans;			/*!< Retransmission number */
	int seqno;			/*!< Sequence number */
	struct sip_dialog *dialog;	/*!< Owner SIP dialog */
	int retransid;			/*!< Retransmission ID */
	int timer_a;			/*!< SIP timer A, retransmission timer */
	int timer_t1;			/*!< SIP Timer T1, estimated RTT or 500 ms */
	int packetlen;			/*!< Length of packet */
	char data[SIP_MAX_PACKET];	/*!< The actual message */
};

/*! \brief Invite transaction state */
struct sip_trans {
	struct sip_request initreq;	/*!< Initial request */
	int is_outbound;		/*!< TRUE if this is an outbound request */
	int cseq;			/*!< Cseq for this transaction */
	enum transaction_state state;	/*!< Transaction status */
	enum invitetrans_state invstate;	/*!< Invite transaction state */
};

/*! \brief Description of SUBSCRIBE events */
struct cfsubscription_types {
	enum subscriptiontype type;
	const char * const event;
	const char * const mediatype;
	const char * const text;
};


/*! \brief Structure for parsing of SIP methods.
\note Note that sip_methods[i].id == i must hold or the code breaks */
struct cfsip_methods { 
	enum sipmethod id;
	int need_rtp;		/*!< when this is the 'primary' use for a pvt structure, does it need RTP? */
	char * const text;
	int creates_dialog;	/*! Whether or not this method can create dialog */
};

/*! \brief Structure for expiration times for inbound/outbound REGISTER */
struct expiry_times {
	int	min_expiry;
	int	max_expiry;
	int	default_expiry;
	int	expiry;		/* ?? Is this ever used? */
};

/*! \brief List of well-known SIP options. If we get this in a require,
   we should check the list and answer accordingly. */
struct cfsip_options {
	int id;			/*!< Bitmap ID */
	int supported;		/*!< Supported by Asterisk ? */
	char * const text;	/*!< Text id, as in standard */
};


/*
 * A sip packet is stored into the data[] buffer, with the header followed
 * by an empty line and the body of the message.
 * On outgoing packets, data is accumulated in data[] with len reflecting
 * the next available byte, headers and lines count the number of lines
 * in both parts. There are no '\0' in data[0..len-1].
 *
 * On received packet, the input read from the socket is copied into data[],
 * len is set and the string is NUL-terminated. Then a parser fills up
 * the other fields -header[] and line[] to point to the lines of the
 * message, rlPart1 and rlPart2 parse the first lnie as below:
 *
 * Requests have in the first line	METHOD URI SIP/2.0
 *	rlPart1 = method; rlPart2 = uri;
 * Responses have in the first line	SIP/2.0 code description
 *	rlPart1 = SIP/2.0; rlPart2 = code + description;
 *
 */

/*! \brief structure used in transfers */
struct sip_dual {
	struct ast_channel *chan1;	/*!< First channel involved */
	struct ast_channel *chan2;	/*!< Second channel involved */
	struct sip_request req;		/*!< Request that caused the transfer (REFER) */
	int seqno;			/*!< Sequence number */
};

/*! \brief Parameters to the transmit_invite function */
struct sip_invite_param {
	int addsipheaders;		/*!< Add extra SIP headers */
	const char *uri_options;	/*!< URI options to add to the URI */
	const char *vxml_url;		/*!< VXML url for Cisco phones */
	char *auth;			/*!< Authentication */
	char *authheader;		/*!< Auth header */
	enum sip_auth_type auth_type;	/*!< Authentication type */
	const char *replaces;		/*!< Replaces header for call transfers */
	int transfer;			/*!< Flag - is this Invite part of a SIP transfer? (invite/replaces) */
};

/*! \brief Structure to save routing information for a SIP session */
struct sip_route {
	struct sip_route *next;
	char hop[0];
};


/*! \brief Domain data structure. 
	\note In the future, we will connect this to a configuration tree specific
	for this domain
*/
struct domain {
	char domain[MAXHOSTNAMELEN];		/*!< SIP domain we are responsible for */
	char context[AST_MAX_EXTENSION];	/*!< Incoming context for this domain */
	enum domain_mode mode;			/*!< How did we find this domain? */
	AST_LIST_ENTRY(domain) list;		/*!< List mechanics */
};

/*! \brief sip_history: Structure for saving transactions within a SIP dialog */
struct sip_history {
	AST_LIST_ENTRY(sip_history) list;
	char event[0];	/* actually more, depending on needs */
};

/*! \brief sip_auth: Creadentials for authentication to other SIP services */
struct sip_auth {
	char realm[AST_MAX_EXTENSION];  /*!< Realm in which these credentials are valid */
	char username[256];             /*!< Username */
	char secret[256];               /*!< Secret */
	char md5secret[256];            /*!< MD5Secret */
	struct sip_auth *next;          /*!< Next auth structure in list */
};

/*! \brief T.38 channel settings (at some point we need to make this alloc'ed */
struct t38properties {
	struct ast_flags t38support;	/*!< Flag for udptl, rtp or tcp support for this session */
	int capability;			/*!< Our T38 capability */
	int peercapability;		/*!< Peers T38 capability */
	int jointcapability;		/*!< Supported T38 capability at both ends */
	enum t38state state;		/*!< T.38 state */
};

/*! \brief The peer list: Peers and Friends */
struct sip_device_list {
	ASTOBJ_CONTAINER_COMPONENTS(struct sip_peer);
};

/*! \brief  The register list: Other SIP proxys we register with and place calls to */
struct sip_register_list {
	ASTOBJ_CONTAINER_COMPONENTS(struct sip_registry);
	int recheck;
};

/**--- some list management macros. **/
#define UNLINK(element, head, prev) do {	\
	if (prev)				\
		(prev)->next = (element)->next;	\
	else					\
		(head) = (element)->next;	\
	} while (0)


/*! \brief Append to SIP dialog history 
	\return Always returns 0 */
#define append_history(p, event, fmt , args... )	append_history_full(p, "%-15s " fmt, event, ## args)


/*--- Various flags for the flags field in the pvt structure */
#define SIP_ALREADYGONE		(1 << 0)	/*!< Whether or not we've already been destroyed by our peer */
#define SIP_NEEDDESTROY		(1 << 1)	/*!< if we need to be destroyed by the monitor thread */
#define SIP_NOVIDEO		(1 << 2)	/*!< Didn't get video in invite, don't offer */
#define SIP_RINGING		(1 << 3)	/*!< Have sent 180 ringing */
#define SIP_PROGRESS_SENT	(1 << 4)	/*!< Have sent 183 message progress */
#define SIP_NEEDREINVITE	(1 << 5)	/*!< Do we need to send another reinvite? */
#define SIP_PENDINGBYE		(1 << 6)	/*!< Need to send bye after we ack? */
#define SIP_GOTREFER		(1 << 7)	/*!< Got a refer? */
#define SIP_PROMISCREDIR	(1 << 8)	/*!< Promiscuous redirection */
#define SIP_TRUSTRPID		(1 << 9)	/*!< Trust RPID headers? */
#define SIP_USEREQPHONE		(1 << 10)	/*!< Add user=phone to numeric URI. Default off */
#define SIP_REALTIME		(1 << 11)	/*!< Flag for realtime users */
#define SIP_USECLIENTCODE	(1 << 12)	/*!< Trust X-ClientCode info message */
#define SIP_OUTGOING		(1 << 13)	/*!< Is this an outgoing call? */
#define SIP_CAN_BYE		(1 << 14)	/*!< Can we send BYE on this dialog? */
#define SIP_DEFER_BYE_ON_TRANSFER	(1 << 15)	/*!< Do not hangup at first ast_hangup */
#define SIP_DTMF		(3 << 16)	/*!< DTMF Support: four settings, uses two bits */
#define SIP_DTMF_RFC2833	(0 << 16)	/*!< DTMF Support: RTP DTMF - "rfc2833" */
#define SIP_DTMF_INBAND		(1 << 16)	/*!< DTMF Support: Inband audio, only for ULAW/ALAW - "inband" */
#define SIP_DTMF_INFO		(2 << 16)	/*!< DTMF Support: SIP Info messages - "info" */
#define SIP_DTMF_AUTO		(3 << 16)	/*!< DTMF Support: AUTO switch between rfc2833 and in-band DTMF */
/* NAT settings */
#define SIP_NAT			(3 << 18)	/*!< four settings, uses two bits */
#define SIP_NAT_NEVER		(0 << 18)	/*!< No nat support */
#define SIP_NAT_RFC3581		(1 << 18)	/*!< NAT RFC3581 */
#define SIP_NAT_ROUTE		(2 << 18)	/*!< NAT Only ROUTE */
#define SIP_NAT_ALWAYS		(3 << 18)	/*!< NAT Both ROUTE and RFC3581 */
/* re-INVITE related settings */
#define SIP_REINVITE		(7 << 20)	/*!< three bits used */
#define SIP_CAN_REINVITE	(1 << 20)	/*!< allow peers to be reinvited to send media directly p2p */
#define SIP_CAN_REINVITE_NAT	(2 << 20)	/*!< allow media reinvite when new peer is behind NAT */
#define SIP_REINVITE_UPDATE	(4 << 20)	/*!< use UPDATE (RFC3311) when reinviting this peer */
/* "insecure" settings */
#define SIP_INSECURE_PORT	(1 << 23)	/*!< don't require matching port for incoming requests */
#define SIP_INSECURE_INVITE	(1 << 24)	/*!< don't require authentication for incoming INVITEs */
/* Sending PROGRESS in-band settings */
#define SIP_PROG_INBAND		(3 << 25)	/*!< three settings, uses two bits */
#define SIP_PROG_INBAND_NEVER	(0 << 25)
#define SIP_PROG_INBAND_NO	(1 << 25)
#define SIP_PROG_INBAND_YES	(2 << 25)
#define SIP_NO_HISTORY		(1 << 27)	/*!< Supress recording request/response history */
#define SIP_CALL_LIMIT		(1 << 28)	/*!< Call limit enforced for this call */
#define SIP_SENDRPID		(1 << 29)	/*!< Remote Party-ID Support */
#define SIP_INC_COUNT		(1 << 30)	/*!< Did this connection increment the counter of in-use calls? */
#define SIP_G726_NONSTANDARD	(1 << 31)	/*!< Use non-standard packing for G726-32 data */

#define SIP_FLAGS_TO_COPY \
	(SIP_PROMISCREDIR | SIP_TRUSTRPID | SIP_SENDRPID | SIP_DTMF | SIP_REINVITE | \
	 SIP_PROG_INBAND | SIP_USECLIENTCODE | SIP_NAT | SIP_G726_NONSTANDARD | \
	 SIP_USEREQPHONE | SIP_INSECURE_PORT | SIP_INSECURE_INVITE)

/*--- a new page of flags (for flags[1] */
/* realtime flags */
#define SIP_PAGE2_RTCACHEFRIENDS	(1 << 0)
#define SIP_PAGE2_RTUPDATE		(1 << 1)
#define SIP_PAGE2_RTAUTOCLEAR		(1 << 2)
#define SIP_PAGE2_RT_FROMCONTACT 	(1 << 4)
#define SIP_PAGE2_RTSAVE_SYSNAME 	(1 << 5)
/* Space for addition of other realtime flags in the future */
#define SIP_PAGE2_IGNOREREGEXPIRE	(1 << 10)
#define SIP_PAGE2_DEBUG			(3 << 11)
#define SIP_PAGE2_DEBUG_CONFIG 		(1 << 11)
#define SIP_PAGE2_DEBUG_CONSOLE 	(1 << 12)
#define SIP_PAGE2_DYNAMIC		(1 << 13)	/*!< Dynamic Peers register with Asterisk */
#define SIP_PAGE2_SELFDESTRUCT		(1 << 14)	/*!< Automatic peers need to destruct themselves */
#define SIP_PAGE2_VIDEOSUPPORT		(1 << 15)
#define SIP_PAGE2_ALLOWSUBSCRIBE	(1 << 16)	/*!< Allow subscriptions from this peer? */
#define SIP_PAGE2_ALLOWOVERLAP		(1 << 17)	/*!< Allow overlap dialing ? */
#define SIP_PAGE2_SUBSCRIBEMWIONLY	(1 << 18)	/*!< Only issue MWI notification if subscribed to */
#define SIP_PAGE2_INC_RINGING		(1 << 19)	/*!< Did this connection increment the counter of in-use calls? */
#define SIP_PAGE2_T38SUPPORT		(7 << 20)	/*!< T38 Fax Passthrough Support */
#define SIP_PAGE2_T38SUPPORT_UDPTL	(1 << 20)	/*!< 20: T38 Fax Passthrough Support */
#define SIP_PAGE2_T38SUPPORT_RTP	(2 << 20)	/*!< 21: T38 Fax Passthrough Support */
#define SIP_PAGE2_T38SUPPORT_TCP	(4 << 20)	/*!< 22: T38 Fax Passthrough Support */
#define SIP_PAGE2_CALL_ONHOLD		(3 << 23)	/*!< Call states */
#define SIP_PAGE2_CALL_ONHOLD_ONEDIR	(1 << 23)	/*!< 23: One directional hold */
#define SIP_PAGE2_CALL_ONHOLD_INACTIVE	(2 << 24)	/*!< 24: Inactive  */
#define SIP_PAGE2_RFC2833_COMPENSATE    (1 << 26)
#define SIP_PAGE2_SERVICE               (1 << 27)	/*!< Whether this device is a service or not */

#define SIP_PAGE2_FLAGS_TO_COPY \
	(SIP_PAGE2_ALLOWSUBSCRIBE | SIP_PAGE2_ALLOWOVERLAP | SIP_PAGE2_VIDEOSUPPORT | SIP_PAGE2_T38SUPPORT | SIP_PAGE2_RFC2833_COMPENSATE)

/* SIP packet flags */
#define SIP_PKT_DEBUG		(1 << 0)	/*!< Debug this packet */
#define SIP_PKT_WITH_TOTAG	(1 << 1)	/*!< This packet has a to-tag */
#define SIP_PKT_IGNORE 		(1 << 2)	/*!< This is a re-transmit, ignore it */
#define SIP_PKT_IGNORE_RESP	(1 << 3)	/*!< Resp ignore - ??? */
#define SIP_PKT_IGNORE_REQ	(1 << 4)	/*!< Req ignore - ??? */
#define SIP_PKT_INITREQ		(1 << 5)	/*!< This is the initial request in this dialog */

#define SIP_PKT_RESPONSE	(1 << 6)	/*!< This packet is a response, not a request */
#define SIP_PKT_FATAL 		(1 << 7)	/*! Fatal - if this does not get through, the dialog dies */
#define SIP_PKT_CONNECTED	(1 << 8)	/*! This packet is connected to a dialog and should not
							be free'd by sipsock_read() */

#define CAN_CREATE_DIALOG	0
#define CAN_NOT_CREATE_DIALOG	1

/* T.38 set of flags */
#define T38FAX_FILL_BIT_REMOVAL		(1 << 0)	/*!< Default: 0 (unset)*/
#define T38FAX_TRANSCODING_MMR			(1 << 1)	/*!< Default: 0 (unset)*/
#define T38FAX_TRANSCODING_JBIG		(1 << 2)	/*!< Default: 0 (unset)*/
/* Rate management */
#define T38FAX_RATE_MANAGEMENT_TRANSFERED_TCF	(0 << 3)
#define T38FAX_RATE_MANAGEMENT_LOCAL_TCF	(1 << 3)	/*!< Unset for transferredTCF (UDPTL), set for localTCF (TPKT) */
/* UDP Error correction */
#define T38FAX_UDP_EC_NONE			(0 << 4)	/*!< two bits, if unset NO t38UDPEC field in T38 SDP*/
#define T38FAX_UDP_EC_FEC			(1 << 4)	/*!< Set for t38UDPFEC */
#define T38FAX_UDP_EC_REDUNDANCY		(2 << 4)	/*!< Set for t38UDPRedundancy */
/* T38 Spec version */
#define T38FAX_VERSION				(3 << 6)	/*!< two bits, 2 values so far, up to 4 values max */
#define T38FAX_VERSION_0			(0 << 6)	/*!< Version 0 */
#define T38FAX_VERSION_1			(1 << 6)	/*!< Version 1 */
/* Maximum Fax Rate */
#define T38FAX_RATE_2400			(1 << 8)	/*!< 2400 bps t38FaxRate */
#define T38FAX_RATE_4800			(1 << 9)	/*!< 4800 bps t38FaxRate */
#define T38FAX_RATE_7200			(1 << 10)	/*!< 7200 bps t38FaxRate */
#define T38FAX_RATE_9600			(1 << 11)	/*!< 9600 bps t38FaxRate */
#define T38FAX_RATE_12000			(1 << 12)	/*!< 12000 bps t38FaxRate */
#define T38FAX_RATE_14400			(1 << 13)	/*!< 14400 bps t38FaxRate */

#define sipdebug		ast_test_flag(&global.flags[1], SIP_PAGE2_DEBUG)
#define sipdebug_config		ast_test_flag(&global.flags[1], SIP_PAGE2_DEBUG_CONFIG)
#define sipdebug_console	ast_test_flag(&global.flags[1], SIP_PAGE2_DEBUG_CONSOLE)


/*! \brief Structure to handle SIP transfers. Dynamically allocated when needed  */
/* OEJ: Should be moved to string fields */
struct sip_refer {
	char refer_to[AST_MAX_EXTENSION];		/*!< Place to store REFER-TO extension */
	char refer_to_domain[AST_MAX_EXTENSION];	/*!< Place to store REFER-TO domain */
	char refer_to_urioption[AST_MAX_EXTENSION];	/*!< Place to store REFER-TO uri options */
	char refer_to_context[AST_MAX_EXTENSION];	/*!< Place to store REFER-TO context */
	char referred_by[AST_MAX_EXTENSION];		/*!< Place to store REFERRED-BY extension */
	char referred_by_name[AST_MAX_EXTENSION];	/*!< Place to store REFERRED-BY extension */
	char refer_contact[AST_MAX_EXTENSION];		/*!< Place to store Contact info from a REFER extension */
	char replaces_callid[BUFSIZ];			/*!< Replace info: callid */
	char replaces_callid_totag[BUFSIZ/2];		/*!< Replace info: to-tag */
	char replaces_callid_fromtag[BUFSIZ/2];		/*!< Replace info: from-tag */
	struct sip_dialog *refer_call;			/*!< Call we are referring */
	int attendedtransfer;				/*!< Attended or blind transfer? */
	int localtransfer;				/*!< Transfer to local domain? */
	enum referstatus status;			/*!< REFER status */
};

/*! \brief PVT structure are used for each SIP dialog, ie. a call, a registration, a subscribe  

	One SIP dialog is distinguished from another by these four items (if they exist)
		- Call ID
		- Remote tag= and local tag= (From: / To: header tags)
		- Topmost via header branch ID 
*/
struct sip_dialog {
	ast_mutex_t lock;			/*!< Dialog private lock */
	int method;				/*!< SIP method that opened this dialog */
	enum dialogstate state;			/*!< Dialog state */
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(callid);	/*!< Dialog ID: Global CallID  - the call ID is a unique ID for this SIP dialog,
							a string that never changes during the dialog */
		AST_STRING_FIELD(theirtag);	/*!< Dialog ID: remote side's tag */
		AST_STRING_FIELD(remotebranch);	/*!< Dialog ID: branch tag from topmost via */
		AST_STRING_FIELD(ourbranch);	/*!< Dialog ID: branch tag from topmost via */
		AST_STRING_FIELD(randdata);	/*!< Random data */
		AST_STRING_FIELD(realm);	/*!< Authorization realm for this dialog */
		AST_STRING_FIELD(nonce);	/*!< Authorization nonce */
		AST_STRING_FIELD(opaque);	/*!< Authorization Opaque string */
		AST_STRING_FIELD(qop);		/*!< Quality of Protection for authorization  */
		AST_STRING_FIELD(domain);	/*!< Authorization domain */
		AST_STRING_FIELD(from);		/*!< The From: header */
		AST_STRING_FIELD(useragent);	/*!< User agent in SIP request */
		AST_STRING_FIELD(exten);	/*!< Extension where to start */
		AST_STRING_FIELD(context);	/*!< Context for this call */
		AST_STRING_FIELD(subscribecontext); /*!< Subscribecontext */
		AST_STRING_FIELD(subscribeuri); /*!< Subscribecontext */
		AST_STRING_FIELD(fromdomain);	/*!< Domain to show in the from field */
		AST_STRING_FIELD(fromuser);	/*!< User to show in the user field */
		AST_STRING_FIELD(fromname);	/*!< Name to show as display name  */
		AST_STRING_FIELD(tohost);	/*!< Host we should put in the "to" field */
		AST_STRING_FIELD(language);	/*!< Default language for this call (to select prompts) */
		AST_STRING_FIELD(mohinterpret);	/*!< MOH class to use when put on hold */
		AST_STRING_FIELD(mohsuggest);	/*!< MOH class to suggest when putting a peer on hold */
		AST_STRING_FIELD(rdnis);	/*!< Referring DNIS */
		AST_STRING_FIELD(redircause);	/*!< Referring cause */
		AST_STRING_FIELD(defaultuser);	/*!< Default user name (used with default IP) */
		AST_STRING_FIELD(username);	/*!< Username part of URI */
		AST_STRING_FIELD(peername);	/*!< [peer] name, not set if [user] */
		AST_STRING_FIELD(authname);	/*!< Who we use for authentication */
		AST_STRING_FIELD(uri);		/*!< Original requested URI */
		AST_STRING_FIELD(okcontacturi);	/*!< URI from the 200 OK on INVITE */
		AST_STRING_FIELD(peersecret);	/*!< Password */
		AST_STRING_FIELD(peermd5secret);
		AST_STRING_FIELD(cid_num);	/*!< Caller*ID number */
		AST_STRING_FIELD(cid_name);	/*!< Caller*ID name */
		AST_STRING_FIELD(rpid);		/*!< Our RPID header */
		AST_STRING_FIELD(rpid_from);	/*!< Our RPID From header */
		AST_STRING_FIELD(via);		/*!< Via: header */
		AST_STRING_FIELD(fullcontact);	/*!< The Contact: that the UA registers with us */
		AST_STRING_FIELD(our_contact);	/*!< Our contact header */
		AST_STRING_FIELD(accountcode);	/*!< Account code - only used for billing */
	);
	/* Dialog settings */
	unsigned int ocseq;			/*!< Current outgoing seqno */
	unsigned int icseq;			/*!< Current incoming seqno */
	int lastinvite;				/*!< Last Cseq of invite */
	int timer_t1;				/*!< SIP timer T1, ms rtt */
	int autokillid;				/*!< Dialog response timer Auto-kill ID (scheduler) */
	unsigned int sipoptions;		/*!< Supported SIP options on the other end */
	int authtries;				/*!< Times we've tried to authenticate */
	int expiry;				/*!< How long we take to expire */
	char tag[11];				/*!< Dialog ID: Our tag for this session */
	int callingpres;			/*!< Caller ID presentation settings */
	struct sip_route *route;		/*!< Head of linked list of routing steps (fm Record-Route) */
	int route_persistant;			/*!< Is this the "real" route? */
	char lastmsg[256];			/*!< Last Message sent/received */
	int initid;				/*!< Invite Auto-congest ID if appropriate (scheduler) */
	int pendinginvite;			/*!< Any pending invite ? (seqno of this) */
	struct sip_request initreq;		/*!< Initial request that opened the SIP dialog 
							Something that keeps getting overwritten
						 */
	struct sip_request *packets;		/*!< Packets scheduled for re-transmission */
	struct sip_history_head *history;	/*!< History of this SIP dialog */

	struct ast_flags flags[2];		/*!< SIP_ flags - various flags grouped togheter to save memory */

	/* Authentication */
	struct sip_auth *peerauth;		/*!< Realm authentication */
	int noncecount;				/*!< Nonce-count */

	/* The grouping below shows that these settings should be allocated in substructures,
	   depending on the nature of the dialog - the method that opened it. Note that
	   one dialog can have both INVITE and REFER, but not SUSBCRIBE and REGISTER and INVITE */

	/* INVITE: Media support for this dialog */
	struct ast_codec_pref prefs;		/*!< codec prefs */
	int capability;				/*!< Special capability (codec) */
	int jointcapability;			/*!< Supported capability at both ends (codecs ) */
	int peercapability;			/*!< Supported peer capability */
	int prefcodec;				/*!< Preferred codec (outbound only) */
	int noncodeccapability;			/*!< DTMF RFC2833 telephony-event */
	int redircodecs;			/*!< Redirect codecs */
	int maxcallbitrate;			/*!< Maximum Call Bitrate for Video Calls */	
	struct ast_rtp *rtp;			/*!< RTP Session */
	struct ast_rtp *vrtp;			/*!< Video RTP session */

	/* T38 settings - these should be allocated only when needed */
	struct t38properties t38;		/*!< T38 settings */
	struct sockaddr_in udptlredirip;	/*!< Where our T.38 UDPTL should be going if not to us */
	struct ast_udptl *udptl;		/*!< T.38 UDPTL session */

	/* INVITE:  SDP/RTP settings - these could also be grouped together and allocated as needed */
	int sessionid;				/*!< SDP Session ID */
	int sessionversion;			/*!< SDP Session Version */
	struct sockaddr_in sa;			/*!< Our peer */
	struct sockaddr_in redirip;		/*!< Where our RTP should be going if not to us */
	struct sockaddr_in vredirip;		/*!< Where our Video RTP should be going if not to us */
	time_t lastrtprx;			/*!< Last RTP received */
	time_t lastrtptx;			/*!< Last RTP sent */
	struct ast_dsp *vad;			/*!< Inband DTMF Detection dsp */
	int autoframing;			/*!< ???? */

	struct sockaddr_in recv;		/*!< SIP Received from */
	struct in_addr ourip;			/*!< Our IP */

	/* INVITE:  PBX interface - this is only needeed for "calls", not for registrations etc */
	struct sip_invite_param *options;	/*!< Options for INVITE */
	struct ast_channel *owner;		/*!< Who owns us (if we have an owner) */
	ast_group_t callgroup;			/*!< Call group */
	ast_group_t pickupgroup;		/*!< Pickup group */
	int amaflags;				/*!< AMA Flags (only for billing) */
	struct ast_variable *chanvars;		/*!< Channel variables to set for inbound call */

	
	/* REFER: */
	enum transfermodes allowtransfer;	/*!< REFER: restriction scheme */
	struct sip_refer *refer;		/*!< REFER: SIP transfer data structure */

	/* SUBSCRIBE: These need to be allocated only for subscriptions */
	enum subscriptiontype subscribed;	/*!< SUBSCRIBE: Is this dialog a subscription?  */
	int stateid;				/*!< SUBSCRIBE: ID for devicestate subscriptions */
	int laststate;				/*!< SUBSCRIBE: Last known extension state */
	int dialogver;				/*!< SUBSCRIBE: Version for subscription dialog-info */
	struct sip_peer *relatedpeer;		/*!< If this dialog is related to a peer, which one 
							Used in peerpoke, mwi subscriptions */

	/* REGISTER (outbound) */
	struct sip_registry *registry;		/*!< If this is a REGISTER dialog, to which registry */

	struct sip_dialog *next;		/*!< Next dialog in chain */
};


/*! \brief Structure for SIP peer data, we place calls to peers if registered  or fixed IP address (host) */
/* XXX field 'name' must be first otherwise sip_addrcmp() will fail */
struct sip_peer {
	ASTOBJ_COMPONENTS(struct sip_peer);	/*!< name, refcount, objflags,  object pointers */
					/*!< device->name is the unique name of this object */
	char domain[MAXHOSTNAMELEN];	/*!< Domain name for this device. The name needs to be unique within
						a domain only 
					For type=phone, the domain needs to be a locally hosted domain */
	enum objecttype type;		/*!< SIP_PEER */
	char secret[80];		/*!< Password */
	char md5secret[80];		/*!< Password in MD5 */
	struct sip_auth *auth;		/*!< Realm authentication list */
	char context[AST_MAX_CONTEXT];	/*!< Default context for incoming calls */
	char subscribecontext[AST_MAX_CONTEXT];	/*!< Default context for subscriptions */
	char defaultuser[80];		/*!< Temporary username until registration */ 
	char authuser[80];		/*!< Authentication user name */
	char accountcode[AST_MAX_ACCOUNT_CODE];	/*!< Account code */
	int amaflags;			/*!< AMA Flags (for billing) */
	char tohost[MAXHOSTNAMELEN];	/*!< If not dynamic, IP address */
	char regexten[AST_MAX_EXTENSION]; /*!< Extension to register (if regcontext is used) */
	char fromuser[80];		/*!< From: user when calling this peer */
	char fromdomain[MAXHOSTNAMELEN];	/*!< From: domain when calling this peer */
	char fullcontact[256];		/*!< Contact registered with us (not in sip.conf) */
	char cid_num[80];		/*!< Caller ID num */
	char cid_name[80];		/*!< Caller ID name */
	int callingpres;		/*!< Calling id presentation */
	int inUse;			/*!< Number of calls in use */
	int inRinging;			/*!< Number of calls ringing */
	int onHold;                     /*!< Peer has someone on hold */
	int call_limit;			/*!< Limit of concurrent calls */
	enum transfermodes allowtransfer;	/*! SIP Refer restriction scheme */
	char vmexten[AST_MAX_EXTENSION]; /*!< Dialplan extension for MWI notify message*/
	char mailbox[AST_MAX_EXTENSION]; /*!< Mailbox setting for MWI checks */
	char language[MAX_LANGUAGE];	/*!<  Default language for prompts */
	char mohinterpret[MAX_MUSICCLASS];/*!<  Music on Hold class */
	char mohsuggest[MAX_MUSICCLASS];/*!<  Music on Hold class */
	char useragent[256];		/*!<  User agent in SIP request (saved from registration) */
	struct ast_codec_pref prefs;	/*!<  codec prefs */
	int lastmsgssent;
	time_t	lastmsgcheck;		/*!<  Last time we checked for MWI */
	unsigned int sipoptions;	/*!<  Supported SIP options */
	struct ast_flags flags[2];	/*!<  SIP_ flags */
	int expire;			/*!<  When to expire this peer registration */
	int capability;			/*!<  Codec capability */
	int rtptimeout;			/*!<  RTP timeout */
	int rtpholdtimeout;		/*!<  RTP Hold Timeout */
	int rtpkeepalive;		/*!<  Send RTP packets for keepalive */
	ast_group_t callgroup;		/*!<  Call group */
	ast_group_t pickupgroup;	/*!<  Pickup group */
	struct ast_dnsmgr_entry *dnsmgr;/*!<  DNS refresh manager for peer */
	struct sockaddr_in addr;	/*!<  IP address of peer */
	int maxcallbitrate;		/*!< Maximum Bitrate for a video call */
	
	/* Qualification */
	struct sip_dialog *call;		/*!<  Call pointer */
	int pokeexpire;			/*!<  When to expire poke (qualify= checking) */
	int lastms;			/*!<  How long last response took (in ms), or -1 for no response */
	int maxms;			/*!<  Max ms we will accept for the host to be up, 0 to not monitor */
	struct timeval ps;		/*!<  Time when sip_poke_peer() was executed */
	
	struct sockaddr_in defaddr;	/*!<  Default IP address, used until registration */
	struct ast_ha *ha;		/*!<  Access control list */
	struct ast_variable *chanvars;	/*!<  Variables to set for channel created by user */
	struct sip_dialog *mwipvt;		/*!<  Subscription for MWI */
	struct sip_registry *registry;	/*!< If this is a service, which registration is connected to this device */
	int lastmsg;
	int autoframing;
};


/*! \brief Registrations with other SIP proxies */
struct sip_registry {
	ASTOBJ_COMPONENTS_FULL(struct sip_registry,1,1);
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(callid);	/*!< Global Call-ID */
		AST_STRING_FIELD(realm);	/*!< Authorization realm */
		AST_STRING_FIELD(nonce);	/*!< Authorization nonce */
		AST_STRING_FIELD(opaque);	/*!< Opaque nonsense */
		AST_STRING_FIELD(qop);		/*!< Quality of Protection, since SIP wasn't complicated enough yet. */
		AST_STRING_FIELD(domain);	/*!< Authorization domain */
		AST_STRING_FIELD(username);	/*!< Who we are registering as */
		AST_STRING_FIELD(authuser);	/*!< Who we *authenticate* as */
		AST_STRING_FIELD(hostname);	/*!< Domain or host we register to */
		AST_STRING_FIELD(secret);	/*!< Password in clear text */	
		AST_STRING_FIELD(md5secret);	/*!< Password in md5 */
		AST_STRING_FIELD(contact);	/*!< Contact extension */
		AST_STRING_FIELD(extension);	/*!< Extension for callback */
		AST_STRING_FIELD(random);
	);
	int portno;			/*!<  Optional port override */
	int expire;			/*!< Sched ID of expiration */
	int expiry;			/*!< Requested value for expiration time */
	int regattempts;		/*!< Number of attempts (since the last success) */
	int timeout; 			/*!< sched id of sip_reg_timeout */
	int refresh;			/*!< How often to refresh */
	struct sip_dialog *call;	/*!< create a sip_dialog structure for each outbound "registration dialog" in progress */
	enum sipregistrystate regstate;	/*!< Registration state (see above) */
	time_t regtime;		/*!< Last succesful registration time */
	int callid_valid;		/*!< 0 means we haven't chosen callid for this registry yet. */
	unsigned int ocseq;		/*!< Sequence number we got to for REGISTERs for this registry */
	struct sockaddr_in us;		/*!< Who the server thinks we are */
	int noncecount;			/*!< Nonce-count */
	char lastmsg[256];		/*!< Last Message sent/received */
	struct sip_peer *peer;		/*!< If we have a known peer for this registry entry, use it for incoming calls */
};

/* Global settings only apply to the channel */
struct sip_globals {
	struct ast_jb_conf jbconf;	/*!< Jitterbuffer configuration */
	int rtautoclear;		/*!< Realtime caching options */
	int notifyringing;		/*!< Send notifications on ringing */
	int alwaysauthreject;		/*!< Send 401 Unauthorized for all failing requests */
	int srvlookup;			/*!< SRV Lookup on or off. Default is off, RFC behavior is on */
	int autocreatepeer;		/*!< Auto creation of peers at registration? Default off. */
	int relaxdtmf;			/*!< Relax DTMF */
	int rtptimeout;			/*!< Time out call if no RTP */
	int rtpholdtimeout;
	int rtpkeepalive;		/*!< Send RTP keepalives */
	int reg_timeout;	
	int regattempts_max;		/*!< Registration attempts before giving up */
	int allowguest;			/*!< allow unauthenticated users/peers to connect? */
	int allowsubscribe;		/*!< Flag for disabling ALL subscriptions, this is FALSE only if all peers are FALSE 
					    	the global setting is in globals_flags[1] */
	int mwitime;			/*!< Time between MWI checks for peers */
	unsigned int tos_sip;		/*!< IP type of service for SIP packets */
	unsigned int tos_audio;		/*!< IP type of service for audio RTP packets */
	unsigned int tos_video;		/*!< IP type of service for video RTP packets */
	unsigned int tos_presence;	/*!< IP type of service for SIP presence packets */
	int compactheaders;		/*!< send compact sip headers */
	int recordhistory;		/*!< Record SIP history. Off by default */
	int dumphistory;		/*!< Dump history to verbose before destroying SIP dialog */
	char realm[MAXHOSTNAMELEN]; 	/*!< Default realm */
	char regcontext[AST_MAX_CONTEXT];	/*!< Context for auto-extensions */
	char useragent[AST_MAX_EXTENSION];	/*!< Useragent for the SIP channel */
	int allow_external_domains;	/*!< Accept calls to external SIP domains? */
	int callevents;			/*!< Whether we send manager events or not */
	int t1min;			/*!< T1 roundtrip time minimum */
	enum transfermodes allowtransfer;	/*!< SIP Refer restriction scheme */
	int autoframing;
	struct ast_flags flags[2];	/* Flags for various default settings */
	/* Default values */
	int default_qualifycheck_ok;	/*!< Default qualify time when status is ok */
	int default_qualifycheck_notok;	/*!< Default qualify time when statusis not ok */
	int default_qualify;		/*!< Default Qualify= setting */
	int capability;			/*!< Codec support */
	int dtmf_capability;		/*!< DTMF support (2833) */
	int t38_capability;		/*!< T38 Capability */
	char default_context[AST_MAX_CONTEXT];
	char default_subscribecontext[AST_MAX_CONTEXT];
	char default_language[MAX_LANGUAGE];
	char default_callerid[AST_MAX_EXTENSION];
	char default_fromdomain[AST_MAX_EXTENSION];
	char default_notifymime[AST_MAX_EXTENSION];
	char default_vmexten[AST_MAX_EXTENSION];
	char default_mohinterpret[MAX_MUSICCLASS];  /*!< Global setting for moh class to use when put on hold */
	char default_mohsuggest[MAX_MUSICCLASS];	   /*!< Global setting for moh class to suggest when putting 
                                                    *   a bridged channel on hold */
	int default_maxcallbitrate;	/*!< Maximum bitrate for call */
	struct ast_codec_pref default_prefs;	/*!< Default codec prefs */
};

/* Network interface settings */
struct sip_network {
	int sipsock;			/*!< Network socket for this interface */
	struct sockaddr_in bindaddr;	/*!< Bind address */
	struct sockaddr_in externip;	/*!< External IP address (outside of NAT) */
	char externhost[MAXHOSTNAMELEN];	/*!< Extern host name in case of us being behind NAT */
	time_t externexpire;		/*!< Expiration time for DNS resolution of externhost */
	int externrefresh;		/*!< How often to re-resolve */
	struct ast_ha *localaddr;	/*!< Our local addresses (locanet= ) */
	struct in_addr __ourip;		/*!< Our IP */
	int ourport;		/*!< Our port */
	struct sockaddr_in outboundproxyip;	/*!< First SIP route hop */
	struct sockaddr_in debugaddr;	/*!< Debugging ??? */
	int *read_id;			/*!< ID of IO entry for sipsock socket FD */
};

struct channel_counters {
	int static_users;
	int realtime_users;
	int static_peers;
	int realtime_peers;
	int autocreated_peers;
	int registry_objects;
	int dialog_objects;
	int peers_with_mwi;
};

/*! @name External objects */
/*! @{ */
extern struct sip_network sipnet;               /*!< Sockets and networking */
extern struct expiry_times expiry;		/*!< Various expiration times */
extern struct ast_config *notify_types;		/*!< Notification types */
extern const char notify_config[];		/*!< Configuration file for notifications */
extern const struct cfsip_methods sip_methods[];	/*!< sip3_parse.c: SIP method table */
extern struct sip_globals global;	        /* Defined in chan_sip3.c */
extern struct sched_context *sched;             /*!< The scheduling context */
extern struct io_context *io;                   /*!< The IO context */
extern struct channel_counters sipcounters;	/*!< Various object counters */
extern struct sip_device_list devicelist; /*!< Device list */
extern struct sip_register_list regl;	/*!< Registration list */
extern struct sip_auth *authl;		/*!< Realm authentications */
extern struct sip_dialog *dialoglist;
/*! @} */

#endif
