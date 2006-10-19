/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
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

/*!
 * \file
 * \brief Definitions of functions in the sip3 library files used
 * 	by chan_sip3.c 
 *
 * Version 3 of chan_sip
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Olle E. Johansson <oej@edvina.net> (all the chan_sip3 changes)
 *
 * See Also:
 * \arg \ref AstCREDITS
 *
 */

#ifndef SIP3_FUNCS
#define SIP3_FUNCS

//#define GNURK	extern
#define GNURK

/*! Function declarations */

/*! Chan_sip3.c */
/* XXX Should we really expose functions in chan_sip3.c ? */
extern struct sip_globals global;	/* Defined in chan_sip3.c */
extern struct sched_context *sched;     /*!< The scheduling context */
extern struct io_context *io;           /*!< The IO context */
extern struct channel_counters sipcounters;	/*!< Various object counters */
extern struct sip_user_list userl;
extern struct sip_device_list peerl;
extern struct sip_register_list regl;
extern struct sip_auth *authl;

GNURK inline int sip_debug_test_pvt(struct sip_pvt *p) ;
GNURK void append_history_full(struct sip_pvt *p, const char *fmt, ...);
GNURK void append_history_va(struct sip_pvt *p, const char *fmt, va_list ap);
GNURK void sip_peer_hold(struct sip_pvt *p, int hold);
GNURK int sip_register(char *value, int lineno);;
GNURK struct sip_auth *add_realm_authentication(struct sip_auth *authlist, char *configuration, int lineno);	/* Add realm authentication in list */
GNURK int transmit_reinvite_with_sdp(struct sip_pvt *p);
GNURK struct sip_pvt *find_call(struct sip_request *req, struct sockaddr_in *sin, const int intended_method);
GNURK void add_blank(struct sip_request *req);
GNURK int lws2sws(char *msgbuf, int len);
GNURK int handle_request(struct sip_pvt *p, struct sip_request *req, struct sockaddr_in *sin, int *recount, int *nounlock);
GNURK const char *get_header(const struct sip_request *req, const char *name);
GNURK int add_header(struct sip_request *req, const char *var, const char *value);
GNURK int add_header_contentLength(struct sip_request *req, int len);
GNURK void sip_destroy_device(struct sip_peer *peer);
GNURK void destroy_association(struct sip_peer *peer);
GNURK void reg_source_db(struct sip_peer *peer);
GNURK int expire_register(void *data);

/*! sip3_refer.c */
GNURK const char *referstatus2str(enum referstatus rstatus) attribute_pure;

/*! sip3_subscribe.c */
GNURK const char *subscription_type2str(enum subscriptiontype subtype) attribute_pure;
GNURK const struct cfsubscription_types *find_subscription_type(enum subscriptiontype subtype);

/*! sip3_network.c */
GNURK int sipsock_read(int *id, int fd, short events, void *ignore);
GNURK int sipnet_ourport(void);		/*!< Get current port number */
GNURK void sipnet_ourport_set(int port);	/*!< Set our port number */
GNURK void sipnet_lock(void);			/*!< Lock netlock mutex */
GNURK void sipnet_unlock(void);		/*!< Unlock netlock mutex */
GNURK int sipsocket_open(void);		/* Open network socket for SIP */
GNURK int sipsocket_initialized(void);		/* Check if we have network socket open */
/* XXX these (including retrans_pkt) may not belong here in the future,
   they involve the transaction states  and need to handle various transports (UDP, TCP) */
GNURK int send_response(struct sip_pvt *p, struct sip_request *req, enum xmittype reliable, int seqno);
GNURK int send_request(struct sip_pvt *p, struct sip_request *req, enum xmittype reliable, int seqno);

/*! sip3_parse.c */
GNURK char *sip_method2txt(int method);
GNURK int sip_method_needrtp(int method);
GNURK int method_match(enum sipmethod id, const char *name);
GNURK int find_sip_method(const char *msg);
GNURK int sip_option_lookup(const char *optionlabel);
GNURK unsigned int parse_sip_options(struct sip_pvt *pvt, const char *supported);
GNURK char *sip_option2text(int option);
GNURK void sip_options_print(int options, int fd);

/*! sip3_domain.c: Domain handling functions (sip domain hosting, not DNS lookups) */
GNURK int add_sip_domain(const char *domain, const enum domain_mode mode, const char *context);
GNURK int domains_configured(void);
GNURK int check_sip_domain(const char *domain, char *context, size_t len);
GNURK void clear_sip_domains(void);
GNURK int func_check_sipdomain(struct ast_channel *chan, char *cmd, char *data, char *buf, size_t len);
GNURK struct ast_custom_function checksipdomain_function;	/* Definition of function */
GNURK const char *domain_mode_to_text(const enum domain_mode mode);
GNURK int sip_show_domains(int fd, int argc, char *argv[]);	/* CLI Function */

/*! sip3_auth.c */
GNURK void auth_headers(enum sip_auth_type code, char **header, char **respheader);
GNURK enum check_auth_result check_auth(struct sip_pvt *p, struct sip_request *req, const char *username,
		 const char *secret, const char *md5secret, int sipmethod,
		 char *uri, enum xmittype reliable, int ignore);
GNURK int do_register_auth(struct sip_pvt *p, struct sip_request *req, enum sip_auth_type code);
GNURK int do_proxy_auth(struct sip_pvt *p, struct sip_request *req, enum sip_auth_type code, int sipmethod, int init);
GNURK int reply_digest(struct sip_pvt *p, struct sip_request *req, char *header, int sipmethod,  char *digest, int digest_len);
GNURK int build_reply_digest(struct sip_pvt *p, int method, char* digest, int digest_len);

/* sip3_sdprtp.c */
GNURK char *get_body(struct sip_request *req, char *name);
GNURK int process_sdp(struct sip_pvt *p, struct sip_request *req);
GNURK int sip_set_rtp_peer(struct ast_channel *chan, struct ast_rtp *rtp, struct ast_rtp *vrtp, int codecs, int nat_active);
GNURK enum ast_rtp_get_result sip_get_rtp_peer(struct ast_channel *chan, struct ast_rtp **rtp);
GNURK enum ast_rtp_get_result sip_get_vrtp_peer(struct ast_channel *chan, struct ast_rtp **rtp);
GNURK char *get_body(struct sip_request *req, char *name);
GNURK int find_sdp(struct sip_request *req);
GNURK int add_sdp(struct sip_request *resp, struct sip_pvt *p);

/* sip3_config.c */
GNURK void set_device_defaults(struct sip_peer *device);
GNURK struct sip_peer *realtime_peer(const char *newpeername, struct sockaddr_in *sin);
GNURK struct sip_peer *realtime_user(const char *username);
GNURK int reload_config(enum channelreloadreason reason);
#endif
