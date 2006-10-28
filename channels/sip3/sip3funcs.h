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
/* These needs to be resorted and moved around */
GNURK inline int sip_debug_test_pvt(struct sip_dialog *p) ;
GNURK void append_history_full(struct sip_dialog *p, const char *fmt, ...);
GNURK void append_history_va(struct sip_dialog *p, const char *fmt, va_list ap);
GNURK void sip_peer_hold(struct sip_dialog *p, int hold);
GNURK int sip_register(char *value, int lineno);;
GNURK struct sip_auth *add_realm_authentication(struct sip_auth *authlist, char *configuration, int lineno);	/* Add realm authentication in list */
GNURK int transmit_reinvite_with_sdp(struct sip_dialog *p);
GNURK struct sip_dialog *find_call(struct sip_request *req, struct sockaddr_in *sin, const int intended_method);
GNURK void add_blank(struct sip_request *req);
GNURK int lws2sws(char *msgbuf, int len);
GNURK int handle_request(struct sip_dialog *p, struct sip_request *req, struct sockaddr_in *sin, int *recount, int *nounlock);
GNURK const char *get_header(const struct sip_request *req, const char *name);
GNURK int add_header(struct sip_request *req, const char *var, const char *value);
GNURK int add_header_contentLength(struct sip_request *req, int len);
GNURK void sip_destroy_device(struct sip_peer *peer);
GNURK void destroy_association(struct sip_peer *peer);
GNURK void reg_source_db(struct sip_peer *peer);
GNURK int expire_register(void *data);
GNURK struct sip_auth *find_realm_authentication(struct sip_auth *authlist, const char *realm);
GNURK int add_line(struct sip_request *req, const char *line);
GNURK int sip_do_relaod(enum channelreloadreason reason);
GNURK inline int sip_debug_test_addr(const struct sockaddr_in *addr);
GNURK void parse_request(struct sip_request *req);
GNURK int transmit_response(struct sip_dialog *p, const char *msg, const struct sip_request *req);
GNURK const struct sockaddr_in *sip_real_dst(const struct sip_dialog *p);
GNURK void parse_copy(struct sip_request *dst, const struct sip_request *src);
GNURK int sip_prune_realtime(int fd, int argc, char *argv[]);	/* XXX Needs to move to sip3_cliami.c */
GNURK int sip_notify(int fd, int argc, char *argv[]); /* XXX Move where ?? */
GNURK struct sip_peer *find_device(const char *peer, struct sockaddr_in *sin, int realtime);
GNURK char *regstate2str(enum sipregistrystate regstate) attribute_const;
GNURK int sip_reload(int fd);
GNURK int transmit_response_with_auth(struct sip_dialog *p, const char *msg, const struct sip_request *req, const char *rand, enum xmittype reliable, const char *header, int stale);
GNURK int transmit_register(struct sip_registry *r, int sipmethod, const char *auth, const char *authheader);
GNURK int transmit_invite(struct sip_dialog *p, int sipmethod, int sdp, int init);
GNURK int transmit_reinvite_with_t38_sdp(struct sip_dialog *p);
GNURK void sip_scheddestroy(struct sip_dialog *p, int ms);

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
GNURK int send_response(struct sip_dialog *p, struct sip_request *req, enum xmittype reliable, int seqno);
GNURK int send_request(struct sip_dialog *p, struct sip_request *req, enum xmittype reliable, int seqno);

/*! sip3_parse.c */
GNURK char *sip_method2txt(int method);
GNURK int sip_method_needrtp(int method);
GNURK int method_match(enum sipmethod id, const char *name);
GNURK int find_sip_method(const char *msg);
GNURK int sip_option_lookup(const char *optionlabel);
GNURK unsigned int parse_sip_options(struct sip_dialog *pvt, const char *supported);
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
GNURK enum check_auth_result check_auth(struct sip_dialog *p, struct sip_request *req, const char *username,
		 const char *secret, const char *md5secret, int sipmethod,
		 char *uri, enum xmittype reliable, int ignore);
GNURK int do_register_auth(struct sip_dialog *p, struct sip_request *req, enum sip_auth_type code);
GNURK int do_proxy_auth(struct sip_dialog *p, struct sip_request *req, enum sip_auth_type code, int sipmethod, int init);
GNURK int reply_digest(struct sip_dialog *p, struct sip_request *req, char *header, int sipmethod,  char *digest, int digest_len);
GNURK int build_reply_digest(struct sip_dialog *p, int method, char* digest, int digest_len);

/* sip3_sdprtp.c */
GNURK void register_rtp_and_udptl(void);
GNURK void unregister_rtp_and_udptl(void);
GNURK char *get_body(struct sip_request *req, char *name);
GNURK int process_sdp(struct sip_dialog *p, struct sip_request *req);
GNURK int sip_set_rtp_peer(struct ast_channel *chan, struct ast_rtp *rtp, struct ast_rtp *vrtp, int codecs, int nat_active);
GNURK enum ast_rtp_get_result sip_get_rtp_peer(struct ast_channel *chan, struct ast_rtp **rtp);
GNURK enum ast_rtp_get_result sip_get_vrtp_peer(struct ast_channel *chan, struct ast_rtp **rtp);
GNURK char *get_body(struct sip_request *req, char *name);
GNURK int find_sdp(struct sip_request *req);
GNURK int add_sdp(struct sip_request *resp, struct sip_dialog *p);

/* sip3_config.c */
GNURK void set_device_defaults(struct sip_peer *device);
GNURK struct sip_peer *realtime_peer(const char *newpeername, struct sockaddr_in *sin);
GNURK struct sip_peer *realtime_user(const char *username);
GNURK int reload_config(enum channelreloadreason reason);

/* sip3_callerid.c */
GNURK int get_rpid_num(const char *input, char *output, int maxlen);
GNURK char *get_calleridname(const char *input, char *output, size_t outputsize);
GNURK void replace_cid(struct sip_dialog *p, const char *rpid_num, const char *calleridname);

/* sip3_cliami.c */
GNURK const char *sip_nat_mode(const struct sip_dialog *p);
GNURK void  print_group(int fd, ast_group_t group, int crlf);
GNURK int peer_status(struct sip_peer *peer, char *status, int statuslen);
GNURK int manager_sip_show_peers( struct mansession *s, struct message *m );
GNURK int manager_sip_show_peer( struct mansession *s, struct message *m);
GNURK void sip_cli_and_manager_commands_register(void);
GNURK void sip_cli_and_manager_commands_unregister(void);
//static char *complete_sipch(const char *line, const char *word, int pos, int state);
GNURK char *complete_sip_peer(const char *word, int state, int flags2);
GNURK char *complete_sip_show_peer(const char *line, const char *word, int pos, int state);
//static char *complete_sip_debug_peer(const char *line, const char *word, int pos, int state);
GNURK char *complete_sip_user(const char *word, int state, int flags2);
//static char *complete_sip_show_user(const char *line, const char *word, int pos, int state);
//static char *complete_sipnotify(const char *line, const char *word, int pos, int state);
//static char *complete_sip_prune_realtime_peer(const char *line, const char *word, int pos, int state);
//static char *complete_sip_prune_realtime_user(const char *line, const char *word, int pos, int state);


/* sip3_dialog.h */
GNURK void dialoglist_lock(void);
GNURK void dialoglist_unlock(void);

#endif
