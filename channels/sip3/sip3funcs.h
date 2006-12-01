/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 * and Edvina AB, Sollentuna, Sweden (chan_sip3 changes/additions)
 *
 * Mark Spencer <markster@digium.com>
 * Olle E. Johansson
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
GNURK void append_history_full(struct sip_dialog *p, const char *fmt, ...);
GNURK void append_history_va(struct sip_dialog *p, const char *fmt, va_list ap);
GNURK void sip_peer_hold(struct sip_dialog *p, int hold);
GNURK int transmit_reinvite_with_sdp(struct sip_dialog *p, int t38version);
GNURK void add_blank(struct sip_request *req);
GNURK int handle_request(struct sip_dialog *p, struct sip_request *req, struct sockaddr_in *sin, int *recount, int *nounlock);
GNURK int add_header(struct sip_request *req, const char *var, const char *value);
GNURK void sip_destroy_device(struct sip_peer *peer);
GNURK void destroy_association(struct sip_peer *peer);
GNURK void reg_source_db(struct sip_peer *peer);
GNURK int expire_register(void *data);
GNURK int sip_do_reload(void);
GNURK void parse_request(struct sip_request *req);
GNURK int transmit_response(struct sip_dialog *p, const char *msg, const struct sip_request *req);
GNURK void parse_copy(struct sip_request *dst, const struct sip_request *src);
GNURK int sip_prune_realtime(int fd, int argc, char *argv[]);	/* XXX Needs to move to sip3_cliami.c */
GNURK int sip_notify(int fd, int argc, char *argv[]); /* XXX Move where ?? */
GNURK struct sip_peer *find_device(const char *peer, struct sockaddr_in *sin, int realtime);
GNURK int sip_reload(int fd);
GNURK int transmit_response_with_auth(struct sip_dialog *p, const char *msg, const struct sip_request *req, const char *rand, enum xmittype reliable, const char *header, int stale);
GNURK int transmit_invite(struct sip_dialog *p, int sipmethod, int sdp, int init);
GNURK int transmit_request_with_auth(struct sip_dialog *p, int sipmethod, int seqno, enum xmittype reliable, int newbranch);
GNURK void do_setnat(struct sip_dialog *p, int natflags);
GNURK void build_via(struct sip_dialog *p, int forcenewbranch);
GNURK void __sip_pretend_ack(struct sip_dialog *p);
GNURK int create_addr(struct sip_dialog *dialog, const char *opeer);
GNURK int init_req(struct sip_request *req, int sipmethod, const char *recip);
GNURK void initialize_initreq(struct sip_dialog *p, struct sip_request *req);
GNURK int __transmit_response(struct sip_dialog *p, const char *msg, const struct sip_request *req, enum xmittype reliable);
GNURK int init_resp(struct sip_request *resp, const char *msg);
GNURK struct sip_dialog *get_sip_dialog_byid_locked(const char *callid, const char *totag, const char *fromtag);
GNURK void ast_quiet_chan(struct ast_channel *chan);
GNURK void sip_dump_history(struct sip_dialog *dialog);	/* Dump history to LOG_DEBUG at end of dialog, before destroying data */
GNURK void free_old_route(struct sip_route *route);
GNURK void find_via_branch(struct sip_request *req, char *viabuf, size_t vialen);
GNURK int update_call_counter(struct sip_dialog *fup, int event);
GNURK int sip_reload_check(void);
GNURK  int sip_send_mwi_to_peer(struct sip_peer *peer);

/*! sip3_refer.c */
GNURK const char *referstatus2str(enum referstatus rstatus) attribute_pure;
GNURK int handle_request_refer(struct sip_dialog *p, struct sip_request *req, int debug, int seqno, int *nounlock);
GNURK int sip_refer_allocate(struct sip_dialog *p);
GNURK int transmit_notify_with_sipfrag(struct sip_dialog *p, int cseq, char *message, int terminate);

/*! sip3_subscribe.c */
GNURK const char *subscription_type2str(enum subscriptiontype subtype) attribute_pure;
GNURK const struct cfsubscription_types *find_subscription_type(enum subscriptiontype subtype);
GNURK int transmit_state_notify(struct sip_dialog *p, int state, int full, int timeout);

/*! sip3_network.c */
GNURK void reset_ip_interface(struct sip_network *sipsock);
GNURK int sipsock_init(struct sip_network *sipsock, struct sockaddr_in *old_bindappr);
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
GNURK const struct sockaddr_in *sip_real_dst(const struct sip_dialog *p);
GNURK inline int sip_debug_test_pvt(struct sip_dialog *p);
GNURK inline int sip_debug_test_addr(const struct sockaddr_in *addr);
GNURK int sip_ouraddrfor(struct in_addr *them, struct in_addr *us);

/*! sip3_parse.c */
GNURK int lws2sws(char *msgbuf, int len);
GNURK char *sip_method2txt(int method);
GNURK int sip_method_needrtp(int method);
GNURK int method_match(enum sipmethod id, const char *name);
GNURK int find_sip_method(const char *msg);
GNURK int sip_option_lookup(const char *optionlabel);
GNURK unsigned int parse_sip_options(struct sip_dialog *pvt, const char *supported);
GNURK char *sip_option2text(int option);
GNURK void sip_options_print(int options, int fd);
GNURK const char *find_alias(const char *name, const char *_default);
GNURK const char *get_header(const struct sip_request *req, const char *name);
GNURK void copy_request(struct sip_request *dst, const struct sip_request *src);
GNURK int copy_header(struct sip_request *req, const struct sip_request *orig, const char *field);
GNURK int copy_all_header(struct sip_request *req, const struct sip_request *orig, const char *field);
GNURK int copy_via_headers(struct sip_dialog *p, struct sip_request *req, const struct sip_request *orig, const char *field);
GNURK const char *__get_header(const struct sip_request *req, const char *name, int *start);
GNURK char *get_in_brackets(char *tmp);
GNURK char *generate_random_string(char *buf, size_t size);
GNURK const char *gettag(const char *header, char *tagbuf, int tagbufsize);
GNURK int determine_firstline_parts(struct sip_request *req);
GNURK void extract_uri(struct sip_dialog *p, struct sip_request *req);
GNURK void parse_moved_contact(struct sip_dialog *p, struct sip_request *req);
GNURK int get_rdnis(struct sip_dialog *p, struct sip_request *oreq);
GNURK int get_destination(struct sip_dialog *p, struct sip_request *oreq);

/*! sip3_compose.c : Composing new SIP messages */
GNURK void build_callid_pvt(struct sip_dialog *pvt);
GNURK void append_date(struct sip_request *req);
GNURK int add_text(struct sip_request *req, const char *text);
GNURK int add_digit(struct sip_request *req, char digit);
GNURK int respprep(struct sip_request *resp, struct sip_dialog *p, const char *msg, const struct sip_request *req);
GNURK void add_route(struct sip_request *req, struct sip_route *route);
GNURK int add_line(struct sip_request *req, const char *line);
GNURK int add_header_contentLength(struct sip_request *req, int len);
GNURK void initreqprep(struct sip_request *req, struct sip_dialog *p, int sipmethod);
GNURK int reqprep(struct sip_request *req, struct sip_dialog *p, int sipmethod, int seqno, int newbranch);
GNURK void build_contact(struct sip_dialog *p);
GNURK void build_rpid(struct sip_dialog *p);

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
GNURK int clear_realm_authentication(struct sip_auth *authlist);	/* Clear realm authentication list (at reload) */
GNURK struct sip_auth *find_realm_authentication(struct sip_auth *authlist, const char *realm);
GNURK struct sip_auth *add_realm_authentication(struct sip_auth *authlist, char *configuration, int lineno);

/* sip3_sdprtp.c */
GNURK struct ast_frame *sip_read(struct ast_channel *ast);
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
GNURK struct ast_frame *sip_read(struct ast_channel *ast);
GNURK void stop_media_flows(struct sip_dialog *dialog);

/* sip3_config.c */
GNURK void set_device_defaults(struct sip_peer *device);
GNURK struct sip_peer *realtime_peer(const char *newpeername, struct sockaddr_in *sin);
GNURK int reload_config(enum channelreloadreason reason);

/* sip3_callerid.c */
GNURK int get_rpid_num(const char *input, char *output, int maxlen);
GNURK char *get_calleridname(const char *input, char *output, size_t outputsize);
GNURK void replace_cid(struct sip_dialog *p, const char *rpid_num, const char *calleridname);

/* sip3_cliami.c */
GNURK const char *sip_nat_mode(const struct sip_dialog *p);
GNURK void  print_group(int fd, ast_group_t group, int crlf);
GNURK int peer_status(struct sip_peer *peer, char *status, int statuslen);
GNURK int manager_sip_show_device(struct mansession *s, struct message *m );
GNURK int manager_sip_show_devices(struct mansession *s, struct message *m);
GNURK void sip_cli_and_manager_commands_register(void);
GNURK void sip_cli_and_manager_commands_unregister(void);
GNURK char *complete_sip_device(const char *word, int state, int flags2);
GNURK char *complete_sip_show_device(const char *line, const char *word, int pos, int state);


/* sip3_dialog.c */
GNURK void dialoglist_lock(void);
GNURK void dialoglist_unlock(void);
GNURK const char *dialogstate2str(const enum dialogstate state);
GNURK void dialogstatechange(struct sip_dialog *dialog, enum dialogstate newstate);
GNURK void sip_scheddestroy(struct sip_dialog *p, int ms);
GNURK void sip_cancel_destroy(struct sip_dialog *p);
GNURK int hangup_sip2cause(int cause);
GNURK const char *hangup_cause2sip(int cause);
GNURK struct sip_dialog *sip_alloc(ast_string_field callid, struct sockaddr_in *sin, int useglobal_nat, const int intended_method);
GNURK void make_our_tag(char *tagbuf, size_t len);
GNURK struct sip_dialog *match_or_create_dialog(struct sip_request *req, struct sockaddr_in *sin, const int intended_method);
GNURK void sip_destroy(struct sip_dialog *p);
GNURK void __sip_destroy(struct sip_dialog *p, int lockowner, int lockdialoglist);
GNURK void __sip_ack(struct sip_dialog *dialog, int seqno, int resp, int sipmethod, int reset);
GNURK int __sip_semi_ack(struct sip_dialog *p, int seqno, int resp, int sipmethod);
GNURK void dialog_lock(struct sip_dialog *dialog, int state);
GNURK int transmit_final_response(struct sip_dialog *dialog, const char *msg, const struct sip_request *req, enum xmittype reliable);


/* sip3_services.c - outbound registration for services from other servers/providers  */

GNURK void sip_send_all_registers(void);
GNURK int sip_register(char *value, int lineno, struct sip_peer *peer);
GNURK void sip_registry_destroy(struct sip_registry *reg);
GNURK char *regstate2str(enum sipregistrystate regstate) attribute_const;
GNURK int handle_response_register(struct sip_dialog *p, int resp, char *rest, struct sip_request *req, int seqno);
GNURK int transmit_register(struct sip_registry *r, int sipmethod, const char *auth, const char *authheader);

/* sip3_utils.c - various utility functions */
GNURK void logdebug(int level, const char *fmt, ...);

/* sip3_pokedevice.c - poking peers (qualify) */
int sip_poke_noanswer(void *data);
int sip_poke_peer(struct sip_peer *peer);
void sip_poke_all_peers(void);
int sip_poke_peer_s(void *data);
int sip_poke_peer(struct sip_peer *peer);
void handle_response_peerpoke(struct sip_dialog *p, int resp, struct sip_request *req);

/* sip3_monitor.c - the monitor thread */
void *do_sip_monitor(void *data);
void kill_monitor(void);
int restart_monitor(void);

#endif
