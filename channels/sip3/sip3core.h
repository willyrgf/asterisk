/*------------------------------------------------------------------------------------

Old list of all functions in chan_sip3.c - functions that needs to be moved, or 
encapsulated so they are not needed in a common namespace

------------------------------------------------------------------------------------*/

/*--- Transmitting responses and requests */
extern int __transmit_response(struct sip_pvt *p, const char *msg, const struct sip_request *req, enum xmittype reliable);
extern int transmit_sip_request(struct sip_pvt *p, struct sip_request *req);
extern int transmit_response(struct sip_pvt *p, const char *msg, const struct sip_request *req);
extern int transmit_response_reliable(struct sip_pvt *p, const char *msg, const struct sip_request *req);
extern int transmit_response_with_date(struct sip_pvt *p, const char *msg, const struct sip_request *req);
extern int transmit_response_with_sdp(struct sip_pvt *p, const char *msg, const struct sip_request *req, enum xmittype reliable);
extern int transmit_response_with_unsupported(struct sip_pvt *p, const char *msg, const struct sip_request *req, const char *unsupported);
extern int transmit_response_with_auth(struct sip_pvt *p, const char *msg, const struct sip_request *req, const char *rand, enum xmittype reliable, const char *header, int stale);
extern int transmit_response_with_allow(struct sip_pvt *p, const char *msg, const struct sip_request *req, enum xmittype reliable);
extern void transmit_fake_auth_response(struct sip_pvt *p, struct sip_request *req, int reliable);
extern int transmit_request(struct sip_pvt *p, int sipmethod, int inc, enum xmittype reliable, int newbranch);
extern int transmit_request_with_auth(struct sip_pvt *p, int sipmethod, int seqno, enum xmittype reliable, int newbranch);
extern int transmit_invite(struct sip_pvt *p, int sipmethod, int sdp, int init);
extern int transmit_reinvite_with_sdp(struct sip_pvt *p);
extern int transmit_info_with_digit(struct sip_pvt *p, const char digit);
extern int transmit_info_with_vidupdate(struct sip_pvt *p);
extern int transmit_message_with_text(struct sip_pvt *p, const char *text);
extern int transmit_refer(struct sip_pvt *p, const char *dest);
extern int transmit_notify_with_mwi(struct sip_pvt *p, int newmsgs, int oldmsgs, char *vmexten);
extern int transmit_notify_with_sipfrag(struct sip_pvt *p, int cseq, char *message, int terminate);
extern int transmit_state_notify(struct sip_pvt *p, int state, int full);
extern int transmit_register(struct sip_registry *r, int sipmethod, const char *auth, const char *authheader);
extern int send_request(struct sip_pvt *p, struct sip_request *req, enum xmittype reliable, int seqno);
extern void copy_request(struct sip_request *dst, const struct sip_request *src);
extern void receive_message(struct sip_pvt *p, struct sip_request *req);
extern void parse_moved_contact(struct sip_pvt *p, struct sip_request *req);
extern int sip_send_mwi_to_peer(struct sip_peer *peer);
extern int does_peer_need_mwi(struct sip_peer *peer);

/*--- Dialog management */
extern struct sip_pvt *sip_alloc(ast_string_field callid, struct sockaddr_in *sin,
				 int useglobal_nat, const int intended_method);
extern int __sip_autodestruct(void *data);
extern void sip_scheddestroy(struct sip_pvt *p, int ms);
extern void sip_cancel_destroy(struct sip_pvt *p);
extern void sip_destroy(struct sip_pvt *p);
extern void __sip_destroy(struct sip_pvt *p, int lockowner);
extern void __sip_ack(struct sip_pvt *p, int seqno, int resp, int sipmethod, int reset);
extern void __sip_pretend_ack(struct sip_pvt *p);
extern int __sip_semi_ack(struct sip_pvt *p, int seqno, int resp, int sipmethod);
extern int auto_congest(void *nothing);
extern int update_call_counter(struct sip_pvt *fup, int event);
extern int hangup_sip2cause(int cause);
extern const char *hangup_cause2sip(int cause);
extern struct sip_pvt *find_call(struct sip_request *req, struct sockaddr_in *sin, const int intended_method);
extern void free_old_route(struct sip_route *route);
extern void list_route(struct sip_route *route);
extern void build_route(struct sip_pvt *p, struct sip_request *req, int backwards);
extern enum check_auth_result register_verify(struct sip_pvt *p, struct sockaddr_in *sin,
					      struct sip_request *req, char *uri);
extern struct sip_pvt *get_sip_pvt_byid_locked(const char *callid, const char *totag, const char *fromtag);
extern void check_pendings(struct sip_pvt *p);
extern void *sip_park_thread(void *stuff);
extern int sip_park(struct ast_channel *chan1, struct ast_channel *chan2, struct sip_request *req, int seqno);
extern int sip_sipredirect(struct sip_pvt *p, const char *dest);

/*--- Codec handling / SDP */
extern void try_suggested_sip_codec(struct sip_pvt *p);
extern int find_sdp(struct sip_request *req);
extern void add_codec_to_sdp(const struct sip_pvt *p, int codec, int sample_rate,
			     char **m_buf, size_t *m_size, char **a_buf, size_t *a_size,
			     int debug);
extern void add_noncodec_to_sdp(const struct sip_pvt *p, int format, int sample_rate,
				char **m_buf, size_t *m_size, char **a_buf, size_t *a_size,
				int debug);
extern int add_sdp(struct sip_request *resp, struct sip_pvt *p);

/*--- Authentication stuff */
extern int do_proxy_auth(struct sip_pvt *p, struct sip_request *req, char *header, char *respheader, int sipmethod, int init);
extern int reply_digest(struct sip_pvt *p, struct sip_request *req, char *header, int sipmethod, char *digest, int digest_len);
extern int build_reply_digest(struct sip_pvt *p, int method, char *digest, int digest_len);
extern int clear_realm_authentication(struct sip_auth *authlist);	/* Clear realm authentication list (at reload) */
extern struct sip_auth *add_realm_authentication(struct sip_auth *authlist, char *configuration, int lineno);	/* Add realm authentication in list */
extern struct sip_auth *find_realm_authentication(struct sip_auth *authlist, const char *realm);	/* Find authentication for a specific realm */
extern enum check_auth_result check_auth(struct sip_pvt *p, struct sip_request *req, const char *username,
					 const char *secret, const char *md5secret, int sipmethod,
					 char *uri, enum xmittype reliable, int ignore);
extern enum check_auth_result check_user_full(struct sip_pvt *p, struct sip_request *req,
					      int sipmethod, char *uri, enum xmittype reliable,
					      struct sockaddr_in *sin, struct sip_peer **authpeer);
extern int check_user(struct sip_pvt *p, struct sip_request *req, int sipmethod, char *uri, enum xmittype reliable, struct sockaddr_in *sin);
extern int do_proxy_auth(struct sip_pvt *p, struct sip_request *req, char *header, char *respheader, int sipmethod, int init);
extern int build_reply_digest(struct sip_pvt *p, int method, char* digest, int digest_len);

/*--- Domain handling */
extern int check_sip_domain(const char *domain, char *context, size_t len); /* Check if domain is one of our local domains */
extern int add_sip_domain(const char *domain, const enum domain_mode mode, const char *context);
extern void clear_sip_domains(void);

/*--- SIP realm authentication */
extern struct sip_auth *add_realm_authentication(struct sip_auth *authlist, char *configuration, int lineno);
extern int clear_realm_authentication(struct sip_auth *authlist);
extern struct sip_auth *find_realm_authentication(struct sip_auth *authlist, const char *realm);

/*--- Misc functions */
extern int sip_do_reload(enum channelreloadreason reason);
extern int reload_config(enum channelreloadreason reason);
extern int expire_register(void *data);
extern int sip_sipredirect(struct sip_pvt *p, const char *dest);
extern void *do_monitor(void *data);
extern int restart_monitor(void);
extern int sip_send_mwi_to_peer(struct sip_peer *peer);
extern void sip_destroy(struct sip_pvt *p);
extern int sip_addrcmp(char *name, struct sockaddr_in *sin);	/* Support for peer matching */
extern int sip_refer_allocate(struct sip_pvt *p);
extern void ast_quiet_chan(struct ast_channel *chan);
extern int attempt_transfer(struct sip_dual *transferer, struct sip_dual *target);

/*--- Device monitoring and Device/extension state handling */
extern int cb_extensionstate(char *context, char* exten, int state, void *data);
extern int sip_devicestate(void *data);
extern int sip_poke_noanswer(void *data);
extern int sip_poke_peer(struct sip_peer *peer);
extern void sip_poke_all_peers(void);
extern void sip_peer_hold(struct sip_pvt *p, int hold);

/*--- Applications, functions, CLI and manager command helpers */
extern const char *sip_nat_mode(const struct sip_pvt *p);
extern int sip_show_inuse(int fd, int argc, char *argv[]);
extern char *transfermode2str(enum transfermodes mode) attribute_const;
extern char *nat2str(int nat) attribute_const;
extern int peer_status(struct sip_peer *peer, char *status, int statuslen);
extern int sip_show_users(int fd, int argc, char *argv[]);
extern int _sip_show_peers(int fd, int *total, struct mansession *s, struct message *m, int argc, char *argv[]);
extern int manager_sip_show_peers( struct mansession *s, struct message *m );
extern int sip_show_peers(int fd, int argc, char *argv[]);
extern int sip_show_objects(int fd, int argc, char *argv[]);
extern void  print_group(int fd, ast_group_t group, int crlf);
extern const char *dtmfmode2str(int mode) attribute_const;
extern const char *insecure2str(int port, int invite) attribute_const;
extern void cleanup_stale_contexts(char *new, char *old);
extern void print_codec_to_cli(int fd, struct ast_codec_pref *pref);
extern const char *domain_mode_to_text(const enum domain_mode mode);
extern int sip_show_domains(int fd, int argc, char *argv[]);
extern int _sip_show_peer(int type, int fd, struct mansession *s, struct message *m, int argc, char *argv[]);
extern int manager_sip_show_peer( struct mansession *s, struct message *m);
extern int sip_show_peer(int fd, int argc, char *argv[]);
extern int _sip_show_peer(int type, int fd, struct mansession *s, struct message *m, int argc, char *argv[]);
extern int sip_show_user(int fd, int argc, char *argv[]);
extern int sip_show_registry(int fd, int argc, char *argv[]);
extern int sip_show_settings(int fd, int argc, char *argv[]);
extern int __sip_show_channels(int fd, int argc, char *argv[], int subscriptions);
extern int sip_show_channels(int fd, int argc, char *argv[]);
extern int sip_show_subscriptions(int fd, int argc, char *argv[]);
extern int __sip_show_channels(int fd, int argc, char *argv[], int subscriptions);
extern char *complete_sipch(const char *line, const char *word, int pos, int state);
extern char *complete_sip_peer(const char *word, int state, int flags2);
extern char *complete_sip_show_peer(const char *line, const char *word, int pos, int state);
extern char *complete_sip_debug_peer(const char *line, const char *word, int pos, int state);
extern char *complete_sip_user(const char *word, int state, int flags2);
extern char *complete_sip_show_user(const char *line, const char *word, int pos, int state);
extern char *complete_sipnotify(const char *line, const char *word, int pos, int state);
extern char *complete_sip_prune_realtime_peer(const char *line, const char *word, int pos, int state);
extern char *complete_sip_prune_realtime_user(const char *line, const char *word, int pos, int state);
extern int sip_show_channel(int fd, int argc, char *argv[]);
extern int sip_show_history(int fd, int argc, char *argv[]);
extern int sip_do_debug_ip(int fd, int argc, char *argv[]);
extern int sip_do_debug_peer(int fd, int argc, char *argv[]);
extern int sip_do_debug(int fd, int argc, char *argv[]);
extern int sip_no_debug(int fd, int argc, char *argv[]);
extern int sip_notify(int fd, int argc, char *argv[]);
extern int sip_do_history(int fd, int argc, char *argv[]);
extern int sip_no_history(int fd, int argc, char *argv[]);
extern int func_header_read(struct ast_channel *chan, char *function, char *data, char *buf, size_t len);
extern int func_check_sipdomain(struct ast_channel *chan, char *cmd, char *data, char *buf, size_t len);
extern int function_sippeer(struct ast_channel *chan, char *cmd, char *data, char *buf, size_t len);
extern int function_sipchaninfo_read(struct ast_channel *chan, char *cmd, char *data, char *buf, size_t len);
extern int sip_dtmfmode(struct ast_channel *chan, void *data);
extern int sip_addheader(struct ast_channel *chan, void *data);
extern int sip_do_reload(enum channelreloadreason reason);
extern int sip_reload(int fd, int argc, char *argv[]);

/*--- Debugging 
	Functions for enabling debug per IP or fully, or enabling history logging for
	a SIP dialog
*/
extern void sip_dump_history(struct sip_pvt *dialog);	/* Dump history to LOG_DEBUG at end of dialog, before destroying data */
extern inline int sip_debug_test_addr(const struct sockaddr_in *addr);
extern inline int sip_debug_test_pvt(struct sip_pvt *p);
extern void append_history_full(struct sip_pvt *p, const char *fmt, ...);
extern void sip_dump_history(struct sip_pvt *dialog);

/*--- Device object handling */
extern struct sip_peer *temp_peer(const char *name);
extern struct sip_peer *build_peer(const char *name, struct ast_variable *v, struct ast_variable *alt, int realtime);
extern struct sip_peer *build_user(const char *name, struct ast_variable *v, int realtime);
extern int update_call_counter(struct sip_pvt *fup, int event);
extern void sip_destroy_device(struct sip_peer *peer);
extern int sip_poke_peer(struct sip_peer *peer);
extern void set_device_defaults(struct sip_peer *peer);
extern struct sip_peer *temp_peer(const char *name);
extern void register_peer_exten(struct sip_peer *peer, int onoff);
extern struct sip_peer *find_peer(const char *peer, struct sockaddr_in *sin, int realtime);
extern struct sip_peer *find_user(const char *name, int realtime);
extern int sip_poke_peer_s(void *data);
extern enum parse_register_result parse_register_contact(struct sip_pvt *pvt, struct sip_peer *p, struct sip_request *req);
extern int expire_register(void *data);
extern void reg_source_db(struct sip_peer *peer);
extern void destroy_association(struct sip_peer *peer);
extern int handle_common_options(struct ast_flags *flags, struct ast_flags *mask, struct ast_variable *v);

/* Realtime device support */
extern void realtime_update_peer(const char *peername, struct sockaddr_in *sin, const char *username, const char *fullcontact, int expirey);
extern struct sip_peer *realtime_user(const char *username);
extern void update_peer(struct sip_peer *p, int expiry);
extern struct sip_peer *realtime_peer(const char *peername, struct sockaddr_in *sin);
extern int sip_prune_realtime(int fd, int argc, char *argv[]);

/*--- Internal UA client handling (outbound registrations) */
extern int ast_sip_ouraddrfor(struct in_addr *them, struct in_addr *us);
extern void sip_registry_destroy(struct sip_registry *reg);
extern int sip_register(char *value, int lineno);
extern char *regstate2str(enum sipregistrystate regstate) attribute_const;
extern int sip_reregister(void *data);
extern int __sip_do_register(struct sip_registry *r);
extern int sip_reg_timeout(void *data);
extern int do_register_auth(struct sip_pvt *p, struct sip_request *req, char *header, char *respheader);
extern int reply_digest(struct sip_pvt *p, struct sip_request *req, char *header, int sipmethod,  char *digest, int digest_len);
extern void sip_send_all_registers(void);

/*--- Parsing SIP requests and responses */
extern void append_date(struct sip_request *req);	/* Append date to SIP packet */
extern int determine_firstline_parts(struct sip_request *req);
extern const char *gettag(const struct sip_request *req, const char *header, char *tagbuf, int tagbufsize);
extern int find_sip_method(const char *msg);
extern unsigned int parse_sip_options(struct sip_pvt *pvt, const char *supported);
extern void parse_request(struct sip_request *req);
extern const char *get_header(const struct sip_request *req, const char *name);
extern int method_match(enum sipmethod id, const char *name);
extern void parse_copy(struct sip_request *dst, const struct sip_request *src);
static void add_blank(struct sip_request *req);
extern char *get_in_brackets(char *tmp);
extern const char *find_alias(const char *name, const char *_default);
extern const char *__get_header(const struct sip_request *req, const char *name, int *start);
extern const char *get_header(const struct sip_request *req, const char *name);
extern int lws2sws(char *msgbuf, int len);
extern void extract_uri(struct sip_pvt *p, struct sip_request *req);
extern int get_refer_info(struct sip_pvt *transferer, struct sip_request *outgoing_req);
extern int get_also_info(struct sip_pvt *p, struct sip_request *oreq);
extern int parse_ok_contact(struct sip_pvt *pvt, struct sip_request *req);
extern int set_address_from_contact(struct sip_pvt *pvt);
extern void check_via(struct sip_pvt *p, struct sip_request *req);
extern char *get_calleridname(const char *input, char *output, size_t outputsize);
extern int get_rpid_num(const char *input, char *output, int maxlen);
extern int get_rdnis(struct sip_pvt *p, struct sip_request *oreq);
extern int get_destination(struct sip_pvt *p, struct sip_request *oreq);
extern int get_msg_text(char *buf, int len, struct sip_request *req);
extern const char *gettag(const struct sip_request *req, const char *header, char *tagbuf, int tagbufsize);
extern void free_old_route(struct sip_route *route);

/*--- Constructing requests and responses */
extern void initialize_initreq(struct sip_pvt *p, struct sip_request *req);
extern int init_req(struct sip_request *req, int sipmethod, const char *recip);
extern int reqprep(struct sip_request *req, struct sip_pvt *p, int sipmethod, int seqno, int newbranch);
extern void initreqprep(struct sip_request *req, struct sip_pvt *p, int sipmethod);
extern int init_resp(struct sip_request *resp, const char *msg);
extern int respprep(struct sip_request *resp, struct sip_pvt *p, const char *msg, const struct sip_request *req);
extern const struct sockaddr_in *sip_real_dst(const struct sip_pvt *p);
extern void build_via(struct sip_pvt *p);
extern int create_addr_from_peer(struct sip_pvt *r, struct sip_peer *peer);
extern int create_addr(struct sip_pvt *dialog, const char *opeer);
extern char *generate_random_string(char *buf, size_t size);
extern void build_callid_pvt(struct sip_pvt *pvt);
extern void build_callid_registry(struct sip_registry *reg, struct in_addr ourip, const char *fromdomain);
extern void make_our_tag(char *tagbuf, size_t len);
extern int add_header(struct sip_request *req, const char *var, const char *value);
extern int add_header_contentLength(struct sip_request *req, int len);
extern int add_line(struct sip_request *req, const char *line);
extern int add_text(struct sip_request *req, const char *text);
extern int add_digit(struct sip_request *req, char digit);
extern int add_vidupdate(struct sip_request *req);
extern void add_route(struct sip_request *req, struct sip_route *route);
extern int copy_header(struct sip_request *req, const struct sip_request *orig, const char *field);
extern int copy_all_header(struct sip_request *req, const struct sip_request *orig, const char *field);
extern int copy_via_headers(struct sip_pvt *p, struct sip_request *req, const struct sip_request *orig, const char *field);
extern void set_destination(struct sip_pvt *p, char *uri);
extern void append_date(struct sip_request *req);
extern void build_contact(struct sip_pvt *p);
extern void build_rpid(struct sip_pvt *p);

/*------Request handling functions */
extern int handle_request(struct sip_pvt *p, struct sip_request *req, struct sockaddr_in *sin, int *recount, int *nounlock);
extern int handle_request_invite(struct sip_pvt *p, struct sip_request *req, int debug, int seqno, struct sockaddr_in *sin, int *recount, char *e);
extern int handle_request_refer(struct sip_pvt *p, struct sip_request *req, int debug, int ignore, int seqno, int *nounlock);
extern int handle_request_bye(struct sip_pvt *p, struct sip_request *req);
extern int handle_request_register(struct sip_pvt *p, struct sip_request *req, struct sockaddr_in *sin, char *e);
extern int handle_request_cancel(struct sip_pvt *p, struct sip_request *req);
extern int handle_request_message(struct sip_pvt *p, struct sip_request *req);
extern int handle_request_subscribe(struct sip_pvt *p, struct sip_request *req, struct sockaddr_in *sin, int seqno, char *e);
extern void handle_request_info(struct sip_pvt *p, struct sip_request *req);
extern int handle_request_options(struct sip_pvt *p, struct sip_request *req);
extern int handle_invite_replaces(struct sip_pvt *p, struct sip_request *req, int debug, int ignore, int seqno, struct sockaddr_in *sin);
extern int handle_request_notify(struct sip_pvt *p, struct sip_request *req, struct sockaddr_in *sin, int seqno, char *e);
extern int handle_invite_replaces(struct sip_pvt *p, struct sip_request *req, int debug, int ignore, int seqno, struct sockaddr_in *sin);
extern int local_attended_transfer(struct sip_pvt *transferer, struct sip_dual *current, struct sip_request *req, int seqno);

/*------Response handling functions */
extern void handle_response_invite(struct sip_pvt *p, int resp, char *rest, struct sip_request *req, int seqno);
extern void handle_response_refer(struct sip_pvt *p, int resp, char *rest, struct sip_request *req, int seqno);
extern int handle_response_peerpoke(struct sip_pvt *p, int resp, struct sip_request *req);
extern int handle_response_register(struct sip_pvt *p, int resp, char *rest, struct sip_request *req, int ignore, int seqno);
extern void handle_response(struct sip_pvt *p, int resp, char *rest, struct sip_request *req, int ignore, int seqno);

/*----- RTP interface functions */
extern int sip_set_rtp_peer(struct ast_channel *chan, struct ast_rtp *rtp, struct ast_rtp *vrtp, int codecs, int nat_active);
extern int sip_get_codec(struct ast_channel *chan);
extern struct ast_frame *sip_rtp_read(struct ast_channel *ast, struct sip_pvt *p, int *faxdetect);

/*------ T38 Support --------- */
extern int sip_handle_t38_reinvite(struct ast_channel *chan, struct sip_pvt *pvt, int reinvite); /*!< T38 negotiation helper function */
extern int transmit_response_with_t38_sdp(struct sip_pvt *p, char *msg, struct sip_request *req, int retrans);
extern int transmit_reinvite_with_t38_sdp(struct sip_pvt *p);
extern struct ast_udptl *sip_get_udptl_peer(struct ast_channel *chan);
extern int sip_set_udptl_peer(struct ast_channel *chan, struct ast_udptl *udptl);

