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
GNURK int __sip_xmit(struct sip_pvt *p, char *data, int len);

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

/* sip3_sdprtp.c */
GNURK int process_sdp(struct sip_pvt *p, struct sip_request *req);
GNURK int sip_set_rtp_peer(struct ast_channel *chan, struct ast_rtp *rtp, struct ast_rtp *vrtp, int codecs, int nat_active);
GNURK enum ast_rtp_get_result sip_get_rtp_peer(struct ast_channel *chan, struct ast_rtp **rtp);
GNURK enum ast_rtp_get_result sip_get_vrtp_peer(struct ast_channel *chan, struct ast_rtp **rtp);
GNURK char *get_body(struct sip_request *req, char *name);

#endif
