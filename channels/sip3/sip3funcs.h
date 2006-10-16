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

/*! Function declarations */

/*! sip3_refer.c */
const char *referstatus2str(enum referstatus rstatus) attribute_pure;

/*! sip3_subscribe.c */
const char *subscription_type2str(enum subscriptiontype subtype) attribute_pure;
const struct cfsubscription_types *find_subscription_type(enum subscriptiontype subtype);

/*! sip3_network.c */
extern int sipsock_read(int *id, int fd, short events, void *ignore);
extern int sipnet_ourport(void);		/*!< Get current port number */
extern void sipnet_ourport_set(int port);	/*!< Set our port number */
extern void sipnet_lock(void);			/*!< Lock netlock mutex */
extern void sipnet_unlock(void);		/*!< Unlock netlock mutex */
extern int sipsocket_open(void);		/* Open network socket for SIP */
extern int sipsocket_initialized(void);		/* Check if we have network socket open */
extern int __sip_xmit(struct sip_pvt *p, char *data, int len);

/*! sip3_parse.c */
extern char *sip_method2txt(int method);
extern int sip_method_needrtp(int method);
extern int method_match(enum sipmethod id, const char *name);
extern int find_sip_method(const char *msg);
extern int sip_option_lookup(const char *optionlabel);
extern unsigned int parse_sip_options(struct sip_pvt *pvt, const char *supported);
extern char *sip_option2text(int option);
extern void sip_options_print(int options, int fd);

/*! sip3_domain.c: Domain handling functions (sip domain hosting, not DNS lookups) */
extern int add_sip_domain(const char *domain, const enum domain_mode mode, const char *context);
extern int domains_configured();
extern int check_sip_domain(const char *domain, char *context, size_t len);
extern void clear_sip_domains(void);
extern int func_check_sipdomain(struct ast_channel *chan, char *cmd, char *data, char *buf, size_t len);
extern struct ast_custom_function checksipdomain_function;	/* Definition of function */
extern const char *domain_mode_to_text(const enum domain_mode mode);
extern int sip_show_domains(int fd, int argc, char *argv[]);	/* CLI Function */

/*! sip3_auth.c */
extern void auth_headers(enum sip_auth_type code, char **header, char **respheader);
extern enum check_auth_result check_auth(struct sip_pvt *p, struct sip_request *req, const char *username,
		 const char *secret, const char *md5secret, int sipmethod,
		 char *uri, enum xmittype reliable, int ignore);
