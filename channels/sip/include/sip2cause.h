/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2010, Digium, Inc.
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
 * \brief sip2cause header file
 */

#include "sip.h"

#ifndef _SIP_CAUSE_H
#define _SIP_CAUSE_H

/*! \brief Convert SIP response code to ISDN or Asterisk-specific cause code */
int hangup_sip2cause(int cause);

/*! \brief Convert ISDN or Asterisk-specific cause code to SIP response code */
char *hangup_cause2sip(int cause);

/*! \brief Initialized sip2cause tables */
void sip2cause_init(void);

/*! \brief Free sip2cause tables */
void sip2cause_free(void);

/*! \brief Load configuration */
int sip2cause_load(struct ast_config *s2c_config);

#endif /* defined(_SIP_CAUSE_H) */
