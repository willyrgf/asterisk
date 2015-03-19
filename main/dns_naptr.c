/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2015, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
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
 * \brief DNS NAPTR Record Support
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <arpa/nameser.h>

#include "asterisk/dns_core.h"
#include "asterisk/dns_naptr.h"
#include "asterisk/linkedlists.h"
#include "asterisk/dns_internal.h"
#include "asterisk/utils.h"

const char *ast_dns_naptr_get_flags(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->flags;
}

const char *ast_dns_naptr_get_service(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->service;
}

const char *ast_dns_naptr_get_regexp(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->regexp;
}

const char *ast_dns_naptr_get_replacement(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->replacement;
}

unsigned short ast_dns_naptr_get_order(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->order;
}

unsigned short ast_dns_naptr_get_preference(const struct ast_dns_record *record)
{
	struct ast_dns_naptr_record *naptr = (struct ast_dns_naptr_record *) record;

	ast_assert(ast_dns_record_get_rr_type(record) == ns_t_naptr);
	return naptr->preference;
}
