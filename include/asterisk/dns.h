/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Written by Thorsten Lockert <tholo@trollphone.org>
 *
 * Funding provided by Troll Phone Networks AS
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
 * \brief DNS support for Asterisk
 * \author Thorsten Lockert <tholo@trollphone.org>
 */

#ifndef _ASTERISK_DNS_H
#define _ASTERISK_DNS_H

/*!	\brief	Perform DNS lookup (used by DNS, enum and SRV lookups)
	\param	context
	\param	dname	Domain name to lookup (host, SRV domain, TXT record name)
	\param	class	Record Class (see "man res_search")
	\param	type	Record type (see "man res_search")
	\param	callback Callback function for handling DNS result
	\note   Asterisk DNS is synchronus at this time. This means that if your DNS
		services does not work, Asterisk may lock while waiting for response.
*/
int ast_search_dns(void *context, const char *dname, int class, int type,
	 int (*callback)(void *context, unsigned char *answer, int len, unsigned char *fullanswer));

/*!
 * \since 1.8
 *
 * \brief
 * Parses a string with an IPv4 or IPv6 address and place results into an array
 *
 * \details
 * Parses a string containing a host name or an IPv4 or IPv6 address followed
 * by an optional port (separated by a colon).  The result is returned into a
 * array of struct ast_sockaddr. Allowed formats for str are the following:
 *
 * hostname:port
 * host.example.com:port
 * a.b.c.d
 * a.b.c.d:port
 * a:b:c:...:d
 * [a:b:c:...:d]
 * [a:b:c:...:d]:port
 *
 * \param[out] addrs The resulting array of ast_sockaddrs
 * \param str The string to parse
 * \param flags If set to zero, a port MAY be present. If set to
 * PARSE_PORT_IGNORE, a port MAY be present but will be ignored. If set to
 * PARSE_PORT_REQUIRE, a port MUST be present. If set to PARSE_PORT_FORBID, a
 * port MUST NOT be present.
 *
 * \param family Only addresses of the given family will be returned. Use 0 or
 * AST_AF_UNSPEC to get addresses of all families.
 *
 * \retval 0 Failure
 * \retval non-zero The number of elements in addrs array.
 */
int ast_sockaddr_resolve(struct ast_sockaddr **addrs, const char *str, int flags, int family);

/*! \brief  Return the first entry from ast_sockaddr_resolve filtered by address family
 *
 * \warning Using this function probably means you have a faulty design.
 */
int ast_sockaddr_resolve_first_af(struct ast_sockaddr *addr, const char *name, int flag, int family);

#endif /* _ASTERISK_DNS_H */
