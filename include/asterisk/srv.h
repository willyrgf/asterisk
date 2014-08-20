/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
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

/*
 * DNS SRV record support
 */

#ifndef _ASTERISK_SRV_H
#define _ASTERISK_SRV_H

/*!
  \file srv.h
  \brief Support for DNS SRV records, used in to locate SIP services.
  \note Note: This SRV record support will respect the priority and
        weight elements of the records that are returned, but there are
	no provisions for retrying or failover between records.
*/

/*!\brief An opaque type, for lookup usage */
struct srv_context;

/*! \brief Allocate a new SRV context 
*/
struct srv_context *ast_srv_context_new(void);

/*! \brief Free all entries in the context, but not the context itself */
void ast_srv_context_free_list(struct srv_context *context);

/*!\brief Retrieve set of SRV lookups, in order
 * \param[in] context A pointer in which to hold the result
 * \param[in] service The service name to look up
 * \param[out] host Result host
 * \param[out] port Associated TCP portnum
 * \retval -1 Query failed
 * \retval 0 Result exists in host and port
 * \retval 1 No more results
 */
extern int ast_srv_lookup(struct srv_context **context, const char *service, const char **host, unsigned short *port);

/*!\brief Cleanup resources associated with ast_srv_lookup
 * \param context Pointer passed into ast_srv_lookup
 */
void ast_srv_cleanup(struct srv_context **context);


/*! Lookup entry in SRV records Returns 1 if found, 0 if not found, -1 on hangup 
	Only do SRV record lookup if you get a domain without a port. If you get a port #, it's a DNS host name.
	\param	chan Ast channel
	\param	host host name (return value)
	\param	hostlen Length of string "host"
	\param	port Port number (return value)
	\param service Service tag for SRV lookup (like "_sip._udp" or "_stun._udp"
*/
extern int ast_get_srv(struct ast_channel *chan, char *host, int hostlen, int *port, const char *service);

/*! Lookup entry in SRV records Returns 1 if found, 0 if not found, -1 on hangup 
	Only do SRV record lookup if you get a domain without a port. If you get a port #, it's a DNS host name.
	\param  context A context for SRV lookups that will contain the list. Client needs to free this list with ast_srv_cleanup
	\param	chan Ast channel
	\param service Service tag for SRV lookup (like "_sip._udp" or "_stun._udp"
*/
extern int ast_get_srv_list(struct srv_context *context, struct ast_channel *chan, const char *service);

/*!
 * \brief Get the number of records for a given SRV context
 *
 * \details
 * This is meant to be used after calling ast_srv_lookup, so that
 * one may retrieve the number of records returned during a specific
 * SRV lookup.
 *
 * \param context The context returned by ast_srv_lookup
 * \return Number of records in context
 */
unsigned int ast_srv_get_record_count(struct srv_context *context);

/*!
 * \brief Retrieve details from a specific SRV record
 *
 * \details
 * After calling ast_srv_lookup, the srv_context will contain
 * the data from several records. You can retrieve the data
 * of a specific one by asking for a specific record number. The
 * records are sorted based on priority and secondarily based on
 * weight. See RFC 2782 for the exact sorting rules.
 *
 * This function sets the "current" pointer to the selected entry.
 *
 * \param context The context returned by ast_srv_lookup
 * \param record_num The 1-indexed record number to retrieve
 * \param[out] host The host portion of the record
 * \param[out] port The port portion of the record
 * \param[out] priority The priority portion of the record
 * \param[out] weight The weight portion of the record
 * \retval -1 Failed to retrieve information. Likely due to an out of
 * range record_num
 * \retval 0 Success
 */
int ast_srv_get_nth_record(struct srv_context *context, int record_num, const char **host,
		unsigned short *port, unsigned short *priority, unsigned short *weight);

/*!
 * \brief Retrieve details from the next SRV record
 * When doing a SRV record lookup, a list is saved in the context and
 * a pointer is set to the "current" record. This function moves the current
 * pointer to the next entry and returns the names from that entry.
 *
 * \param context The context returned by ast_srv_lookup
 * \param record_num The 1-indexed record number to retrieve
 * \param[out] host The host portion of the record
 * \param[out] port The port portion of the record
 * \param[out] priority The priority portion of the record
 * \param[out] weight The weight portion of the record
 * \retval -1 Failed to retrieve information. Likely due to the end of the list.
 * \retval 0 Success
 */
int ast_srv_get_next_record(struct srv_context *context, const char **host,
		unsigned short *port, unsigned short *priority, unsigned short *weight);

/*!
 * \brief Get the minimum TTL for all records in an SRV record set 
 */
struct timeval *ast_srv_get_min_ttl(struct srv_context *context);

/*!
 * \brief Check if a context is expired (DNS TTL exceeded)
 * \retval 0 (FALSE) The context is expired and needs to be updated
 * \retval 1 (TRUE)  The context is still valid
 */
int ast_srv_context_valid(struct srv_context *context);

/*!
 * \brief Print out the complete data in the SRV list
 */
void ast_srv_debug_print(struct srv_context *context);

#endif /* _ASTERISK_SRV_H */
