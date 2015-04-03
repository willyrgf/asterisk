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

#include "asterisk.h"

#include <pjsip.h>

#include <arpa/nameser.h>

#include "asterisk/astobj2.h"
#include "asterisk/dns_core.h"
#include "asterisk/dns_query_set.h"
#include "asterisk/dns_srv.h"
#include "asterisk/res_pjsip.h"
#include "include/res_pjsip_private.h"

/*! \brief Structure which contains resolved target information */
struct sip_resolved_target {
	/*! \brief The record type that this target originated from */
	/*! \brief The transport to be used */
	pjsip_transport_type_e transport;
	/*! \brief The port */
	int port;
	/*! \brief Resulting addresses */
	pjsip_server_addresses addresses;
};

/*! \brief The vector used for addresses */
AST_VECTOR(addresses, struct sip_resolved_target);

/*! \brief Structure which keeps track of resolution */
struct sip_resolve {
	/*! \brief Addresses currently being resolved, indexed based on index of queries in query set */
	struct addresses resolving;
	/*! \brief Addresses that have been resolved, to ensure proper sorting go from back to front */
	struct addresses resolved;
	/*! \brief Active queries */
	struct ast_dns_query_set *queries;
	/*! \brief Callback to invoke upon completion */
	ast_sip_resolve_callback callback;
	/*! \brief User provided data */
	void *user_data;
};

/*! \brief Destructor for resolution data */
static void sip_resolve_destroy(void *data)
{
	struct sip_resolve *resolve = data;

	AST_VECTOR_FREE(&resolve->resolving);
	AST_VECTOR_FREE(&resolve->resolved);
	ao2_cleanup(resolve->queries);
	ao2_cleanup(resolve->user_data);
}

/*! \brief Perform resolution but keep transport and port information */
static int sip_resolve_add(struct sip_resolve *resolve, const char *name, int rr_type, int rr_class, pjsip_transport_type_e transport, int port)
{
	struct sip_resolved_target target = {
		.transport = transport,
		.port = port,
	};

	if (!resolve->queries) {
		resolve->queries = ast_dns_query_set_create();
	}

	if (!resolve->queries) {
		return -1;
	}

	if (!port) {
		target.port = pjsip_transport_get_default_port_for_type(transport);
	}

	if (AST_VECTOR_APPEND(&resolve->resolving, target)) {
		return -1;
	}

	ast_debug(2, "[%p] Added target '%s' with record type '%d', transport '%s', and port '%d'\n", resolve, name, rr_type,
		pjsip_transport_get_type_name(transport), target.port);

	return ast_dns_query_set_add(resolve->queries, name, rr_type, rr_class);
}

/*! \brief Invoke the user specific callback from inside of a SIP thread */
static int sip_resolve_invoke_user_callback(void *data)
{
	struct sip_resolve *resolve = data;
	pjsip_server_addresses addresses = {
		.count = 0,
	};
	int idx;

	/* We start from the end because the records with the highest preference are there */
	for (idx = AST_VECTOR_SIZE(&resolve->resolved) - 1; idx >= 0; --idx) {
		struct sip_resolved_target *target = AST_VECTOR_GET_ADDR(&resolve->resolved, idx);
		int address_pos;
		char addr[256];

		for (address_pos = 0; address_pos < target->addresses.count; ++address_pos) {
			ast_debug(2, "[%p] Address '%d' is '%s' port '%d' with transport '%s'\n",
				resolve, addresses.count, pj_sockaddr_print(&target->addresses.entry[address_pos].addr, addr, sizeof(addr), 0),
				pj_sockaddr_get_port(&target->addresses.entry[address_pos].addr), pjsip_transport_get_type_name(target->addresses.entry[address_pos].type));
			addresses.entry[addresses.count++] = target->addresses.entry[address_pos];
		}

		if (addresses.count == PJSIP_MAX_RESOLVED_ADDRESSES) {
			break;
		}
	}

	ast_debug(2, "[%p] Invoking user callback with '%d' addresses\n", resolve, addresses.count);
	resolve->callback(resolve->user_data, &addresses);

	ao2_ref(resolve, -1);

	return 0;
}

/*! \brief Callback for when the first pass query set completes */
static void sip_resolve_callback(const struct ast_dns_query_set *query_set)
{
	struct sip_resolve *resolve = ast_dns_query_set_get_data(query_set);
	struct ast_dns_query_set *queries = resolve->queries;
	struct addresses resolving;
	int idx;

	ast_debug(2, "[%p] All parallel queries completed\n", resolve);

	resolve->queries = NULL;

	/* This purposely steals the resolving list so we can add entries to the new one in the same loop and also have access
	 * to the old.
	 */
	resolving = resolve->resolving;
	AST_VECTOR_INIT(&resolve->resolving, 1);

	/* Add any AAAA/A records to the resolved list */
	for (idx = 0; idx < ast_dns_query_set_num_queries(queries); ++idx) {
		struct ast_dns_query *query = ast_dns_query_set_get(queries, idx);
		struct ast_dns_result *result = ast_dns_query_get_result(query);
		struct sip_resolved_target *target;
		const struct ast_dns_record *record;

		if (!result) {
			ast_debug(2, "[%p] No result information for target '%s' of type '%d'\n", resolve,
				ast_dns_query_get_name(query), ast_dns_query_get_rr_type(query));
			continue;
		}

		target = AST_VECTOR_GET_ADDR(&resolving, idx);
		for (record = ast_dns_result_get_records(result); record; record = ast_dns_record_get_next(record)) {
			if (ast_dns_record_get_rr_type(record) == ns_t_a) {
				ast_debug(2, "[%p] A record received on target '%s'\n", resolve, ast_dns_query_get_name(query));
				target->addresses.entry[target->addresses.count].type = target->transport;
				target->addresses.entry[target->addresses.count].addr_len = sizeof(pj_sockaddr_in);
				pj_sockaddr_init(pj_AF_INET(), &target->addresses.entry[target->addresses.count].addr, NULL, target->port);
				target->addresses.entry[target->addresses.count++].addr.ipv4.sin_addr = *(struct pj_in_addr*)ast_dns_record_get_data(record);
			} else if (ast_dns_record_get_rr_type(record) == ns_t_aaaa) {
				ast_debug(2, "[%p] AAAA record received on target '%s'\n", resolve, ast_dns_query_get_name(query));
				target->addresses.entry[target->addresses.count].type = target->transport;
				target->addresses.entry[target->addresses.count].addr_len = sizeof(pj_sockaddr_in6);
				pj_sockaddr_init(pj_AF_INET6(), &target->addresses.entry[target->addresses.count].addr, NULL, target->port);
				pj_memcpy(&target->addresses.entry[target->addresses.count++].addr.ipv6.sin6_addr, ast_dns_record_get_data(record),
					sizeof(pj_sockaddr_in6));
			} else if (ast_dns_record_get_rr_type(record) == ns_t_srv) {
				ast_debug(2, "[%p] SRV record received on target '%s'\n", resolve, ast_dns_query_get_name(query));
				sip_resolve_add(resolve, ast_dns_srv_get_host(record), ns_t_a, ns_c_in, target->transport, ast_dns_srv_get_port(record));
				sip_resolve_add(resolve, ast_dns_srv_get_host(record), ns_t_aaaa, ns_c_in, target->transport, ast_dns_srv_get_port(record));
			}
		}

		/* Only add this finished result if there's actually addresses on it */
		if (target->addresses.count) {
			AST_VECTOR_APPEND(&resolve->resolved, *target);
		}
	}

	/* Free the vector we stole as we are responsible for it */
	AST_VECTOR_FREE(&resolving);

	/* If additional queries were added start the resolution process again */
	if (resolve->queries) {
		ast_debug(2, "[%p] New queries added, performing parallel resolution again\n", resolve);
		ast_dns_query_set_resolve_async(resolve->queries, sip_resolve_callback, resolve);
		ao2_ref(queries, -1);
		return;
	}

	/* Invoke callback with target resolved addresses */
	ast_debug(2, "[%p] Resolution completed - %zd viable targets\n", resolve, AST_VECTOR_SIZE(&resolve->resolved));

	/* Push a task to invoke the callback, we do this so it is guaranteed to run in a PJSIP thread */
	ao2_ref(resolve, +1);
	if (ast_sip_push_task(NULL, sip_resolve_invoke_user_callback, resolve)) {
		ao2_ref(resolve, -1);
	}

	ao2_ref(queries, -1);
}

/*! \brief Determine if the host is already an IP address */
static int sip_resolve_get_ip_addr_ver(const pj_str_t *host)
{
	pj_in_addr dummy;
	pj_in6_addr dummy6;

	if (pj_inet_aton(host, &dummy) > 0) {
		return 4;
	}

	if (pj_inet_pton(pj_AF_INET6(), host, &dummy6) == PJ_SUCCESS) {
		return 6;
	}

	return 0;
}

int ast_sip_resolve(const pjsip_host_info *target, ast_sip_resolve_callback callback, void *user_data)
{
	int ip_addr_ver;
	pjsip_transport_type_e type = target->type;
	struct sip_resolve *resolve;
	char host[NI_MAXHOST], srv[NI_MAXHOST];
	int res = 0;

	ast_copy_pj_str(host, &target->addr.host, sizeof(host));

	ast_debug(2, "Performing SIP DNS resolution of target '%s'\n", host);

	/* If the provided target is already an address don't bother resolving */
	ip_addr_ver = sip_resolve_get_ip_addr_ver(&target->addr.host);

	/* Determine the transport to use if none has been explicitly specified */
	if (type == PJSIP_TRANSPORT_UNSPECIFIED) {
		/* If we've been told to use a secure or reliable transport restrict ourselves to that */
#if PJ_HAS_TCP
		if (target->flag & PJSIP_TRANSPORT_SECURE) {
			type = PJSIP_TRANSPORT_TLS;
		} else if (target->flag & PJSIP_TRANSPORT_RELIABLE) {
			type = PJSIP_TRANSPORT_TCP;
		} else
#endif
		/* According to the RFC otherwise if an explicit IP address OR an explicit port is specified
		 * we use UDP
		 */
		if (ip_addr_ver || target->addr.port) {
			type = PJSIP_TRANSPORT_UDP;
		}
	}

	ast_debug(2, "Transport type for target '%s' is '%s'\n", host, pjsip_transport_get_type_name(type));

	/* If it's already an address call the callback immediately */
	if (ip_addr_ver) {
		pjsip_server_addresses addresses;

		if (ip_addr_ver == 4) {
			pj_sockaddr_init(pj_AF_INET(), &addresses.entry[0].addr, NULL, 0);
			pj_inet_aton(&target->addr.host, &addresses.entry[0].addr.ipv4.sin_addr);
		} else {
			pj_sockaddr_init(pj_AF_INET6(), &addresses.entry[0].addr, NULL, 0);
			pj_inet_pton(pj_AF_INET6(), &target->addr.host, &addresses.entry[0].addr.ipv6.sin6_addr);
			type = (pjsip_transport_type_e)((int)type + PJSIP_TRANSPORT_IPV6);
		}
		addresses.count++;

		ast_debug(2, "Target '%s' is an IP address, skipping resolution\n", host);

		callback(user_data, &addresses);

		return 0;
	}

	resolve = ao2_alloc_options(sizeof(*resolve), sip_resolve_destroy, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!resolve) {
		return -1;
	}

	resolve->callback = callback;
	resolve->user_data = ao2_bump(user_data);

	if (AST_VECTOR_INIT(&resolve->resolving, 2) || AST_VECTOR_INIT(&resolve->resolved, 2)) {
		ao2_ref(resolve, -1);
		return -1;
	}

	ast_debug(2, "[%p] Created resolution tracking for target '%s'\n", resolve, host);

	res |= sip_resolve_add(resolve, host, ns_t_a, ns_c_in, (type == PJSIP_TRANSPORT_UNSPECIFIED ? PJSIP_TRANSPORT_UDP : type), target->addr.port);
	res |= sip_resolve_add(resolve, host, ns_t_aaaa, ns_c_in, (type == PJSIP_TRANSPORT_UNSPECIFIED ? PJSIP_TRANSPORT_UDP : type), target->addr.port);

	/* If no port has been specified we can do NAPTR + SRV */
	if (!target->addr.port) {
		if (type == PJSIP_TRANSPORT_UDP || type == PJSIP_TRANSPORT_UNSPECIFIED) {
			snprintf(srv, sizeof(srv), "_sip._udp.%s", host);
			res |= sip_resolve_add(resolve, srv, ns_t_srv, ns_c_in, PJSIP_TRANSPORT_UDP, 0);
		}
		if (type == PJSIP_TRANSPORT_TCP || type == PJSIP_TRANSPORT_UNSPECIFIED) {
			snprintf(srv, sizeof(srv), "_sip._tcp.%s", host);
			res |= sip_resolve_add(resolve, srv, ns_t_srv, ns_c_in, PJSIP_TRANSPORT_TCP, 0);
		}
		if (type == PJSIP_TRANSPORT_TLS || type == PJSIP_TRANSPORT_UNSPECIFIED) {
			snprintf(srv, sizeof(srv), "_sips._tcp.%s", host);
			res |= sip_resolve_add(resolve, srv, ns_t_srv, ns_c_in, PJSIP_TRANSPORT_TLS, 0);
		}
	}

	if (res) {
		ao2_ref(resolve, -1);
		return -1;
	}

	ast_debug(2, "[%p] Starting initial resolution using parallel queries for target '%s'\n", resolve, host);
	ast_dns_query_set_resolve_async(resolve->queries, sip_resolve_callback, resolve);

	ao2_ref(resolve, -1);

	return 0;
}