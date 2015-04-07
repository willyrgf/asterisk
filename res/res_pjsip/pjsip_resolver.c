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
#include "asterisk/dns_naptr.h"
#include "asterisk/res_pjsip.h"
#include "include/res_pjsip_private.h"

/*! \brief Structure which contains transport+port information for an active query */
struct sip_target {
	/*! \brief The transport to be used */
	pjsip_transport_type_e transport;
	/*! \brief The port */
	int port;
};

/*! \brief The vector used for current targets */
AST_VECTOR(targets, struct sip_target);

/*! \brief Structure which keeps track of resolution */
struct sip_resolve {
	/*! \brief Addresses currently being resolved, indexed based on index of queries in query set */
	struct targets resolving;
	/*! \brief Active queries */
	struct ast_dns_query_set *queries;
	/*! \brief Current viable server addresses */
	pjsip_server_addresses addresses;
	/*! \brief Callback to invoke upon completion */
	pjsip_resolver_callback *callback;
	/*! \brief User provided data */
	void *token;
};

/*! \brief Available transports on the system */
static int sip_available_transports[] = {
	/* This is a list of transports understood by the resolver, with whether they are
	 * available as a valid transport stored
	 */
	[PJSIP_TRANSPORT_UDP] = 0,
	[PJSIP_TRANSPORT_TCP] = 0,
	[PJSIP_TRANSPORT_TLS] = 0,
	[PJSIP_TRANSPORT_UDP6] = 0,
	[PJSIP_TRANSPORT_TCP6] = 0,
	[PJSIP_TRANSPORT_TLS6] = 0,
};

/*! \brief Destructor for resolution data */
static void sip_resolve_destroy(void *data)
{
	struct sip_resolve *resolve = data;

	AST_VECTOR_FREE(&resolve->resolving);
	ao2_cleanup(resolve->queries);
}

/*! \brief Perform resolution but keep transport and port information */
static int sip_resolve_add(struct sip_resolve *resolve, const char *name, int rr_type, int rr_class, pjsip_transport_type_e transport, int port)
{
	struct sip_target target = {
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
	int idx;

	for (idx = 0; idx < resolve->addresses.count; ++idx) {
		char addr[PJ_INET6_ADDRSTRLEN + 10];

		ast_debug(2, "[%p] Address '%d' is %s with transport '%s'\n",
			resolve, idx, pj_sockaddr_print(&resolve->addresses.entry[idx].addr, addr, sizeof(addr), 3),
			pjsip_transport_get_type_name(resolve->addresses.entry[idx].type));
	}

	ast_debug(2, "[%p] Invoking user callback with '%d' addresses\n", resolve, resolve->addresses.count);
	resolve->callback(PJ_SUCCESS, resolve->token, &resolve->addresses);

	ao2_ref(resolve, -1);

	return 0;
}

/*! \brief Callback for when the first pass query set completes */
static void sip_resolve_callback(const struct ast_dns_query_set *query_set)
{
	struct sip_resolve *resolve = ast_dns_query_set_get_data(query_set);
	struct ast_dns_query_set *queries = resolve->queries;
	struct targets resolving;
	int idx, address_count = 0;

	ast_debug(2, "[%p] All parallel queries completed\n", resolve);

	resolve->queries = NULL;

	/* This purposely steals the resolving list so we can add entries to the new one in the same loop and also have access
	 * to the old.
	 */
	resolving = resolve->resolving;
	AST_VECTOR_INIT(&resolve->resolving, 0);

	/* The order of queries is what defines the preference order for the records within this invocation.
	 * The preference order overall is defined as a result of drilling down from other records. Each
	 * invocation starts placing records at the beginning, moving others that may have already been present.
	 */
	for (idx = 0; idx < ast_dns_query_set_num_queries(queries); ++idx) {
		struct ast_dns_query *query = ast_dns_query_set_get(queries, idx);
		struct ast_dns_result *result = ast_dns_query_get_result(query);
		struct sip_target *target;
		const struct ast_dns_record *record;

		if (!result) {
			ast_debug(2, "[%p] No result information for target '%s' of type '%d'\n", resolve,
				ast_dns_query_get_name(query), ast_dns_query_get_rr_type(query));
			continue;
		}

		target = AST_VECTOR_GET_ADDR(&resolving, idx);
		for (record = ast_dns_result_get_records(result); record; record = ast_dns_record_get_next(record)) {

			if (ast_dns_record_get_rr_type(record) == ns_t_a ||
				ast_dns_record_get_rr_type(record) == ns_t_aaaa) {

				/* If the maximum number of addresses has already been reached by this query set, skip subsequent
				 * records as they have lower preference - any existing ones may get replaced/moved if another
				 * invocation occurs after this one
				 */
				if (address_count == PJSIP_MAX_RESOLVED_ADDRESSES) {
					continue;
				}

				/* Move any existing addresses so we can make room for this record, this may hurt your head slightly but
				 * essentially it figures out the maximum number of previous addresses that can exist and caps the
				 * the memmove operation to that
				 */
				memmove(&resolve->addresses.entry[address_count + 1], &resolve->addresses.entry[address_count],
					sizeof(resolve->addresses.entry[0]) *
					MIN(resolve->addresses.count, PJSIP_MAX_RESOLVED_ADDRESSES - address_count - 1));

				resolve->addresses.entry[address_count].type = target->transport;

				/* Populate address information for the new address entry */
				if (ast_dns_record_get_rr_type(record) == ns_t_a) {
					ast_debug(2, "[%p] A record received on target '%s'\n", resolve, ast_dns_query_get_name(query));
					resolve->addresses.entry[address_count].addr_len = sizeof(pj_sockaddr_in);
					pj_sockaddr_init(pj_AF_INET(), &resolve->addresses.entry[address_count].addr, NULL,
						target->port);
					resolve->addresses.entry[address_count].addr.ipv4.sin_addr = *(struct pj_in_addr*)ast_dns_record_get_data(record);
				} else {
					ast_debug(2, "[%p] AAAA record received on target '%s'\n", resolve, ast_dns_query_get_name(query));
					resolve->addresses.entry[address_count].addr_len = sizeof(pj_sockaddr_in6);
					pj_sockaddr_init(pj_AF_INET6(), &resolve->addresses.entry[address_count].addr, NULL,
						target->port);
					pj_memcpy(&resolve->addresses.entry[address_count].addr.ipv6.sin6_addr, ast_dns_record_get_data(record),
						ast_dns_record_get_data_size(record));
				}

				address_count++;
			} else if (ast_dns_record_get_rr_type(record) == ns_t_srv) {
				/* SRV records just create new queries for AAAA+A, nothing fancy */
				ast_debug(2, "[%p] SRV record received on target '%s'\n", resolve, ast_dns_query_get_name(query));

				if (sip_available_transports[target->transport + PJSIP_TRANSPORT_IPV6]) {
					sip_resolve_add(resolve, ast_dns_srv_get_host(record), ns_t_aaaa, ns_c_in, target->transport + PJSIP_TRANSPORT_IPV6,
						ast_dns_srv_get_port(record));
				}

				if (sip_available_transports[target->transport]) {
					sip_resolve_add(resolve, ast_dns_srv_get_host(record), ns_t_a, ns_c_in, target->transport,
						ast_dns_srv_get_port(record));
				}
			} else if (ast_dns_record_get_rr_type(record) == ns_t_naptr) {
				ast_debug(2, "[%p] NAPTR record received on target '%s'\n", resolve, ast_dns_query_get_name(query));

				if (!strcasecmp(ast_dns_naptr_get_service(record), "sip+d2u") &&
					(sip_available_transports[PJSIP_TRANSPORT_UDP] || sip_available_transports[PJSIP_TRANSPORT_UDP6])) {
					if (!strcasecmp(ast_dns_naptr_get_flags(record), "s")) {
						sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_srv, ns_c_in,
							PJSIP_TRANSPORT_UDP, 0);
					} else if (!strcasecmp(ast_dns_naptr_get_flags(record), "a")) {
						if (sip_available_transports[PJSIP_TRANSPORT_UDP6]) {
							sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_aaaa, ns_c_in,
								PJSIP_TRANSPORT_UDP6, 0);
						}
						if (sip_available_transports[PJSIP_TRANSPORT_UDP]) {
							sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_a, ns_c_in,
								PJSIP_TRANSPORT_UDP, 0);
						}
					} else {
						ast_debug(2, "[%p] NAPTR service SIP+D2U received with unsupported flags '%s'\n",
							resolve, ast_dns_naptr_get_flags(record));
					}
				} else if (!strcasecmp(ast_dns_naptr_get_service(record), "sip+d2t") &&
					(sip_available_transports[PJSIP_TRANSPORT_TCP] || sip_available_transports[PJSIP_TRANSPORT_TCP6])) {
					if (!strcasecmp(ast_dns_naptr_get_flags(record), "s")) {
						sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_srv, ns_c_in, PJSIP_TRANSPORT_TCP,
							0);
					} else if (!strcasecmp(ast_dns_naptr_get_flags(record), "a")) {
						if (sip_available_transports[PJSIP_TRANSPORT_TCP6]) {
							sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_aaaa, ns_c_in,
								PJSIP_TRANSPORT_TCP6, 0);
						}
						if (sip_available_transports[PJSIP_TRANSPORT_TCP]) {
							sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_a, ns_c_in,
								PJSIP_TRANSPORT_TCP, 0);
						}
					} else {
						ast_debug(2, "[%p] NAPTR service SIP+D2T received with unsupported flags '%s'\n",
							resolve, ast_dns_naptr_get_flags(record));
					}
				} else if (!strcasecmp(ast_dns_naptr_get_service(record), "sips+d2t") &&
					(sip_available_transports[PJSIP_TRANSPORT_TLS] || sip_available_transports[PJSIP_TRANSPORT_TLS6])) {
					if (!strcasecmp(ast_dns_naptr_get_flags(record), "s")) {
						sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_srv, ns_c_in, PJSIP_TRANSPORT_TLS,
							0);
					} else if (!strcasecmp(ast_dns_naptr_get_flags(record), "a")) {
						if (sip_available_transports[PJSIP_TRANSPORT_TLS6]) {
							sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_aaaa, ns_c_in,
								PJSIP_TRANSPORT_TLS6, 0);
						}
						if (sip_available_transports[PJSIP_TRANSPORT_TLS]) {
							sip_resolve_add(resolve, ast_dns_naptr_get_replacement(record), ns_t_a, ns_c_in,
								PJSIP_TRANSPORT_TLS, 0);
						}
					} else {
						ast_debug(2, "[%p] NAPTR service SIPS+D2T received with unsupported flags '%s'\n",
							resolve, ast_dns_naptr_get_flags(record));
					}
				}
			}
		}
	}

	/* Update the server addresses to include any new entries, but since it's limited to the maximum resolved
	 * it must never exceed that
	 */
	resolve->addresses.count = MIN(resolve->addresses.count + address_count, PJSIP_MAX_RESOLVED_ADDRESSES);

	/* Free the vector we stole as we are responsible for it */
	AST_VECTOR_FREE(&resolving);

	/* If additional queries were added start the resolution process again */
	if (resolve->queries) {
		ast_debug(2, "[%p] New queries added, performing parallel resolution again\n", resolve);
		ast_dns_query_set_resolve_async(resolve->queries, sip_resolve_callback, resolve);
		ao2_ref(queries, -1);
		return;
	}

	ast_debug(2, "[%p] Resolution completed - %d viable targets\n", resolve, resolve->addresses.count);

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

static void sip_resolve(pjsip_resolver_t *resolver, pj_pool_t *pool, const pjsip_host_info *target,
	void *token, pjsip_resolver_callback *cb)
{
	int ip_addr_ver;
	pjsip_transport_type_e type = target->type;
	struct sip_resolve *resolve;
	char host[NI_MAXHOST];
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
		pjsip_server_addresses addresses = {
			.entry[0].type = type,
			.count = 1,
		};

		if (ip_addr_ver == 4) {
			addresses.entry[0].addr_len = sizeof(pj_sockaddr_in);
			pj_sockaddr_init(pj_AF_INET(), &addresses.entry[0].addr, NULL, 0);
			pj_inet_aton(&target->addr.host, &addresses.entry[0].addr.ipv4.sin_addr);
		} else {
			addresses.entry[0].addr_len = sizeof(pj_sockaddr_in6);
			pj_sockaddr_init(pj_AF_INET6(), &addresses.entry[0].addr, NULL, 0);
			pj_inet_pton(pj_AF_INET6(), &target->addr.host, &addresses.entry[0].addr.ipv6.sin6_addr);
			addresses.entry[0].type = (pjsip_transport_type_e)((int)addresses.entry[0].type + PJSIP_TRANSPORT_IPV6);
		}

		pj_sockaddr_set_port(&addresses.entry[0].addr, !target->addr.port ? pjsip_transport_get_default_port_for_type(type) : target->addr.port);

		ast_debug(2, "Target '%s' is an IP address, skipping resolution\n", host);

		cb(PJ_SUCCESS, token, &addresses);

		return;
	}

	resolve = ao2_alloc_options(sizeof(*resolve), sip_resolve_destroy, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!resolve) {
		cb(PJ_EINVAL, token, NULL);
		return;
	}

	resolve->callback = cb;
	resolve->token = token;

	if (AST_VECTOR_INIT(&resolve->resolving, 2)) {
		ao2_ref(resolve, -1);
		cb(PJ_EINVAL, token, NULL);
		return;
	}

	ast_debug(2, "[%p] Created resolution tracking for target '%s'\n", resolve, host);

	/* If no port has been specified we can do NAPTR + SRV */
	if (!target->addr.port) {
		char srv[NI_MAXHOST];

		res |= sip_resolve_add(resolve, host, ns_t_naptr, ns_c_in, type, 0);

		if ((type == PJSIP_TRANSPORT_TLS || type == PJSIP_TRANSPORT_UNSPECIFIED) &&
			(sip_available_transports[PJSIP_TRANSPORT_TLS] || sip_available_transports[PJSIP_TRANSPORT_TLS6])) {
			snprintf(srv, sizeof(srv), "_sips._tcp.%s", host);
			res |= sip_resolve_add(resolve, srv, ns_t_srv, ns_c_in, PJSIP_TRANSPORT_TLS, 0);
		}
		if ((type == PJSIP_TRANSPORT_TCP || type == PJSIP_TRANSPORT_UNSPECIFIED) &&
			(sip_available_transports[PJSIP_TRANSPORT_TCP] || sip_available_transports[PJSIP_TRANSPORT_TCP6])) {
			snprintf(srv, sizeof(srv), "_sip._tcp.%s", host);
			res |= sip_resolve_add(resolve, srv, ns_t_srv, ns_c_in, PJSIP_TRANSPORT_TCP, 0);
		}
		if ((type == PJSIP_TRANSPORT_UDP || type == PJSIP_TRANSPORT_UNSPECIFIED) &&
			(sip_available_transports[PJSIP_TRANSPORT_UDP] || sip_available_transports[PJSIP_TRANSPORT_UDP6])) {
			snprintf(srv, sizeof(srv), "_sip._udp.%s", host);
			res |= sip_resolve_add(resolve, srv, ns_t_srv, ns_c_in, PJSIP_TRANSPORT_UDP, 0);
		}
	}

	if (sip_available_transports[PJSIP_TRANSPORT_UDP6]) {
		res |= sip_resolve_add(resolve, host, ns_t_aaaa, ns_c_in, (type == PJSIP_TRANSPORT_UNSPECIFIED ? PJSIP_TRANSPORT_UDP6 : type), target->addr.port);
	}

	if (sip_available_transports[PJSIP_TRANSPORT_UDP]) {
		res |= sip_resolve_add(resolve, host, ns_t_a, ns_c_in, (type == PJSIP_TRANSPORT_UNSPECIFIED ? PJSIP_TRANSPORT_UDP : type), target->addr.port);
	}

	if (res) {
		ao2_ref(resolve, -1);
		cb(PJ_EINVAL, token, NULL);
		return;
	}

	ast_debug(2, "[%p] Starting initial resolution using parallel queries for target '%s'\n", resolve, host);
	ast_dns_query_set_resolve_async(resolve->queries, sip_resolve_callback, resolve);

	ao2_ref(resolve, -1);
}

/*! \brief Internal function used to determine if a transport is available */
static void sip_check_transport(pj_pool_t *pool, pjsip_transport_type_e type, const char *name)
{
	pjsip_tpmgr_fla2_param prm;

	pjsip_tpmgr_fla2_param_default(&prm);
	prm.tp_type = type;

	if (pjsip_tpmgr_find_local_addr2(pjsip_endpt_get_tpmgr(ast_sip_get_pjsip_endpoint()),
		pool, &prm) == PJ_SUCCESS) {
		ast_verb(2, "'%s' is an available SIP transport\n", name);
		sip_available_transports[type] = 1;
	} else {
		ast_verb(2, "'%s' is not an available SIP transport, disabling resolver support for it\n",
			name);
	}
}

static int sip_replace_resolver(void *data)
{
	pj_pool_t *pool;


	pool = pjsip_endpt_create_pool(ast_sip_get_pjsip_endpoint(), "Transport Availability", 256, 256);
	if (!pool) {
		return -1;
	}

	/* Determine what transports are available on the system */
	sip_check_transport(pool, PJSIP_TRANSPORT_UDP, "UDP+IPv4");
	sip_check_transport(pool, PJSIP_TRANSPORT_TCP, "TCP+IPv4");
	sip_check_transport(pool, PJSIP_TRANSPORT_TLS, "TLS+IPv4");
	sip_check_transport(pool, PJSIP_TRANSPORT_UDP6, "UDP+IPv6");
	sip_check_transport(pool, PJSIP_TRANSPORT_TCP6, "TCP+IPv6");
	sip_check_transport(pool, PJSIP_TRANSPORT_TLS6, "TLS+IPv6");

	pjsip_endpt_release_pool(ast_sip_get_pjsip_endpoint(), pool);

	/* Replace the PJSIP resolver with our own implementation */
	pjsip_endpt_set_resolver_implementation(ast_sip_get_pjsip_endpoint(), sip_resolve);
	return 0;
}

void ast_sip_initialize_resolver(void)
{
	/* Replace the existing PJSIP resolver with our own implementation */
	ast_sip_push_task_synchronous(NULL, sip_replace_resolver, NULL);
}