/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 * and Edvina AB, Sollentuna, Sweden (chan_sip3 changes/additions)
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

/*!
 * \file
 * \brief Various SIP object handling functions
 *	(phones, trunks, services)
 * Version 3 of chan_sip
 *
 * \author Mark Spencer <markster@digium.com>
 * \author Olle E. Johansson <oej@edvina.net> (all the chan_sip3 changes)
 *
 * See Also:
 * \arg \ref AstCREDITS
 *
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <regex.h>

#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/options.h"
#include "asterisk/sched.h"
#include "asterisk/io.h"
#include "asterisk/rtp.h"
#include "asterisk/udptl.h"
#include "asterisk/acl.h"
#include "asterisk/manager.h"
#include "asterisk/callerid.h"
#include "asterisk/cli.h"
#include "asterisk/app.h"
#include "asterisk/musiconhold.h"
#include "asterisk/dsp.h"
#include "asterisk/features.h"
#include "asterisk/srv.h"
#include "asterisk/astdb.h"
#include "asterisk/causes.h"
#include "asterisk/utils.h"
#include "asterisk/file.h"
#include "asterisk/astobj.h"
#include "asterisk/dnsmgr.h"
#include "asterisk/devicestate.h"
#include "asterisk/linkedlists.h"
#include "asterisk/stringfields.h"
#include "asterisk/monitor.h"
#include "asterisk/localtime.h"
#include "asterisk/abstract_jb.h"
#include "asterisk/compiler.h"
#include "sip3.h"
#include "sip3funcs.h"


struct sip_device_list devicelist;           /*!< The device list */

/*! \brief Support routine for find_device */
static int sip_addrcmp(char *name, struct sockaddr_in *sin)
{
	/* We know name is the first field, so we can cast */
	struct sip_device *peer = (struct sip_device *) name;
	return 	!(!inaddrcmp(&peer->addr, sin) || 
					(ast_test_flag(&peer->flags[0], SIP_INSECURE_PORT) &&
					(peer->addr.sin_addr.s_addr == sin->sin_addr.s_addr)));
}


/*! \brief Update peer object in realtime storage 
	If the Asterisk system name is set in asterisk.conf, we will use
	that name and store that in the "regserver" field in the sippeers
	table to facilitate multi-server setups.
*/
GNURK void realtime_update_peer(const char *peername, struct sockaddr_in *sin, const char *username, const char *fullcontact, int expiry)
{
	char port[10];
	char ipaddr[INET_ADDRSTRLEN];
	char regseconds[20];

	char *sysname = ast_config_AST_SYSTEM_NAME;
	char *syslabel = NULL;

	time_t nowtime = time(NULL) + expiry;
	const char *fc = fullcontact ? "fullcontact" : NULL;
	
	snprintf(regseconds, sizeof(regseconds), "%d", (int)nowtime);	/* Expiration time */
	ast_copy_string(ipaddr, ast_inet_ntoa(sin->sin_addr), sizeof(ipaddr));
	snprintf(port, sizeof(port), "%d", ntohs(sin->sin_port));
	
	if (ast_strlen_zero(sysname))	/* No system name, disable this */
		sysname = NULL;
	else if (ast_test_flag(&global.flags[1], SIP_PAGE2_RTSAVE_SYSNAME))
		syslabel = "regserver";

	if (fc)
		ast_update_realtime("sippeers", "name", peername, "ipaddr", ipaddr,
			"port", port, "regseconds", regseconds,
			"defaultuser", username, fc, fullcontact, syslabel, sysname, NULL); /* note fc and syslabel _can_ be NULL */
	else
		ast_update_realtime("sippeers", "name", peername, "ipaddr", ipaddr,
			"port", port, "regseconds", regseconds,
			"defaultuser", username, syslabel, sysname, NULL); /* note syslabel _can_ be NULL */
}

/*! \brief Automatically add peer extension to dial plan */
GNURK void register_peer_exten(struct sip_device *device, int onoff)
{
	char multi[256];
	char *stringp, *ext, *context;

	/* XXX note that global.regcontext is both a global 'enable' flag and
	 * the name of the global regexten context, if not specified
	 * individually.
	 */
	if (ast_strlen_zero(global.regcontext))
		return;

	ast_copy_string(multi, S_OR(device->extra.regexten, device->name), sizeof(multi));
	stringp = multi;
	while ((ext = strsep(&stringp, "&"))) {
		if ((context = strchr(ext, '@'))) {
			*context++ = '\0';	/* split ext@context */
			if (!ast_context_find(context)) {
				ast_log(LOG_WARNING, "Context %s must exist in regcontext= in sip.conf!\n", context);
				continue;
			}
		} else {
			context = global.regcontext;
		}
		if (onoff)
			ast_add_extension(context, 1, ext, 1, NULL, NULL, "Noop",
				 ast_strdup(device->name), ast_free, "SIP");
		else
			ast_context_remove_extension(context, ext, 1, NULL);
	}
}

/*! \brief Destroy device object from memory */
GNURK void sip_destroy_device(struct sip_device *device)
{
	logdebug(3, "Destroying SIP device %s\n", device->name);
	//if (option_debug > 2)
		//ast_log(LOG_DEBUG, "Destroying SIP %s %s\n", device->type & SIP_USER ? "user" : "peer", device->name);

	/* Delete it, it needs to disappear */
	if (device->call)
		sip_destroy(device->call);
	if (device->chanvars) {
		ast_variables_destroy(device->chanvars);
		device->chanvars = NULL;
	}

	if (device->mailbox.mwipvt) 		/* We have an active subscription, delete it */
		sip_destroy(device->mailbox.mwipvt);

	if (device->expire > -1)
		ast_sched_del(sched, device->expire);
	if (device->pokeexpire > -1)
		ast_sched_del(sched, device->pokeexpire);
	ast_free_ha(device->ha);

	if (device->type & SIP_PEER) {
		register_peer_exten(device, FALSE);
		clear_realm_authentication(device->auth);
		device->auth = (struct sip_auth *) NULL;
		if (ast_test_flag((&device->flags[1]), SIP_PAGE2_SELFDESTRUCT))
			sipcounters.autocreated_peers--;
		else if (ast_test_flag(&device->flags[0], SIP_REALTIME))
			sipcounters.realtime_peers--;
		else
			sipcounters.static_peers--;
	} 
	if (device->type & SIP_USER) {	/* SIP_USER */
		if (ast_test_flag(&device->flags[0], SIP_REALTIME))
			sipcounters.realtime_users--;
		else
			sipcounters.static_users--;
	}
	if (device->dnsmgr)
		ast_dnsmgr_release(device->dnsmgr);
	if (device->registry) {
		device->registry->peer = NULL;
		ASTOBJ_UNREF(device->registry,sip_registry_destroy);
	}

	/* Free the stringfield pool */
	ast_string_field_free_pools(device);
	free(device);
}

/*! \brief Update peer data in database (if used) */
GNURK void update_peer(struct sip_device *device, int expiry)
{
	int rtcachefriends = ast_test_flag(&device->flags[1], SIP_PAGE2_RTCACHEFRIENDS);
	if (ast_test_flag(&global.flags[1], SIP_PAGE2_RTUPDATE) &&
	    (ast_test_flag(&device->flags[0], SIP_REALTIME) || rtcachefriends)) {
		realtime_update_peer(device->name, &device->addr, device->defaultuser, rtcachefriends ? device->fullcontact : NULL, expiry);
	}
}

/*! \brief Locate peer by name or ip address 
 *	This is used on incoming SIP message to find matching peer on ip
	or outgoing message to find matching peer on name */
GNURK struct sip_device *find_device(const char *device, struct sockaddr_in *sin, int realtime)
{
	struct sip_device *peer = NULL;

	if (device)
		peer = ASTOBJ_CONTAINER_FIND(&devicelist, device);
	else
		peer = ASTOBJ_CONTAINER_FIND_FULL(&devicelist, sin, name, sip_addr_hashfunc, 1, sip_addrcmp);

	if (!peer && realtime)
		peer = realtime_peer(device, sin);

	return peer;
}

/*! \brief Create temporary peer (used in autocreatepeer mode) */
GNURK struct sip_device *temp_device(const char *name)
{
	struct sip_device *peer;

	if (!(peer = ast_calloc(1, sizeof(*peer))))
		return NULL;

	sipcounters.autocreated_peers++;
	ASTOBJ_INIT(peer);
	peer->type = SIP_PEER;
	set_device_defaults(peer);

	ast_copy_string(peer->name, name, sizeof(peer->name));

	ast_set_flag(&peer->flags[1], SIP_PAGE2_SELFDESTRUCT);
	ast_set_flag(&peer->flags[1], SIP_PAGE2_DYNAMIC);
	peer->prefs = global.default_prefs;
	sip_reg_source_db(peer);

	return peer;
}

/*! \brief Get registration details from Asterisk DB 
	\ref chan_sip3_registrydb
*/
GNURK void sip_reg_source_db(struct sip_device *peer)
{
	/*! \page chan_sip3_registrydb SIP3 :: THe registry database (astdb)
		The SIP3 registry database contains a string that contains
		fields separated by | characters. When a device registers,
		the string is stored to the database in order to allow
		restarts of Asterisk without loosing data.
		When Asterisk restarts, the SIP channel loads data from 
		the ASTDB "sip3-registry" family in order to populate
		the peer list with registered peers.

		\b Fields:

		- \b Expirytime: The time (unix time) when this registration expires
		- \b IP address: Registered IP address or NAT address
		- \b Port: Registered port our NAT port
		- \b Expiry: How long this registration is valid
		- \b Contact: The Contact header registered with Asterisk

		\b Functions:
	
		- \ref sip_reg_source_db()

		A problem with this is that if Asterisk has not been running for more
		than 30 secs, we might not be able to keep NAT relations alive and will
		send out keepalives that will be refused by the NAT. The device will
		quickly become UNREACHABLE until we get a new registration from the inside.
	*/

	char data[BUFSIZ * 4];
	struct in_addr in;
	int expiry;
	int port;
	time_t exptime;
	char *scan, *expirytime, *addr, *port_str, *expiry_str, *contact;

	if (ast_test_flag(&peer->flags[1], SIP_PAGE2_RT_FROMCONTACT)) 	/*! \bug XXX What is this???? */
		return;
	if (ast_db_get("SIP3-Registry", peer->name, data, sizeof(data)))
		return;

	scan = data;
	expirytime = strsep(&scan, "|");
	addr = strsep(&scan, "|");
	port_str = strsep(&scan, "|");
	expiry_str = strsep(&scan, "|");
	contact = scan;	/* Contact include sip: and has to be the last part of the database entry as long as we use : as a separator */

	exptime = (time_t) atoi(expirytime);
	if (exptime < time(NULL)) {
		/* This peer as expired, registration no longer valid */
		if (option_debug > 1 && sipdebug)
			ast_log(LOG_DEBUG, "Peer %s has expired. Deleting entry in astdb\n", peer->name);
		ast_db_del("SIP3-Registry", peer->name);
		return;
	}
	if (!inet_aton(addr, &in))
		return;

	if (port_str)
		port = atoi(port_str);
	else
		return;

	if (expiry_str)
		expiry = atoi(expiry_str);
	else
		return;

	if (contact)
		ast_string_field_set(peer, fullcontact, contact);

	if (option_verbose > 2)
		ast_verbose(VERBOSE_PREFIX_3 "SIP Loaded device from astdb: '%s' at %s:%d for %d\n",
			    peer->name, ast_inet_ntoa(in), port, expiry);

	memset(&peer->addr, 0, sizeof(peer->addr));
	peer->addr.sin_family = AF_INET;
	peer->addr.sin_addr = in;
	peer->addr.sin_port = htons(port);

	/* Schedule a poke only, pretty soon */
	if (peer->pokeexpire > -1)
		ast_sched_del(sched, peer->pokeexpire);
	peer->pokeexpire = ast_sched_add(sched, ast_random() % 5000 + 1, sip_poke_peer_s, peer);

	if (peer->expire > -1)
		ast_sched_del(sched, peer->expire);
	

	//peer->expire = ast_sched_add(sched, (expiry + 10) * 1000, expire_register, peer);
	peer->expire = ast_sched_add(sched, (exptime + 10 - time(NULL)) * 1000, expire_register, peer);

	register_peer_exten(peer, TRUE);
}

/*! \brief Remove registration data from realtime database or AST/DB when registration expires */
GNURK void destroy_association(struct sip_device *device)
{
	if (!ast_test_flag(&global.flags[1], SIP_PAGE2_IGNOREREGEXPIRE)) {
		if (ast_test_flag(&device->flags[1], SIP_PAGE2_RT_FROMCONTACT))
			ast_update_realtime("sippeers", "name", device->name, "fullcontact", "", "ipaddr", "", "port", "", "regseconds", "0", "defaultuser", "", "regserver", "", NULL);
		else 
			ast_db_del("SIP3-Registry", device->name);
	}
}

/*! \brief Expire registration of SIP device */
GNURK int expire_register(void *data)
{
	struct sip_device *device = data;
	
	if (!device)		/* Hmmm. We have no peer. Weird. */
		return 0;

	memset(&device->addr, 0, sizeof(device->addr));

	destroy_association(device);	/* remove registration data from storage */
	
	manager_event(EVENT_FLAG_SYSTEM, "PeerStatus", "Peer: SIP/%s\r\nPeerStatus: Unregistered\r\nCause: Expired\r\n", device->name);
	register_peer_exten(device, FALSE);	/* Remove regexten */
	device->expire = -1;
	ast_device_state_changed("SIP/%s", device->name);

	/* Do we need to release this peer from memory? 
		Only for realtime peers and autocreated peers
	*/
	if (ast_test_flag(&device->flags[1], SIP_PAGE2_SELFDESTRUCT) ||
	    ast_test_flag(&device->flags[1], SIP_PAGE2_RTAUTOCLEAR)) {
		device = ASTOBJ_CONTAINER_UNLINK(&devicelist, device);	/* Remove from peer list */
		device_unref(device);
	}

	return 0;
}
