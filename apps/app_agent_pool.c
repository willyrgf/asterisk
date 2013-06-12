/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013 Digium, Inc.
 *
 * Richard Mudgett <rmudgett@digium.com>
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
 * \brief Call center agent pool.
 *
 * \author Richard Mudgett <rmudgett@digium.com>
 *
 * See Also:
 * \arg \ref AstCREDITS
 * \arg \ref Config_agent
 */
/*** MODULEINFO
	<depend>res_monitor</depend>
	<support_level>core</support_level>
 ***/


#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/config_options.h"
#include "asterisk/astobj2.h"
#include "asterisk/stringfields.h"

/*** DOCUMENTATION
	<application name="AgentLogin" language="en_US">
		<synopsis>
			Call agent login.
		</synopsis>
		<syntax>
			<parameter name="AgentId">
				<para>
	 				If not present the agent is prompted for an identifier.
	 			</para>
			</parameter>
			<parameter name="options">
				<optionlist>
					<option name="s">
						<para>silent login - do not announce the login ok segment after
						agent logged on/off</para>
					</option>
				</optionlist>
			</parameter>
		</syntax>
		<description>
			<para>Login an agent to the system.  Always returns <literal>-1</literal>.
			While logged in, the agent can receive calls and will hear a <literal>beep</literal>
			when a new call comes in.  The agent can dump the call by pressing the star key.</para>
		</description>
		<see-also>
			<ref type="application">Queue</ref>
			<ref type="application">AddQueueMember</ref>
			<ref type="application">RemoveQueueMember</ref>
			<ref type="application">PauseQueueMember</ref>
			<ref type="application">UnpauseQueueMember</ref>
			<ref type="function">AGENT</ref>
			<ref type="filename">agents.conf</ref>
			<ref type="filename">queues.conf</ref>
		</see-also>
	</application>
	<function name="AGENT" language="en_US">
		<synopsis>
			Gets information about an Agent
		</synopsis>
		<syntax argsep=":">
			<parameter name="agentid" required="true" />
			<parameter name="item">
				<para>The valid items to retrieve are:</para>
				<enumlist>
					<enum name="status">
						<para>(default) The status of the agent (LOGGEDIN | LOGGEDOUT)</para>
					</enum>
					<enum name="password">
						<para>The password of the agent</para>
					</enum>
					<enum name="name">
						<para>The name of the agent</para>
					</enum>
					<enum name="mohclass">
						<para>MusicOnHold class</para>
					</enum>
					<enum name="channel">
						<para>The name of the active channel for the Agent (AgentLogin)</para>
					</enum>
					<enum name="fullchannel">
						<para>The untruncated name of the active channel for the Agent (AgentLogin)</para>
					</enum>
				</enumlist>
			</parameter>
		</syntax>
		<description></description>
	</function>
	<manager name="Agents" language="en_US">
		<synopsis>
			Lists agents and their status.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
		</syntax>
		<description>
			<para>Will list info about all possible agents.</para>
		</description>
	</manager>
	<manager name="AgentLogoff" language="en_US">
		<synopsis>
			Sets an agent as no longer logged in.
		</synopsis>
		<syntax>
			<xi:include xpointer="xpointer(/docs/manager[@name='Login']/syntax/parameter[@name='ActionID'])" />
			<parameter name="Agent" required="true">
				<para>Agent ID of the agent to log off.</para>
			</parameter>
			<parameter name="Soft">
				<para>Set to <literal>true</literal> to not hangup existing calls.</para>
			</parameter>
		</syntax>
		<description>
			<para>Sets an agent as no longer logged in.</para>
		</description>
	</manager>
 ***/

/* ------------------------------------------------------------------- */

/*
 * BUGBUG Change agents.conf to use this format:
 * [general]
 * section reserved
 *
 * [agents]
 * gives warning if present and declines to load.
 *
 * [1001] <- agent-id/username
 * type=agent <- to leave section names open for other purposes
 * secret=password
 * fullname=Agent name used for logging purposes.
 * other parameters.
 *
 * None of the current global options need to remain global.
 * They can be made per agent.
 */

/*! Single agent config line parameters. */
struct agent_cfg {
	AST_DECLARE_STRING_FIELDS(
		/*! Identification of the agent.  (agents config container key) */
		AST_STRING_FIELD(username);
		/*! Password the agent needs when logging in. */
		AST_STRING_FIELD(password);
		/*! Name of agent for logging and querying purposes */
		AST_STRING_FIELD(full_name);

		/*! DTMF string for an agent to accept a call. (login override) */
		AST_STRING_FIELD(dtmf_accept);
		/*! DTMF string for an agent to end a call. (login override) */
		AST_STRING_FIELD(dtmf_end);
		/*! Beep sound file to use.  Alert the agent a call is waiting. */
		AST_STRING_FIELD(beep_sound);
/* BUGBUG NOT USED agents.conf goodbye option */
		AST_STRING_FIELD(goodbye_sound);
		/*! MOH class to use while agent waiting for call. */
		AST_STRING_FIELD(moh);
		/*! Absolute recording filename directory. (Made to start and end with '/') */
		AST_STRING_FIELD(save_calls_in);
		/*! Recording filename extension. */
		AST_STRING_FIELD(record_format);
/* BUGBUG the following config option likely cannot be supported: record_format_text */
		/*! Recording filename extension used with url_prefix. */
		AST_STRING_FIELD(record_format_text);
/* BUGBUG the following config option likely cannot be supported: url_prefix */
		/*! CDR userfield recording filename directory. */
		AST_STRING_FIELD(url_prefix);
	);
	/*! Agent groups an agent belongs to. */
	ast_group_t group;
	/*! Number of seconds for agent to ack a call before being logged off if non-zero. (login override) */
	int auto_logoff;
	/*! TRUE if agent needs to ack a call to accept it. (login override) */
	int ack_call;
	/*! TRUE if agent can use DTMF to end a call. */
	int end_call;
	/*! Number ms after a call before can get a new call. (login override) */
	int wrapup_time;
	/*! Number of failed login attempts allowed. (login override) */
	int max_login_tries;
/* BUGBUG the following config option likely cannot be supported: updatecdr */
	/*! TRUE if CDR is to be updated with agent id.  (login override) */
	int updatecdr;
/* BUGBUG NOT USED agents.conf autologoffunavail option */
	int autologoffunavail;
	/*! TRUE if agent calls are recorded. */
	int record_agent_calls;
};

static void *agent_cfg_alloc(const char *username)
{
	/*! \todo BUGBUG agent_cfg_alloc() not written */
	return NULL;
}

static void *agent_cfg_find(struct ao2_container *agents, const char *username)
{
	/*! \todo BUGBUG agent_cfg_find() not written */
	return NULL;
}

/*! Agents config section */
struct agents_cfg {
	/*! Configured agents */
	struct ao2_container *agents;
};

static struct aco_type agent_type = {
	.type = ACO_ITEM,
	.name = "agent",
	.category_match = ACO_BLACKLIST,
	.category = "^(general|agents)$",
	.matchfield = "type",
	.matchvalue = "agent",
	.item_alloc = agent_cfg_alloc,
	.item_find = agent_cfg_find,
	.item_offset = offsetof(struct agents_cfg, agents),
};

/* The general category is reserved, but unused */
static struct aco_type general_type = {
	.type = ACO_GLOBAL,
	.name = "global",
	.category_match = ACO_WHITELIST,
	.category = "^general$",
};

static struct aco_file agents_conf = {
	.filename = "agents.conf",
	.types = ACO_TYPES(&general_type, &agent_type),
};

/*
 * BUGBUG must fix config framework loading of multiple files.
 *
 * A reload with multiple files must reload all files if any
 * file has been touched.
 */
/*
 * BUGBUG chan_agent stupidly deals with users.conf.
 *
 * Agents built by users.conf will use defaults except for the
 * three parameters obtained from users.conf.  Also any agent
 * declared by users.conf must not already be declared by
 * agents.conf.
 *
 * [general]
 * hasagent = yes/no (global [user] hasagent=yes value)
 *
 * [user] <- agent-id/username
 * hasagent = yes/no
 * fullname=name
 * secret=password
 *
 *static struct aco_file users_conf = {
 *	.filename = "users.conf",
 *	.preload = { "general", NULL }
 *	.types = ACO_TYPES(&users_type, &users_general_type),
 *};
 *
 *	.files = ACO_FILES(&agents_conf, &users_conf),
 */

static AO2_GLOBAL_OBJ_STATIC(cfg_handle);

static void *agents_cfg_alloc(void)
{
	/*
	 * Create struct agents_cfg object.  A lock is not needed for
	 * the object or any secondary created cfg objects.  These
	 * objects are immutable after the config is loaded.
	 */
	/*! \todo BUGBUG agents_cfg_alloc() not written */
	return NULL;
}

CONFIG_INFO_STANDARD(cfg_info, cfg_handle, agents_cfg_alloc,
	.files = ACO_FILES(&agents_conf),
);

static void destroy_config(void)
{
	ao2_global_obj_release(cfg_handle);
	aco_info_destroy(&cfg_info);
}

static int load_config(int reload)
{
	if (!reload) {
		if (aco_info_init(&cfg_info)) {
			return -1;
		}
	}

	/*! \todo BUGBUG load_config() not written */

	if (aco_process_config(&cfg_info, reload) == ACO_PROCESS_ERROR) {
		goto error;
	}

	return 0;

error:
	/* On a reload, just keep the config we already have in place. */
	if (!reload) {
		destroy_config();
	}
	return -1;
}

static int unload_module(void)
{
	destroy_config();
	return 0;
}

static int load_module(void)
{
	if (load_config(0)) {
		ast_log(LOG_ERROR, "Unable to load config. Not loading module.\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

static int reload(void)
{
	return load_config(1);
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Call center agent pool applications",
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
	.load_pri = AST_MODPRI_DEVSTATE_PROVIDER,
);
