/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Contributed by Carlos Antunes <cmantunes@gmail.com>
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
 * \brief Just generate white noise 
 * 
 */

/*** MODULEINFO
	<support_level>random</support_level>
 ***/


#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/app.h"

#include <math.h>

static char *app = "WhiteNoise";


/*** DOCUMENTATION
	<application name="WhiteNoise" language="en_US">
		<synopsis>
			Generates white noise
		</synopsis>
		<syntax>
		<parameter name="args">
			<argument name="timeout" required="true" />
			<argument name="level" required="false" />
		</parameter>
		</syntax>
		<description>
			<para>Generates white noise at 'level' dBov's for 'timeout' seconds or indefinitely if timeout
			is absent or is zero.</para>
			<para>Level is a non-positive number. For example, WhiteNoise(0.0) generates
			white noise at full power, while WhiteNoise(-3.0) generates white noise at
			half full power. Every -3dBov's reduces white noise power in half. Full
			power in this case is defined as noise that overloads the channel roughly 0.3%
			of the time. Note that values below -69 dBov's start to give out silence
			frequently, resulting in intermittent noise, i.e, alternating periods of
			silence and noise.</para>

		</description>
	</application>
***/

static int noise_exec(struct ast_channel *chan, const char *data) {

	struct ast_module_user *u;
	char *excessdata;
	float level = 0;
	float timeout = 0;
	char *s;
	int res;
	struct ast_noise_generator *gendata;

        AST_DECLARE_APP_ARGS(args,
                AST_APP_ARG(timeout);
                AST_APP_ARG(level);
        );

	/* Verify we potentially have arguments and get local copy */
        if (!data) {
                ast_log(LOG_WARNING, "WhiteNoise usage following: WhiteNoise([timeout[, level]])\n");
                return -1;
        }
	
	/* Separate arguments */	
        s = ast_strdupa(data);
        AST_STANDARD_APP_ARGS(args, s);

	if (args.timeout) {	
		/* Extract second argument, if available, and validate
		 * timeout is non-negative. Zero timeout means no timeout */
		args.timeout = ast_trim_blanks(args.timeout);
		timeout = strtof(args.timeout, &excessdata);
		if ((excessdata && *excessdata) || timeout < 0) {
			ast_log(LOG_WARNING, "Invalid argument 'timeout': WhiteNoise requires non-negative floating-point argument for timeout in seconds\n");				
			return -1;
		}

		/* Convert timeout to milliseconds
		 * and ensure minimum of 20ms      */
		timeout = roundf(timeout * 1000.0);
		if (timeout > 0 && timeout < 20) {
			timeout = 20;
		}
	} 

	if (args.level) {
		/* Extract first argument and ensure we have
		 * a valid noise level argument value        */
		args.level = ast_trim_blanks(args.level);
		level = strtof(args.level, &excessdata);
		if ((excessdata && *excessdata) || level > 0) {
			ast_log(LOG_ERROR, "Invalid argument 'level': WhiteNoise requires non-positive floating-point argument for noise level in dBov's\n");
			return -1;
		}
	} 

	ast_debug(1, "Setting up white noise generator with level %.1fdBov's and %.0fms %stimeout\n", level, timeout, timeout == 0 ? "(no) " : "");

	u = ast_module_user_add(chan);
	if (chan->_state != AST_STATE_UP) {
		ast_answer(chan);
	}
	gendata = ast_channel_start_noise_generator(chan, level);
	if (data == NULL)	{
		ast_log(LOG_WARNING, "Failed to activate white noise generator on '%s'\n",chan->name);
		res = -1;
	} else {
		/* Just do the noise... */
		res = -1;
		if (timeout > 0) {
			res = ast_safe_sleep(chan, timeout);
		} else  {
			while(!ast_safe_sleep(chan, 10000));
		}
		ast_channel_stop_noise_generator(chan, gendata);
	}
	ast_module_user_remove(u);
	return res;
}

static int unload_module(void) {
	ast_module_user_hangup_all();
	
	return ast_unregister_application(app);
}

static int load_module(void) {
	return ast_register_application_xml(app, noise_exec);
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS, "White Noise Generator Application",
                .load = load_module,
                .unload = unload_module,
               );
