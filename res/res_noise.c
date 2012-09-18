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

#include <math.h>

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/app.h"

#ifdef HAVE_EXP10L
#define FUNC_EXP10       exp10l
#elif (defined(HAVE_EXPL) && defined(HAVE_LOGL))
#define FUNC_EXP10(x)   expl((x) * logl(10.0))
#elif (defined(HAVE_EXP) && defined(HAVE_LOG))
#define FUNC_EXP10(x)   (long double)exp((x) * log(10.0))
#endif

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

static struct ast_frame framedefaults = {
	.frametype = AST_FRAME_VOICE,
	.subclass.codec = AST_FORMAT_SLINEAR,
	.offset = AST_FRIENDLY_OFFSET,
	.mallocd = 0,
	.data.ptr = NULL,
	.datalen = 0,
	.samples = 0,
	.src = "whitenoise",
	.delivery.tv_sec = 0,
	.delivery.tv_usec = 0
};


#ifndef LOW_MEMORY
/*
 * We pregenerate 64k of white noise samples that will be used instead of
 * generating the samples continously and wasting CPU cycles. The buffer
 * below stores these pregenerated samples.
 */
static float pregeneratedsamples[65536L];
#endif

/* 
 * We need a nice, not too expensive, gaussian random number generator.
 * It generates two random numbers at a time, which is great.
 * From http://www.taygeta.com/random/gaussian.html
 */
static void box_muller_rng(float stddev, float *rn1, float *rn2) {
	const float twicerandmaxinv = 2.0 / RAND_MAX;
	float x1, x2, w;
	 
	do {
		x1 = random() * twicerandmaxinv - 1.0;
		x2 = random() * twicerandmaxinv - 1.0;
		w = x1 * x1 + x2 * x2;
	} while (w >= 1.0);
	
	w = stddev * sqrt((-2.0 * logf(w)) / w);
	*rn1 = x1 * w;
	*rn2 = x2 * w;
}

static void *noise_alloc(struct ast_channel *chan, void *data) {
	float level = *(float *)data; /* level is noise level in dBov */
	float *pnoisestddev; /* pointer to calculated noise standard dev */
	const float maxsigma = 32767.0 / 3.0;

	/*
	 * When level is zero (full power, by definition) standard deviation
	 * (sigma) is calculated so that 3 * sigma equals max sample value
	 * before overload. For signed linear, which is what we use, this
	 * value is 32767. The max value of sigma will therefore be
	 * 32767.0 / 3.0. This guarantees that roughly 99.7% of the samples
	 * generated will be between -32767 and +32767. The rest, 0.3%,
	 * will be clipped to comform to the channel limits, i.e., +/-32767.
	 * 
	 */
	pnoisestddev = malloc(sizeof (float));
	if(pnoisestddev) {
		*pnoisestddev = maxsigma * FUNC_EXP10(level / 20.0);
	}
	return pnoisestddev;
}

static void noise_release(struct ast_channel *chan, void *data) {
	free((float *)data);
}

static int noise_generate(struct ast_channel *chan, void *data, int len, int samples) {
#ifdef LOW_MEMORY
	float randomnumber[2];
	float sampleamplitude;
	int j;
#else
	uint16_t start;
#endif
	float noisestddev = *(float *)data;
	struct ast_frame f;
	int16_t *buf, *pbuf;
	int i;

#ifdef LOW_MEMORY
	/* We need samples to be an even number */
	if (samples & 0x1) {
		ast_log(LOG_WARNING, "Samples (%d) needs to be an even number\n", samples);
		return -1;
	}
#endif

	/* Allocate enough space for samples.
	 * Remember that slin uses signed dword samples */
	len = samples * sizeof (int16_t);
	if(!(buf = alloca(len))) {
		ast_log(LOG_WARNING, "Unable to allocate buffer to generate %d samples\n", samples);
		return -1;
	}

	/* Setup frame */
	memcpy(&f, &framedefaults, sizeof (f));
	f.data.ptr = buf;
	f.datalen = len;
	f.samples = samples;

	/* Let's put together our frame "data" */
	pbuf = buf;

#ifdef LOW_MEMORY
	/* We need to generate samples every time we are called */
	for (i = 0; i < samples; i += 2) {
		box_muller_rng(noisestddev, &randomnumber[0], &randomnumber[1]);
		for (j = 0; j < 2; j++) {
			sampleamplitude = randomnumber[j];
			if (sampleamplitude > 32767.0)
				sampleamplitude = 32767.0;
			else if (sampleamplitude < -32767.0)
				sampleamplitude = -32767.0;
			*(pbuf++) = (int16_t)sampleamplitude;
		}
	}
#else
	/*
	 * We are going to use pregenerated samples. But we start at
	 * different points on the pregenerated samples buffer every time
	 * to create a little bit more randomness
	 *
	 */
	start = (uint16_t) (65536.0 * random() / RAND_MAX);
	for (i = 0; i < samples; i++) {
		*(pbuf++) = (int16_t)(noisestddev * pregeneratedsamples[start++]);
	}
#endif

	/* Send it out */
	if (ast_write(chan, &f) < 0) {
		ast_log(LOG_WARNING, "Failed to write frame to channel '%s'\n", chan->name);
		return -1;
	}
	return 0;
}

static struct ast_generator noise_generator = 
{
	alloc: noise_alloc,
	release: noise_release,
	generate: noise_generate,
} ;

static int noise_exec(struct ast_channel *chan, const char *data) {

	struct ast_module_user *u;
	char *excessdata;
	float level = 0;
	float timeout = 0;
	char *s;
	int res;

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
	ast_set_write_format(chan, AST_FORMAT_SLINEAR);
	ast_set_read_format(chan, AST_FORMAT_SLINEAR);
	if (chan->_state != AST_STATE_UP) {
		ast_answer(chan);
	}
	if (ast_activate_generator(chan, &noise_generator, &level) < 0)	{
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
		ast_deactivate_generator(chan);
	}
	ast_module_user_remove(u);
	return res;
}

static int unload_module(void) {
	ast_module_user_hangup_all();
	
	return ast_unregister_application(app);
}

static int load_module(void) {
#ifndef LOW_MEMORY
	/* Let's pregenerate all samples with std dev = 1.0 */
	int i;

	for (i = 0; i < sizeof (pregeneratedsamples) / sizeof (pregeneratedsamples[0]); i += 2) {
		box_muller_rng(1.0, &pregeneratedsamples[i], &pregeneratedsamples[i + 1]);

	}
#endif
	return ast_register_application_xml(app, noise_exec);
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS, "White Noise Generator Application",
                .load = load_module,
                .unload = unload_module,
               );
