/*
 * Asterisk -- A telephony toolkit for Linux.
 *
 * Implementation of SIP - The Session Initiation protocol
 *
 * Version 3 of the SIP channel
 * 
 * Copyright (C) 2003-2006, Digium Inc
 * and Edvina AB (for the chan_sip3 additions/changes)
 *
 * Mark Spencer <markster@linux-support.net>
 * and Olle E. Johansson <oej@edvina.net>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 */
 
#ifndef _SIP3_H
#define _SIP3_H

#define THIS_IS_A_TEST	"Pineapples are sweet"

#ifndef FALSE
#define FALSE    0
#endif

#ifndef TRUE
#define TRUE     1
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


#define VIDEO_CODEC_MASK        0x1fc0000 /*!< Video codecs from H.261 thru AST_FORMAT_MAX_VIDEO */
#ifndef IPTOS_MINCOST
#define IPTOS_MINCOST           0x02
#endif

/* #define VOCAL_DATA_HACK */

#define DEFAULT_DEFAULT_EXPIRY  120
#define DEFAULT_MIN_EXPIRY      60
#define DEFAULT_MAX_EXPIRY      3600
#define DEFAULT_REGISTRATION_TIMEOUT 20
#define DEFAULT_MAX_FORWARDS    "70"

/* guard limit must be larger than guard secs */
/* guard min must be < 1000, and should be >= 250 */
#define EXPIRY_GUARD_SECS       15                /*!< How long before expiry do we reregister */
#define EXPIRY_GUARD_LIMIT      30                /*!< Below here, we use EXPIRY_GUARD_PCT instead of 
                                                   EXPIRY_GUARD_SECS */
#define EXPIRY_GUARD_MIN        500                /*!< This is the minimum guard time applied. If 
                                                   GUARD_PCT turns out to be lower than this, it 
                                                   will use this time instead.
                                                   This is in milliseconds. */
#define EXPIRY_GUARD_PCT        0.20                /*!< Percentage of expires timeout to use when 
                                                    below EXPIRY_GUARD_LIMIT */
#define DEFAULT_EXPIRY 900                          /*!< Expire slowly */

#endif
