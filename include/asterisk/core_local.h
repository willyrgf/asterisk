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
 * \brief Local proxy channel and other unreal channel derivatives framework.
 *
 * \author Richard Mudgett <rmudgett@digium.com>
 *
 * See Also:
 * \arg \ref AstCREDITS
 */

#ifndef _ASTERISK_CORE_LOCAL_H
#define _ASTERISK_CORE_LOCAL_H

#include "asterisk/channel.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

/* ------------------------------------------------------------------- */

/*!
 * \brief The base pvt structure for local channel derivatives.
 *
 * The unreal pvt has two ast_chan objects - the "owner" and the "next channel", the outbound channel
 *
 * ast_chan owner -> ast_unreal_pvt -> ast_chan chan
 */
struct ast_unreal_pvt {
	struct ast_channel *owner;      /*!< Master Channel - ;1 side */
	struct ast_channel *chan;       /*!< Outbound channel - ;2 side */
	struct ast_format_cap *reqcap;  /*!< Requested format capabilities */
	struct ast_jb_conf jb_conf;     /*!< jitterbuffer configuration */
	unsigned int flags;             /*!< Private option flags */
	/*! Base name of the unreal channels.  exten@context or other name. */
	char name[AST_MAX_EXTENSION + AST_MAX_CONTEXT + 2];
};

#define AST_UNREAL_IS_OUTBOUND(a, b) ((a) == (b)->chan ? 1 : 0)

#define AST_UNREAL_CARETAKER_THREAD (1 << 0) /*!< The ;2 side launched a PBX, was pushed into a bridge, or was masqueraded into an application. */
#define AST_UNREAL_NO_OPTIMIZATION  (1 << 1) /*!< Do not optimize out the unreal channels */
#define AST_UNREAL_MOH_PASSTHRU     (1 << 2) /*!< Pass through hold start/stop frames */

/*!
 * \brief Send an unreal pvt in with no locks held and get all locks
 *
 * \note NO locks should be held prior to calling this function
 * \note The pvt must have a ref held before calling this function
 * \note if outchan or outowner is set != NULL after calling this function
 *       those channels are locked and reffed.
 * \note Batman.
 */
void ast_unreal_lock_all(struct ast_unreal_pvt *p, struct ast_channel **outchan, struct ast_channel **outowner);

/*!
 * \brief Hangup one end (maybe both ends) of an unreal channel derivative.
 * \since 12.0.0
 *
 * \param p Private channel struct (reffed)
 * \param ast Channel being hung up.  (locked)
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int ast_unreal_hangup(struct ast_unreal_pvt *p, struct ast_channel *ast);

int ast_unreal_digit_begin(struct ast_channel *ast, char digit);
int ast_unreal_digit_end(struct ast_channel *ast, char digit, unsigned int duration);
int ast_unreal_answer(struct ast_channel *ast);
struct ast_frame *ast_unreal_read(struct ast_channel *ast);
int ast_unreal_write(struct ast_channel *ast, struct ast_frame *f);
int ast_unreal_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen);
int ast_unreal_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
int ast_unreal_sendhtml(struct ast_channel *ast, int subclass, const char *data, int datalen);
int ast_unreal_sendtext(struct ast_channel *ast, const char *text);
int ast_unreal_queryoption(struct ast_channel *ast, int option, void *data, int *datalen);
int ast_unreal_setoption(struct ast_channel *chan, int option, void *data, int datalen);

/*!
 * \brief Get the other local channel in the pair.
 * \since 12.0.0
 *
 * \param ast Local channel to get peer.
 *
 * \note On entry, ast must be locked.
 *
 * \note Intended to be called after ast_request() and before
 * ast_call() on a local channel.
 *
 * \retval peer reffed on success.
 * \retval NULL if no peer or error.
 */
struct ast_channel *ast_local_get_peer(struct ast_channel *ast);

/* ------------------------------------------------------------------- */

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif	/* _ASTERISK_CORE_LOCAL_H */
