/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, Olle E. Johansson
 *
 * Olle E. Johansson <oej@edvina.net>
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
 * \brief Audiohook for silnce detection
 */

#ifndef _ASTERISK_SILENCEDETECTION_H
#define _ASTERISK_SILENCEDETECTION_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

/*! \brief Activation of silence detection 
	\param chan		The channel
	\param silencelevel 	Audio treshold for silence
	\param silenceframes	Number of frames before we react

     \note That this function assumes the channel is set to read signed linear audio

*/
int ast_sildet_activate(struct ast_channel *chan, unsigned int silencelevel, unsigned int silenceframes);

/*! \brief Deactivation of silence detection 
	\param chan		The channel
*/
int ast_sildet_deactivate(struct ast_channel *chan);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _ASTERISK_SILENCEDETECTION_H */
