Edvina AB
Olle E. Johansson

Project initiated: 2013-06-24







Reset Music on hold after transfer to queue
===========================================

Problem:
========

When doing attended SIP transfer to a queue the music on hold is not provided
to the new channel. After a period of silence, a periodic statement may
be provided and after that music is turned on.

The queue application turns on music on hold, but no one checks that a
call has been transferred and the masquerade operation doesn't reset
music. Queue() belives that the channel is getting music but there's
no active generator on the channel.

Chan_sip turns off all generators before doing a masquerade, but has
no known status to reset. There's a flag in the channel indicating that
MOH is active, but there's no saved music class to reset it.

Possible Solution:
==================

When setting the AST_MOH flag on the channel, also set the music class.
In the SIP channel, store the music class and reset MOH after transfer
succeeded, much like hold states.

This requires changes to at least the music on hold system and the
SIP channel driver, and the ast_channel structure.

Todo:
=====
1. Figure out what to do.
2. Do it.
3. Test it.
4. Commit it1. Figure out what to do.
2. Do it.
3. Test it.
4. Commit it.

