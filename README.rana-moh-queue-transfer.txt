Edvina AB
Olle E. Johansson

Project initiated: 2013-06-24
Update: 2013-07-03






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

Solution:
==================

Implement a new function in the Asterisk MOH interface to query
the musicclass. This is ONLY returned if MOH is active.

Chan_sip reads this before masquerading channels and resets
MOH after masquerade, since the transfer code resets all generators.

This only applies to attended transfers where one leg of the call
is not bridged. Like transfer to queue, IVR, or simply parking.

Testing:
========
This has been tested with a number of SIP phones and proved
to work.
