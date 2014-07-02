Edvina AB 
Olle E. Johansson


Started: 2014-07-02



The Timestamp Dilemma
=====================

When Asterisk has a bridged (not p2p) RTP call we tend to send out the same timestamps as
we receive.

If the call is put on hold we start sending music on hold and add to the last timestamp
received while sending RTP. If the other end puts us off hold, we ignore our last sent
time stamp and start sending the incoming time stamp again, which in many cases
means that we send a time stamp from the past instead of adding.

We could change SSRC and be happy, but that would mean adding another SSRC change to
what we're already doing. While changing SSRC is a cure for a lot of bad code, I think
it's better to fix the issue. There is no reason that the incoming time stamp controls
the outbound time stamp. None at all. Let's keep our time stamp and just add to it.

