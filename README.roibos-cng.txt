Edvina AB
Olle E. Johansson


Started: 2012-09-18
Updated: 2014-04-07





Silence Suppression and Comfort Noise support in Asterisk 1.8
=============================================================

Comfort Noise in SIP/RTP is 
- negotiated in the SDP as a codec
- starts activated by a silence in the media stream
- the sender stops sending media, sends a single CNG RTP packet that indicates
  a noise level
- the receiver activated a Comfort Noise Generator in the call until media 
  reappears from the sender

A requirement for using this is that it is included as a codec with payload
13 (or dynamic) in the SDP

Asterisk Architecture
=====================
In a bridged call, where one end is SIP with CNG enabled, the RTP system
will get an incoming CNG frame with a noise level. This will be sent
over the bridge to the bridged channel.

If that channel is SIP with CNG enabled for the call, the RTP system
will send out a CNG frame.  This is to enable forwarding a CNG frame 
across to another SIP device which now gets the responsibility to play out 
the noise.

It that channel is a type that doesn't support CNG or SIP with CNG
disabled, then Asterisk needs to generate noise in the bridged
channel - not the SIP channel that received the CNG frame. 

Current state:
==============

* RTP Channel
-------------

- Asterisk RTP (res_rtp_asterisk.c) will read CNG packets and produce a warning. 
  These will be forwarded to the core.
- CNG packets will be sent only as RTP keepalives

* SIP Channel
-------------
- The SIP channel will negotiate any CNG support if offered and
  offer CNG if configured. SIP.conf setting:
	;comfort-noise=yes              ; Enable Comfort Noise generation on RTP streams
	;                               ; Available per device too

* Core
------
- If a generator is active and CNG is received, Asterisk moves to timer based
  generation of outbound packets
- Comfort noise generator added to core
- Comfort noise generator will be used when CNG frame is received, until the RTP
  channel signals that CNG will end.

Detecting Silence
=================
The current silence detector in Asterisk only supports signed linear audio.
This means that for a g.729 call we have to transcode to signed linear, listen 
for audio and in some cases, but not all, transcode back.

Later we have to
- Add silence detection to the codec modules so they can signal silence
  in an incoming stream to the core

Debugging
=========
Place a call between one phone that supports CN (I've used a SNOM 820) and a
phone that lacks support for it (or has it disabled for testing). 
- Turn on RTP debug and SIP debug.
- Set core debug to 3.
You will now see that Asterisk receives a CN RTP packet, and will activate
the noise generator on the other channel. This happens many times during 
the call.

Todo :: comfort noise support
-----------------------------
  - Check how this affects RTP bridge and queue bridge
  - Add CN support in SDP for outbound calls

Done:
  - Support in core bridge
  - For inbound streams, generate noise in calls (both inbound and outbound calls)
  - Added res_noise.c from cmantunes from https://issues.asterisk.org/jira/browse/ASTERISK-5263
    This includes a noise generator
  - Add SIP negotiation in SDP - done
  - Support CN codec on incoming INVITEs - done
  - Silence detection and suppression added for SIP calls

References
----------

- RFC 3389 http://tools.ietf.org/html/rfc3389
- Appendix II to Recommendation G.711 (02/2000) - A comfort noise
        payload definition for ITU-T G.711 use in packet-based
        multimedia communication systems.


Terms
-----
- DTX Discontinues Transmission capability
- VAD Voice Activity Detection
- CN Comfort Noise , http://en.wikipedia.org/wiki/Comfort_noise
- CNG Comfort Noise Generator
- Silence Suppression: http://en.wikipedia.org/wiki/Silence_suppression

RTP Framing (RFC 3389 section 4)
--------------------------------
The RTP header for the comfort noise packet SHOULD be constructed as
   if the comfort noise were an independent codec.  Thus, the RTP
   timestamp designates the beginning of the comfort noise period.

At the beginning of
   an inactive voice segment (silence period), a CN packet is
   transmitted in the same RTP stream and indicated by the CN payload
   type.  The CN packet update rate is left implementation specific. For
   example, the CN packet may be sent periodically or only when there is
   a significant change in the background noise characteristics.  The
   CNG algorithm at the receiver uses the information in the CN payload
   to update its noise generation model and then produce an appropriate
   amount of comfort noise.

Noise Level (RFC 3389 Section 3.1)
----------------------------------
The magnitude of the noise level is packed into the least significant
   bits of the noise-level byte with the most significant bit unused and
   always set to 0 as shown below in Figure 1.  The least significant
   bit of the noise level magnitude is packed into the least significant
   bit of the byte.

   The noise level is expressed in -dBov, with values from 0 to 127
   representing 0 to -127 dBov.  dBov is the level relative to the
   overload of the system.  (Note: Representation relative to the
   overload point of a system is particularly useful for digital
   implementations, since one does not need to know the relative
   calibration of the analog circuitry.)  For example, in the case of a
   u-law system, the reference would be a square wave with values +/-
   8031, and this square wave represents 0dBov.  This translates into
   6.18dBm0.

-----------------
Various notes:
=============
From file:

The logic for determining if a native bridge can be performed or not lives in ast_channel_bridge in channel.c - there is an if statement with many conditions that have to be met before doing it. You can extend that and add another which is "if the CN support on channel A is the same as channel B then allow native bridge"

Question: If I run RTP bridge (not the p2p or remote) can we still operate
on timer? If not, I have to disable RTP bridging totally. If we rely on incoming
packets (which will not happen) to send out, CN will not work.

Yes, you can still operate on timer. The RTP bridge still has all the normal bridging logic in it. That's how music on hold and such works.

Brian West in ASTERISK-140 2004-04-24:
"This is the one thing that keeps asterisk out of the big boy toy box.... lets get it going boys."
