Edvina AB
Olle E. Johansson


Started: 2012-09-18
Updated: 2012-11-13





Comfort Noise support in Asterisk 1.8
=====================================

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
will get an incoming CNG frame with a noise level. THis will be sent
over the bridge to the bridged channel.

If that channel is SIP with CNG enabled for the call, the RTP system
will send out a CNG frame.

It that channel is a type that doesn't support CNG or SIP with CNG
disabled, then Asterisk needs to generate noise in the bridged
channel - not the SIP channel that received the CNG frame. This is
to enable forwarding a CNG across to another SIP device which now
gets the responsibility to play out the noise.

The architecture for this may be using Asterisk Framehooks, but is still
under discussion.

Current state:

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

To add comfort noise support
----------------------------

- For inbound streams, generate noise in calls
- For outbound we can as step 1 just never send any CNG packets
  - As step 2, add silence detection to calls
  - Measure noise level
  - Start sending CNG
  - Listen for talk detection
  - Stop sending CNG, send media

Done:
  - Added res_noise.c from cmantunes from https://issues.asterisk.org/jira/browse/ASTERISK-5263
    This includes a noise generator
  - Add SIP negotiation in SDP - done

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
- CN Comfort Noise 
- CNG Comfort Noise Generator

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
