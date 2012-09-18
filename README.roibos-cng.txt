Edvina AB
Olle E. Johansson


Started: 2012-09-18





Comfort Noise support in Asterisk 1.8
=====================================

Current state:

* RTP Channel
-------------

- Asterisk RTP (res_rtp_asterisk.c) will read CNG packets and produce a warning. 
  These will be forwarded to the core.
- CNG packets will be sent only as RTP keepalives

* SIP Channel
-------------
- The SIP channel will *NOT* negotiate any CNG support if offered, nor 
  offer CNG

* Core
------

- If a generator is active and CNG is received, Asterisk moves to timer based
  generation of outbound packets
- No comfort noise generator exists in core

To add comfort noise support
----------------------------

- Add SIP negotiation in SDP
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
