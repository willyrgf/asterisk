Edvina AB
Olle E. Johansson


Project started: 2013-09-12


Goal: 		To accept INVITEs with crypto lifetime and MKI values
Out of scope:	To actually follow and honor the crypto lifetime
		This may be part 2 of this project though


Problem:
========

Chan_sip currently doesn't parse any key attributes in SDES negotiations, 
nor does it support multiple keys in the SDP. When receiving any attribute,
chan_sip hangs up the call. This is obviously not a behaviour anyone wants.
Generally, hanging up a call is considered bad behaviour.

Current status:
===============
- We do accept lifetimes over 10 hours (hard coded, could be setting)
- We only accept MKI number 1. Nothing else.
- We handle no lifetime, only MKI or only lifetime too
- We check that the lifetime is not too big
- We check that the crypto tag is up to 9 characters only (should be checked for digits only at some point)
- We reject everything with an option like FEC_ORDER

tested with a few different a=crypto syntaxes below.

SDES crypto attribute examples:
==============================

Syntax: from RFC 4568
         a=crypto:<tag> <crypto-suite> <key-params> [<session-params>]

For SDES the key-params starts with "inline:". There can be multiple key-params, separated
with semi-colon.

Example of a=crypto headers:
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32

a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32

THe lifetime can be ignored as this example (also from RFC 4568)
        inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1066:4

There can be multiple keys with different MKI values:

a=crypto:2 F8_128_HMAC_SHA1_80
       inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4;
       inline:QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5|2^20|2:4
       FEC_ORDER=FEC_SRTP


The MKI always have a colon. The lifetime parameter can be decimal.
