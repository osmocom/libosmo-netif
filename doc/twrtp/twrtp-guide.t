.\" This document is written in troff language, using -ms macros
.\" plus pic and tbl preprocessors.  The original ThemWi version
.\" of this document was produced on a MicroVAX 4.3BSD system
.\" using Quasijarus troff; the present Osmocom-adapted version
.\" has been modified to format with groff, an implementation of
.\" troff that is available in most GNU+Linux distributions.
.nr LL 6.5i
.TL
Guide to ThemWi RTP endpoint library (Osmocom version)
.AU
Mychaela N. Falconia
.AI
Themyscira Wireless
.\" Any additional authors editing this document in the future,
.\" please add another stanza of this form:
.\"
.\" .AU
.\" Your name
.\" .AI
.\" Your "institution", e.g., sysmocom GmbH or Osmocom Community etc.
.\"
.hw hand-over
.hw time-stamp
.hw trans-port
.hw wrap-around
.NH 1
Introduction
.PP
This document describes the version of Themyscira Wireless RTP endpoint
library (\fBtwrtp\fP) that is integrated into \&\fClibosmo\-netif\fP.
This version of \fBtwrtp\fP is a derivative work based on the original
author's \&\fCtwrtp\-native\fP version, used by ThemWi network elements
in Osmocom+ThemWi hybrid networks, and this version of the manual
is a derivative work based on the original \fBtwrtp\fP guide document.
.NH 2
Principal function
.PP
ThemWi RTP endpoint library, consisting of \%\fC<osmocom/netif/twrtp.h>\fP
and \%\fC<osmocom/netif/twjit.h>\fP blocks in the present version,
is intended for interworking between an RTP stream and a fixed timing system
such as GSM Um interface TCH or T1/E1 TDM.  Such interworking consists of two
fundamental elements:
.IP \(bu
In every fixed time quantum, the interworking element receives a unit of
speech or CSData media from the fixed source and emits an RTP packet
carrying that quantum of speech or CSData.
.IP \(bu
In the opposite direction, the fixed timing system requires a quantum of
speech or CSData to be fed to it on every tick without fail, yet the
interworking element has no control over when RTP packets may arrive
from the IP network.  This direction of interworking requires a rather
complex element called a jitter buffer, an element whose design and
configuration always involves some trade-offs and compromises.
.NH 2
Domain of application
.PP
The present library is \fBnot\fP intended to be an all-purpose implementation
of IETF RFCs 3550 and 3551, supporting all possible RTP use cases as
envisioned by IETF.  Instead it is intended to support RTP \fIas it is used\fP
in these two specific telecom network environments:
.IP \(bu
3GPP networks that use RTP according to TS\ 26.102 and TS\ 48.103;
.IP \(bu
The way RTP is used to transport G.711 PSTN traffic across the public
Internet in what may be colloquially referred to as IP-PSTN.
.LP
The two 3GPP specs referenced above prescribe a fixed packetization time
of 20\ ms for all codecs on AoIP interface.  Furthermore, they stipulate
that:
.IP \(bu
In the case of compressed speech transport, each RTP packet carries
exactly one frame of the speech codec in use;
.IP \(bu
In the case of uncompressed G.711 speech or CSData transport, each RTP
packet carries exactly 160 payload octets (20\ ms worth) of what would
have been a 64\ kbit/s timeslot in T1/E1 transport.
.LP
This fixed-quantum property, namely the property that every RTP packet
carries exactly one fixed quantum of speech or CSData, where the duration
of this quantum is known at connection setup time and cannot suddenly
change from one packet to the next, is required by the present ThemWi
RTP endpoint library \(em this requirement constitutes a fundamental aspect
of its architectural design.
.PP
An RTP endpoint implementation library that imposes the just-described
requirement is sufficient for the purpose of building IP-based GSM networks
that follow 3GPP TS\ 48.103 (the requirements of that spec are in agreement
with the library constraint), and it is also sufficient for interfacing
to IP-PSTN by way of common commercial PSTN-via-SIP connectivity providers.
.PP
In the case of IP-PSTN, the author of the present library has experience
only with North American PSTN-via-SIP connectivity providers.  In all
of our operational experience so far, these IP-PSTN connectivity providers
behave in ways that are fully compatible with the expectations of the
present RTP library, as long as the following conditions are met:
.IP \(bu
No attempt is made to use any codecs other than PCMU or PCMA:
don't include any other codecs in the SDP offer, and send only SDP answers
that select either PCMU or PCMA out of the received multi-codec offer.
.IP \(bu
No attempt is made to use any other \&\fCptime\fP besides the most common
industry standard of 20\ ms.
.LP
In all operational experience so far, incoming INVITE SDPs indicate either
\&\fCa=ptime:20\fP or \&\fCa=maxptime:20\fP, and when we indicate
\&\fCa=ptime:20\fP in all SDPs we send out, the IP-PSTN peer always sends us
20\ ms RTP packets, as opposed to some other packetization interval which
would break the fixed-quantum model assumed by the present RTP library.
.PP
However, it needs to be acknowledged that the present library is \fBnot\fP
suitable for general-purpose, IETF-style applications outside of
``walled garden'' 3GPP networks or the semi-walled environment of
IP-PSTN with ``well-behaved'' entities: there are many behaviors that
are perfectly legal per the RFCs, but are not supported by the present
library.  Having a peer send RTP with a packetization interval that is
different from what we asked for via \&\fCptime\fP attribute is one of those
behaviors that is allowed by IETF, but not supported by this library.
.NH 3
Expectation of continuous streaming
.PP
In addition to the just-described requirement for a fixed packetization
interval, the domain of application for \fBtwrtp\fP is subject to one more
constraint: our jitter buffer component (\fBtwjit\fP) is designed for
environments that implement continuous streaming, and may perform suboptimally
in those that do not.
.PP
Continuous streaming is an operational policy under which an RTP endpoint
\fIalways\fP emits an RTP packet in \fIevery\fP 20\ ms (or whatever other
packetization interval is used) time window, be it rain or shine, even if
it has no data to send because nothing was received on the air interface
(DTX pause on the radio link, reception errors, frame stealing) or because
E1 TRAU frame decoding failed, etc.
Continuous streaming may be implemented by sending an RTP packet with a
zero-length payload when the endpoint has nothing else to send in a given
quantum time window \(em this method allows any existing RTP payload format
standard to be operationally modified for continuous streaming.
There also exist Themyscira-defined enhanced RTP payload formats for GSM
speech codecs that not only mandate continuous streaming, but additionally
convey errored frame bits and the Time Alignment Flag in every 20\ ms frame
position, exactly like TRAU-UL frames in the world of TDM-based GSM.
.PP
The opposite of continuous streaming is the practice of intentional gaps.
Under this operational policy, an RTP endpoint may create intentional gaps
in the RTP stream it emits, simply by sending no RTP packets at all when
it deems that there are no useful data to be transmitted.
An intentional gap is distinguished from packet loss in that the sequence
number in the RTP header increments by one while the timestamp increments
by a greater than normal amount.
Unfortunately for \fBtwjit\fP, intentional gaps in RTP were the design intent
of IETF.
Even more unfortunately, this IETF-ism has been canonized
by 3GPP in TS\ 26.102 and TS\ 48.103 \(em hence those operators who prefer a
continuous streaming model now have to explicitly deviate from 3GPP
specifications.
.PP
In an Osmocom GSM network, 3GPP-compliant operation with intentional gaps
is the default \(em however, the operator can switch to continuous streaming
model
by setting \%\fCrtp\ continuous\-streaming\fP in OsmoBTS vty configuration.
.PP
Fortunately for \fBtwjit\fP, however, the situation is better in the world
of IP-PSTN, the other RTP environment for which the present library was
designed.
At least on North American IP-PSTN and at least when uncompressed PCMU or
PCMA codecs are used, all PSTN-via-SIP connectivity providers in our
operational experience so far always emit perfectly continuous RTP streams,
without any intentional gaps.
.PP
If an application uses \fBtwrtp\fP with \fBtwjit\fP to receive an RTP stream
that incurs intentional gaps, the resulting performance may be acceptable
or unacceptable depending on additional factors:
.IP \(bu
If RTP gaps are incurred only during frame erasure events (radio
errors or FACCH stealing) without DTX, the resulting \fBtwjit\fP performance
will most likely still be acceptable for speech applications.
All transmitted speech frames will still be delivered to the receiver,
but the frame erasure gap may lengthen or shorten depending on exact jitter
buffer conditions at the time of the intentional gap in the Tx stream \(em
in other words, a phase shift may be incurred.
.IP \(bu
If RTP stream gaps are enabled in conjunction with DTX, \fBtwjit\fP will not
be able to receive such a stream according to common expectations.
When RTP stream gaps are used together with DTX, the stream will typically
feature occasional single packets of comfort noise update, sent every
160, 240 or 480 ms depending on the codec, surrounded by gaps.
When \fBtwjit\fP receives such a stream and the flow-starting fill level
is set to 2 or greater (the default and usually necessary configuration),
all of these ``isolated island'' comfort noise update packets will be dropped
\(em a behavior counter to the way DTX is expected to work.
.LP
The take-away is that if an operator wishes to use DTX with \fBtwrtp\fP,
they need to enable \%\fCrtp\ continuous\-streaming\fP.
.NH 2
Configurable quantum duration and time scale
.LP
For every RTP stream it handles, the library needs to know two key
parameters:
.IP \(bu
The scale or ``clock rate'' used for RTP timestamps, i.e., how many
timestamp units equal one millisecond of physical time;
.IP \(bu
The ``quantum'' duration in milliseconds.
.PP
\fBQuantum\fP is the term used in this RTP endpoint library for the unit
of speech or CSData carried in one RTP packet.  In Kantian philosophy terms,
a quantum of speech or CSData is the thing-in-itself (a single codec frame,
or a contiguous chunk of 160 PCM samples grabbed from an ISDN B channel),
whereas the RTP packet that carries said quantum is one particular transport
representation of that thing-in-itself.
.PP
In most applications of this library (all 3GPP codecs other than AMR-WB,
and all IP-PSTN applications in our experience so far), the time scale
is 8000 timestamp units per second (or 8 per millisecond, as it appears
in the actual APIs) and the time duration of a single quantum is 20\ ms,
hence one quantum equals 160 timestamp units.
Both parameters (RTP timestamp clock rate in kHz and the number of ms
per quantum) are configurable at the time of endpoint creation, allowing
RTP endpoints for AMR-WB, or perhaps G.711 or CSData applications with
different packetization times \(em but they cannot be changed later in
the lifetime of an allocated endpoint.
.PP
For ease of exposition, the rest of this document will assume that
one quantum equals 20\ ms in time or 160 RTP timestamp units.  If these
numbers are different in your application, substitute accordingly.
.NH 1
Jitter buffer model
.PP
In the interworking direction from incoming RTP to the fixed timing system,
the latter will poll the RTP endpoint (or more precisely, the jitter buffer
portion thereof) for a quantum of media every 20\ ms, whenever that quantum
is required for transmission on GSM Um TCH or for TDM output etc.
The job of the jitter buffer is to match previously received RTP packets
to these fixed-timing output polls, while striving to meet these two
conflicting goals:
.IP \(bu
Any time that elapses between an RTP packet being received and its
payload being passed as a quantum to the fixed timing system constitutes
added latency \(em which needs to be minimized.
.IP \(bu
IP-based transport always involves some jitter: the time delta between
the receipt of one RTP packet and the arrival of its successor is very
unlikely to be exactly equal to 20\ ms every time.  This jitter may be
already present in the RTP stream from its source if that source is
an IP-native BTS that does not pass through E1 Abis and thus exposes
the inherent jitter of GSM TDMA multiframe structure, but even if
the source is perfectly timed, some jitter will still be seen on the
receiving end.  Depending on the actual amount of jitter seen in a
given deployment, it may be necessary to introduce some latency-adding
buffering in the receiving RTP endpoint \(em otherwise the function of
interworking to the fixed timing system at the destination will perform
poorly, as will be seen in the ensuing sections.
.LP
This chapter covers the design and operation of \fBtwjit\fP,
the jitter buffer component of ThemWi RTP endpoint library.
.NH 2
Flows and handovers
.LP
In \fBtwjit\fP terminology, a single RTP flow is a portion (or the whole)
of an RTP stream that exhibits the following two key properties:
.IP \(bu
All packets have the same SSRC;
.IP \(bu
The RTP timestamp increment from each packet to the next always equals
the fixed quantum duration expressed in timestamp units, i.e., 160
in most practical applications.
.LP
A handover in \fBtwjit\fP terminology is a point in the incoming RTP stream
at which either of the following events occurs:
.IP \(bu
An SSRC change is seen;
.IP \(bu
The RTP timestamp advances by an increment that is not an integral multiple
of the expected fixed quantum duration.  In contrast, if an RTP timestamp
increment is seen that \fIis\fP an integral multiple of the quantum, but that
integral multiple is more than one, and there is enough buffering in the
system such that this event is seen before the jitter buffer underruns,
such events are \fBnot\fP treated as handovers: instead it is assumed to be
an occurrence of either packet loss or reordering.
.LP
A handover in \fBtwjit\fP is thus a transition from one flow to the next.
This term was adopted because such transitions are expected to occur
when an RTP stream belonging to a single call switches from one BSS endpoint
to another (in the same BSS or in a different one) upon radio handover events
in GSM and other cellular networks, but handovers in \fBtwjit\fP sense can also
occur in other applications that aren't GSM.  For example, if an IP-PSTN peer
we are conversing with suddenly decides, for its own reasons known only to
itself, to change its SSRC or jump its RTP output timescale, our \fBtwjit\fP
instance will treat that event as a handover.
.NH 2
Examples of flows
.PP
The following drawing depicts the best case scenario of a TDM-native speech or
CSData stream being transported across an IP network in RTP:
.KS
.PS
# each time line in these drawings is 4i long
# let's represent each 20 ms interval as 0.4i in the drawing,
# i.e., each 1 ms is 0.020i long

Tx_line: line -> right 4i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 4i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 3.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

for x = 0.2i to 3.4i by 0.4i do {
	arrow from Tx_line + x,0 down vdist right 0.3i
}
.PE
.ce
Figure 1: Ideal case
.KE
.PP
In the above figure and other similar drawings that follow, each
down-and-forward arrow represents an RTP packet: the beginning of each arrow
on the RTP Tx line is the point in time when that RTP packet is emitted
by the source endpoint, and the landing point of each arrow on the RTP Rx
line is the time point when the same packet is received at the destination
endpoint.  The forward horizontal movement of each arrow in the figure is
the flight time of the corresponding RTP packet through the IP network.
Tick marks below the RTP Rx time axis represent fixed points in time
when the destination application polls its \fBtwjit\fP buffer because
the destination fixed timing system (GSM Um TCH, T1/E1 etc) requires a new
quantum of media.
.PP
Figure\ 1 depicts the ideal scenario: the source endpoint emits RTP packets
in a perfect 20\ ms cadence without built-in jitter, the flight time through
the IP network also remains constant from each packet to the next (no jitter
introduced by IP transport), and these packets arrive in a perfect cadence
at the receiving endpoint, exactly one packet before each \fBtwjit\fP polling
instant.
Let us now consider a more realistic scenario:
.KS
.PS
Tx_line: line -> right 4i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 4i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 3.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

Tx0: Tx_line + 0.04i,0

Land0: Rx_line + (0.04i + 0.02i * 26.0),0
Land1: Land0 + (0.02i * 19.992),0
Land2: Land1 + (0.02i * 20.522),0
Land3: Land2 + (0.02i * 19.509),0
Land4: Land3 + (0.02i * 20.211),0
Land5: Land4 + (0.02i * 19.741),0
Land6: Land5 + (0.02i * 25.245),0
Land7: Land6 + (0.02i * 14.776),0
Land8: Land7 + (0.02i * 20.007),0

arrow from Tx0 to Land0
arrow from Tx0 + (0.02i * 20),0 to Land1
arrow from Tx0 + (0.02i * 40),0 to Land2
arrow from Tx0 + (0.02i * 60),0 to Land3
arrow from Tx0 + (0.02i * 80),0 to Land4
arrow from Tx0 + (0.02i * 100),0 to Land5
arrow from Tx0 + (0.02i * 120),0 to Land6
arrow from Tx0 + (0.02i * 140),0 to Land7
arrow from Tx0 + (0.02i * 160),0 to Land8

"seq # 0x0630" at 1/2 <Tx_line.start, Rx_line.start> + 0.23i,0 rjust
"seq # 0x0638" at 1/2 <Tx_line.end, Rx_line.end> - 0.45i,0 ljust
.PE
.ce
Figure 2: IP-PSTN realistic scenario, good Internet connection
.KE
.PP
Figure\ 2 above is based on an actual IP-PSTN test call that was made on
2024-05-14 from the author's interconnection point with BulkVS to a phone
number on T-Mobile USA (2G).  The figure was drawn using these time-of-arrival
delta numbers from the pcap of that call:
.TS
box center;
c|c|c
n|n|n.
From seq #	To seq #	ToA delta (ms)
_
0x0630	0x0631	19.992
0x0631	0x0632	20.522
0x0632	0x0633	19.509
0x0633	0x0634	20.211
0x0634	0x0635	19.741
0x0635	0x0636	25.245
0x0636	0x0637	14.776
0x0637	0x0638	20.007
.TE
.PP
This small excerpt from the pcap of one particular test call is a
representative example of this author's general experience with North American
IP-PSTN.  Most of the time the \(*D between arrival times of two successive
RTP packets is within a few microseconds of the ideal 20\ ms value;
interarrival jitter spikes up to about 500\ \(*ms are fairly frequent
(seen a few times every second), but larger spikes (in the range of several
milliseconds) appear as rare outliers when I look at pcap files from
short test calls.
.PP
In order to draw packet flight diagrams that are intuitively understandable
by a human reader, we need to know the absolute flight time from the source
for each depicted packet.  In actual operation this absolute flight time
is unknowable \(em the only available info is the observed cadence of
time-of-arrival deltas.  (The absolute reception time of each packet according
to the local clock is known of course, but it is of no use without knowing
the absolute time at which those packets were emitted by the sender.)
These absolute flight times of packets are furthermore not needed for
actual operation of jitter buffers \(em the available ToA \(*D information
is sufficient for jitter buffer design and tuning \(em but they are needed
for more intuitive understanding by humans.
Therefore, when we draw packet flight diagrams, we have to factor in some
arbitrary, made-up number for the ``baseline'' packet flight time under
ideal conditions: the purely notional ``baseline'' number which, when added
to the actually observed jitter, equals what we assume to be the true
flight time of each individual packet.
In drawing Figure\ 2 above, I set this ``baseline'' delay to 26\ ms:
one half of the lowest round-trip time I observe now when I ping the
IPv4 address of the IP-PSTN node I was conversing with in that test call.
.PP
In drawing this figure, I also exercised a degree of freedom in choosing
the arbitrary (not known in advance in real operation) phase shift between
the arrival time of RTP packets and the receiving entity's fixed time base,
i.e., the position of fixed-time polling ticks below the RTP Rx time axis
relative to the times of packet arrival on the same axis.
The specific phase shift I chose in drawing this figure is one that
illustrates the effect of this amount of real-world jitter on \fBtwjit\fP
operation: RTP packet with sequence number 0x0636 arrives just after
the receiver's polling time instead of just before.
The significance of this effect will be seen when we examine \fBtwjit\fP
operation and tuning.
.PP
At this point a reader of this paper, seeing that most packets depicted
in Figure\ 2 exhibit interarrival jitter measured in \(*ms rather than ms,
with a single occurrence of 5\ ms jitter as a rare outlier, may accuse
this author of first-world privilege in terms of Internet connection quality.
So let us consider what the figure would look like with more substantial
jitter \(em but still below 20\ ms.
(Why below 20\ ms, you may ask?  The answer will be seen shortly.)
Because such jitter does not occur in the wild where I live,
I used a made-up dataset for the following figure:
.KS
.PS
# Let's assume each packet flight time consists of a 24 ms fixed component
# and a random jitter component between 0 and 13 ms: total flight time
# thus ranges from 24 to 37 ms, random in this range.

Tx_line: line -> right 4i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 4i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 3.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

Pkt1: arrow from Tx_line + 0.06,0 down vdist right 0.02i * 24.791
Pkt2: arrow from Pkt1 + 0.4,0 down vdist right 0.02i * 34.899
Pkt3: arrow from Pkt2 + 0.4,0 down vdist right 0.02i * 26.518
Pkt4: arrow from Pkt3 + 0.4,0 down vdist right 0.02i * 29.739
Pkt5: arrow from Pkt4 + 0.4,0 down vdist right 0.02i * 27.318
Pkt6: arrow from Pkt5 + 0.4,0 down vdist right 0.02i * 31.820
Pkt7: arrow from Pkt6 + 0.4,0 down vdist right 0.02i * 26.468
Pkt8: arrow from Pkt7 + 0.4,0 down vdist right 0.02i * 36.795
Pkt9: arrow from Pkt8 + 0.4,0 down vdist right 0.02i * 24.051
.PE
.ce
Figure 3: 13\ ms of random jitter
.KE
.PP
In the above figure, each packet flight time was arbitrarily picked in the
range between 24 and 37 ms, i.e., a ``baseline'' delay of 24\ ms combined
with 13\ ms of jitter.  (The actual flight times for the figure were
initially drawn from an RNG program, then slightly tweaked by hand to
get closer to the extremes of the jitter range to be illustrated.)
Unlike Figure\ 2 which represents a real life occurrence, Figure\ 3 is
completely made up \(em yet as will be seen later in this paper,
the same \fBtwjit\fP configuration that is optimal for Figure\ 2 will also
handle the conditions of Figure\ 3 just as well \(em and the jitter
is more visible here.
.PP
So far we've only considered cases of jitter below 20\ ms, i.e., jitter
magnitude less than the periodic interval between successive RTP packets.
A reader ought to ask now: what happens if the jitter exceeds 20\ ms?  Before
we can answer the question of what happens in such cases, let us first
consider what it means for IP network-induced jitter to exceed the interval
between successive packets.
Assuming that successive RTP packets are emitted every 20\ ms by the sender,
for the receiver to experience interarrival jitter that exceeds 20\ ms,
the intervening IP network would have to ``bunch up'' packets: the receiving
end suddenly stops receiving packets when they are expected, then a slew of
massively delayed packets arrive all at once.
The following figure is a real life example of such occurrence:
.KS
.PS
Tx_line: line -> right 6i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 6i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 5.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

Tx0: Tx_line + 0.1i,0

Land0: Rx_line + (0.1i + 0.02i * 26.0),0
Land1: Land0 + (0.02i * 19.951),0
Land2: Land1 + (0.02i * 22.235),0
Land3: Land2 + (0.02i * 18.341),0
Land4: Land3 + (0.02i * 19.429),0
Land5: Land4 + (0.02i * 127.784),0
Land6: Land5 + (0.02i * 1.542),0
Land7: Land6 + (0.02i * 3.417),0
Land8: Land7 + (0.02i * 0.273),0
Land9: Land8 + (0.02i * 0.440),0
Land10: Land9 + (0.02i * 0.115),0
Land11: Land10 + (0.02i * 6.467),0
Land12: Land11 + (0.02i * 20.013),0
Land13: Land12 + (0.02i * 20.009),0

arrow from Tx0 to Land0
arrow from Tx0 + (0.02i * 20),0 to Land1
arrow from Tx0 + (0.02i * 40),0 to Land2
arrow from Tx0 + (0.02i * 60),0 to Land3
arrow from Tx0 + (0.02i * 80),0 to Land4
arrow from Tx0 + (0.02i * 100),0 to Land5
arrow from Tx0 + (0.02i * 120),0 to Land6
arrow from Tx0 + (0.02i * 140),0 to Land7
arrow from Tx0 + (0.02i * 160),0 to Land8
arrow from Tx0 + (0.02i * 180),0 to Land9
arrow from Tx0 + (0.02i * 200),0 to Land10
arrow from Tx0 + (0.02i * 220),0 to Land11
arrow from Tx0 + (0.02i * 240),0 to Land12
arrow from Tx0 + (0.02i * 260),0 to Land13

"seq # 0x0082" at 1/2 <Tx_line.start, Rx_line.start> + 0.28i,0 rjust
"seq # 0x008F" at 1/2 <Tx_line.end, Rx_line.end> - 0.40i,0 ljust
.PE
.ce
Figure 4: 6 packets bunched together by IP network bottleneck
.KE
.PP
The above figure is based on observed behavior during an experiment performed
by this author on 2024-03-31, involving a mobile Internet connection (LTE)
and a Hurricane Electric IPv6 tunnel.
A WireGuard tunnel was established between the author's laptop and a server;
the test laptop was connected to the Internet via T-Mobile LTE in this
experiment, while the server was one that has native IPv4 plus an IPv6 address
by way of HE 6-in-4 tunnel.
The WireGuard tunnel was set up using only IPv6 addresses on the outside,
i.e., the LTE leg saw only IPv6 in this experiment.
A test stream of RTP packets,
spaced 20\ ms apart on the sending end, was transmitted inside a WireGuard
tunnel from the test laptop to the test server; the path of each packet
was thus as follows:
.IP \(bu
WireGuard encapsulation in IPv6 on the sending end (laptop);
.IP \(bu
Transport across T-Mobile Internet service (LTE) in IPv6, going
to the IPv6 address of the Hurricane Electric tunnel;
.IP \(bu
Hurricane Electric PoP received each packet on IPv6 and re-emitted it in IPv4
wrapping, going to the IPv4 address of the author's server;
.IP \(bu
The receiving server decapsulated first 6-in-4, then WireGuard.
.LP
A similar experiment was performed addressing a different server, one that has
native IPv6 connectivity in addition to IPv4; the behavior seen in Figure\ 4
was not seen in that other experiment, leading to the conclusion that the IP
network bottleneck that occasionally ``bunches together'' a series of
consecutive RTP packets is an artifact of the HE 6-in-4 tunnel, rather than
an artifact of mobile Internet access via LTE.
.PP
Irrespective of the cause though, Figure\ 4 is a good illustration of what
happens when buffering delays at an IP network bottleneck significantly exceed
the spacing interval between successive RTP packets.
No packet loss occurred in this experiment, i.e., every packet emitted by
the sending end was \fIeventually\fP received; likewise, no reordering appeared
at the receiving end: packets were received in the same order in which they
were emitted by the sender.
However, if we look at the arrival times of these selected packets
on the receiving end, we see the following picture \(em the dataset from which
Figure\ 4 was drawn:
.TS
box center;
c|c|c
c|c|n.
From seq #	To seq #	ToA delta (ms)
_
0x0082	0x0083	19.951
0x0083	0x0084	22.235
0x0084	0x0085	18.341
0x0085	0x0086	19.429
0x0086	0x0087	127.784
0x0087	0x0088	1.542
0x0088	0x0089	3.417
0x0089	0x008A	0.273
0x008A	0x008B	0.440
0x008B	0x008C	0.115
0x008C	0x008D	6.467
0x008D	0x008E	20.013
0x008E	0x008F	20.009
.TE
.PP
Generally speaking, IP network behavior in this more adverse environment
(passing through a leg of consumer mobile Internet) is not much worse than the
``luxurious'' IP-PSTN environment (server to server, business-grade Internet
connection on the non-datacenter end) of Figure\ 2: most of the time, ToA \(*D
from one packet to the next is only a few \(*ms away from the true 20\ ms
ideal, with occasional jitter spikes of a few ms.
However, occasionally a more obstinent bottleneck occurs in the IP network path
that blocks the flow for a much longer duration: in the example I presented
here, for just over 120\ ms.
During such suddenly induced pauses, RTP packets coming from the source every
20\ ms accumulate at the bottleneck, and when that bottleneck clears,
all queued-up packets are delivered directly back to back, arriving less than
1\ ms apart, essentially all at once.
.PP
In all examples we have considered so far, there has been no packet reordering:
despite variations in flight time that appear on the receiving end as jitter,
all RTP packets were received in the same order in which they were emitted
by the source endpoint.
Now let us consider what kind of scenarios can result in RTP packets arriving
out of order.
So far this author has not observed even one actual occurrence of packet
reordering \(em apparently it does not happen on IP networks that exist
in this part of the world, even on consumer LTE \(em hence the following
analysis will be strictly theoretical.
Given that the source endpoint steadily emits one packet at a time,
spaced every 20\ ms, how can these packets arrive in a reversed order?  In
order for packets to arrive out of order, a later-sent packet has to
experience significantly shorter transit delay than an earlier-sent one,
such that the later-sent packet ``overtakes'' the earlier-sent one.
One situation where we can easily imagine such happening is the ``melee''
shown in Figure\ 4, the spot on the RTP Rx time axis where 6 different arrows,
representing 6 different RTP packets emitted 20\ ms apart, all arrive at
essentially the same point in time.
In our actual experience, such ``bunched together'' packets still arrive in
the correct order, even if the \(*D in the time of arrival between them is
only a few \(*ms \(em but we can easily imagine a different implementation
of the offending IP network element (the one where the bottleneck occurs)
that ``sprays'' buffered packets out of order when the congestion clears.
The following drawing is a rework of Figure\ 4, showing what this hypothesized
behavior would look like:
.KS
.PS
Tx_line: line -> right 6i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 6i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 5.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

Tx0: Tx_line + 0.1i,0

Land0: Rx_line + (0.1i + 0.02i * 26.0),0
Land1: Land0 + (0.02i * 19.951),0
Land2: Land1 + (0.02i * 22.235),0
Land3: Land2 + (0.02i * 18.341),0
Land4: Land3 + (0.02i * 19.429),0
Land5: Land4 + (0.02i * 127.784),0
Land6: Land5 + (0.02i * 1.542),0
Land7: Land6 + (0.02i * 3.417),0
Land8: Land7 + (0.02i * 0.273),0
Land9: Land8 + (0.02i * 0.440),0
Land10: Land9 + (0.02i * 0.115),0
Land11: Land10 + (0.02i * 6.467),0
Land12: Land11 + (0.02i * 20.013),0
Land13: Land12 + (0.02i * 20.009),0

arrow from Tx0 to Land0
arrow from Tx0 + (0.02i * 20),0 to Land1
arrow from Tx0 + (0.02i * 40),0 to Land2
arrow from Tx0 + (0.02i * 60),0 to Land3
arrow from Tx0 + (0.02i * 80),0 to Land4
arrow from Tx0 + (0.02i * 100),0 to Land10
arrow from Tx0 + (0.02i * 120),0 to Land9
arrow from Tx0 + (0.02i * 140),0 to Land8
arrow from Tx0 + (0.02i * 160),0 to Land7
arrow from Tx0 + (0.02i * 180),0 to Land6
arrow from Tx0 + (0.02i * 200),0 to Land5
arrow from Tx0 + (0.02i * 220),0 to Land11
arrow from Tx0 + (0.02i * 240),0 to Land12
arrow from Tx0 + (0.02i * 260),0 to Land13

"seq # 0x0082" at 1/2 <Tx_line.start, Rx_line.start> + 0.28i,0 rjust
"seq # 0x008F" at 1/2 <Tx_line.end, Rx_line.end> - 0.40i,0 ljust
.PE
.ce
Figure 5: Hypothetical reordering of the 6 ``bunched up'' packets of Figure 4
.KE
.PP
Figure\ 5 above (hypothetical scenario) differs from Figure\ 4 (actual
experience) in that the arrival times of 6 RTP packets 0x0087 through 0x008C
(RTP sequence numbers from the dataset of Figure\ 4) have been reversed:
0x008C is hypothesized to arrive when 0x0087 actually arrived, 0x0087 is
hypothesized to arrive when 0x008C actually arrived, and the 4 packets in
the middle are mirrored symmetrically.
Because all 6 of these packets were stuck waiting behind the same bottleneck
at the same time, the fictional scenario presented in Figure\ 5 is at least
plausible.
.PP
For the sake of completeness, let us consider a more fantastical (less likely
in reality) scenario of packet reordering.
Figure\ 6 below depicts the way beginning students of IP networking likely
imagine packet reordering:
.KS
.PS
Tx_line: line -> right 4i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 4i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 3.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

arrow from Tx_line + 0.2i,0 down vdist right 0.3i
arrow from Tx_line + 0.6i,0 down vdist right 1.3i
arrow from Tx_line + 1.0i,0 down vdist right 0.3i
arrow from Tx_line + 1.4i,0 down vdist right 0.3i
arrow from Tx_line + 1.8i,0 down vdist right 1.0i
arrow from Tx_line + 2.2i,0 down vdist right 0.3i
arrow from Tx_line + 2.6i,0 down vdist right 0.8i
arrow from Tx_line + 3.0i,0 down vdist right 0.3i
arrow from Tx_line + 3.4i,0 down vdist right 0.3i
.PE
.ce
Figure 6: Unlikely form of packet reordering
.KE
.PP
In order for the fictional scenario of Figure\ 6 to occur, the IP network
would have to behave in a way where some packets get stuck behind a
delay-inducing bottleneck, yet other packets, including those that directly
follow the unlucky ``stuck'' packet, are delivered without excessive delay,
arriving ahead of those that got stuck.
It is difficult to imagine what mechanisms could cause a real IP network
to behave in such manner \(em but if some real IP network somewhere does
indeed exhibit this theorized behavior, \fBtwjit\fP should be able to handle
it with appropriate tuning.
.PP
None of the examples we've examined so far include packet loss, only delay
and perhaps reordering.  However, each of the presented figures can be
trivially modified to reflect packet loss: instead of a packet arriving late
or out of order (later than a subsequently-sent packet), it never arrives
at all.
Readers are invited to use their imagination: take any of the arrows that
represent individual RTP packets, and erase it.
.NH 2
Design of twjit
.PP
Having seen various scenarios of RTP flows, let us now consider what work
\fBtwjit\fP needs to do in order to convert a received RTP stream back to
fixed timing.
.PP
Each \fBtwjit\fP instance consists of two sub-buffers (subbufs for short)
and a global state variable that gives the overall state of the instance
across both subbufs.
Each subbuf holds a queue of received RTP packets that belong to a single
RTP flow as defined in \(sc2.1; two subbufs are needed in order to handle
handovers \(em if the incoming RTP stream does not exhibit any handover
events, a single subbuf is sufficient.
.NH 3
The major states of twjit
.LP
Each \fBtwjit\fP instance as a whole, across both subbufs, is a finite state
machine with 4 possible states:
.sp .3
.IP \fBEMPTY\fP 15
The \fBtwjit\fP instance is completely empty, neither subbuf holds any
packets or any meaningful state information.
.IP \fBHUNT\fP 15
Only one subbuf is active and valid in this state;
this subbuf is non-empty \(em some received packets are held \(em but it hasn't
started flowing out yet, as will be explained in the following section.
.IP \fBFLOWING\fP 15
Only one subbuf is active and valid in this state;
this subbuf is both flowing out and accepting new packets.
This state is the one that holds long-term during good reception of a
steady RTP flow.
.IP \fBHANDOVER\fP 15
Both subbufs are active and valid:
one is flowing out while the other receives new packets.
As indicated in the name, this state is entered from the \fBFLOWING\fP state
only when the received RTP stream exhibits a handover.
.sp .3
.LP
Possible transitions between these 4 fundamental states are as follows:
.PS
circlerad = 0.5
EMPTY: circle "\fBEMPTY\fP"
move right 0.65i
HUNT: circle "\fBHUNT\fP"
move same
FLOWING: circle "\fBFLOWING\fP"
move same
HANDOVER: circle "\fBHANDOVER\fP"
arrow from EMPTY.e to HUNT.w
arrow from HUNT.e to FLOWING.w
arc cw -> from FLOWING.s to EMPTY.s rad 2i
arc cw -> from FLOWING.e to HANDOVER.w rad 0.5i
arc cw -> from HANDOVER.w to FLOWING.e rad 0.5i
arc -> from HANDOVER.n to HUNT.n rad 2i
.PE
.PP
In order to understand the workings of \fBtwjit\fP,
let us first consider operation without handovers
(SSRC never changes, and the timestamp increment from each source-emitted packet
to the next always equals the samples-per-quantum constant) \(em in such
sans-handover operation, only \fBEMPTY\fP, \fBHUNT\fP and \fBFLOWING\fP states
are encountered \(em and then examine handover handling.
.NH 3
Structure and operation of one subbuf
.PP
Each subbuf of \fBtwjit\fP
holds a queue of received RTP packets that belong to a single
RTP flow as defined in \(sc2.1.
In terms of memory allocation, the queue of each subbuf is implemented
as a linked list of Osmocom message buffers (\fBmsgb\fPs) \(em but this
implementation detail is really only a matter of memory allocation strategy,
and must \fBnot\fP be misconstrued to infer what kinds of packet sequences
are allowed to exist in one subbuf.
In sharp contrast with a naive interpretation of what a linked list can
presumably hold (any sequence of packets, without strict constraints on
timestamp increment or any other aspect), the logical structure of a single
\fBtwjit\fP subbuf is a chain of fixed slots, where each slot corresponds
to a given RTP timestamp and may be either empty or filled with a received
packet.
.PP
A good physical analogy for the logical structure of a \fBtwjit\fP subbuf
can be found in carrier tapes that hold electronic components in tape-and-reel
packaging.
There is a long tape made of plastic or thick paper with regularly spaced
wells, with each well intended to hold one piece of the reeled part.
Whether each given well in the tape holds a component or is empty, the spacing
between wells remains fixed, and a component cannot be inserted anywhere into
the tape except into a designated well.
.PP
The following drawing depicts a subbuf with both filled and empty slots:
.KS
.PS
boxwid = 0.5
boxht = 0.3

box; box; box; box

move to 1st box.n; line <- up " head" ljust
move to last box.n; line <- up " tail" ljust

"0" at 1st box.s below
"1" at 2nd box.s below
"2" at 3rd box.s below
"3" at last box.s below

boxwid = 0.2
boxht = 0.1

box filled 1 with .center at 1st box
box filled 1 with .center at 4th box

.PE
.ce
Figure 7: Basic principle of twjit subbuf
.KE
.PP
The subbuf depicted in Figure\ 7 has a total depth (to be defined shortly)
of 4 quantum units (please recall the definition of a quantum in \(sc1.3),
the tail slot is filled as always required for a non-empty subbuf,
the head slot is also filled in this example, but the other two slots
are empty.
(Such subbuf state may result from packet loss, and may also occur in cases
of packet reordering if the packets destined for empty slots 1 and 2 may yet
arrive.)
.PP
Every non-empty \fBtwjit\fP subbuf has a head slot, a tail slot and a total
depth.
The head slot is defined by the 32-bit RTP timestamp stored in \&\fChead_ts\fP
member of the subbuf structure, which is \&\fCstruct\ twjit_subbuf\fP inside
\&\fCtwjit.c\fP in the present version.
If the subbuf holds a received RTP packet whose timestamp equals
\&\fChead_ts\fP, that packet resides in the head slot; if no such packet is
held, then the head slot is empty.
However, packets with RTP timestamps earlier than \&\fChead_ts\fP \fBcannot\fP
exist in a subbuf!
.PP
Every received RTP packet held in a subbuf, as well as every empty slot that
can potentially be filled by a late-arriving out-of-order packet, can be viewed
as existing at a certain depth.
The head slot shall be regarded as depth 0, the following slot shall be
regarded as depth 1, and so forth.
Recall that per the fundamental design of \fBtwjit\fP, each subbuf can only
hold RTP packets belonging to a single flow as defined in \(sc2.1 \(em thus
if one quantum equals 160 timestamp units,
slot 1 can only hold an RTP packet whose timestamp equals
(\fChead_ts\fP\ +\ 160),
slot 2 can only hold an RTP packet whose timestamp equals
(\fChead_ts\fP\ +\ 320),
and so forth.
.PP
Of all received RTP packets held by the subbuf, whichever packet has the newest
RTP timestamp is regarded as the current tail of the subbuf, and its depth
is regarded as the current tail slot.
The total depth of a subbuf is defined as the depth of the tail packet plus 1;
in the example of Figure\ 7, the tail packet has depth 3 and the total depth
of the subbuf is 4.
The total depth of a subbuf is also called the fill level, by analogy with
fill level of a water tank.
.PP
When a new RTP packet is received, and that packet is deemed to belong to the
flow already being received (same SSRC, timestamp increment meets expectations),
the newly received packet is added to the current write subbuf.
The insertion depth of the new packet is calculated as the newly received
timestamp minus \&\fChead_ts\fP, divided by the number of timestamp units
per quantum.
If this insertion depth exceeds the current tail depth, which is the normal
case, the subbuf grows (the fill level increases) and the newly added packet
becomes the new tail.
As a result of this operation, the tail slot of a non-empty subbuf
can never be empty!
Alternatively, if the insertion depth falls somewhere before the current
total depth of the subbuf, the fill level stays the same and the target slot
\(em which is expected to be empty in this case \(em
is filled with the newly received packet.
If that target slot was already filled, the new packet is discarded and
an error counter is incremented, indicating duplicate Rx packets.
.PP
When an active, flowing-out subbuf is polled for output at fixed times
determined by TDM or GSM Um etc, the head slot is consumed, whether it is
filled or empty.
If the consumed head slot was filled, that buffered packet is delivered
to the fixed timing system on the output of the jitter buffer.
If that slot was empty, the application on the output of the jitter buffer
receives a gap in the stream.
Either way, when the previous head slot is consumed, \&\fChead_ts\fP is
incremented by the samples-per-quantum constant, the following slot becomes
the new head slot, and the total depth of the subbuf decreases by 1.
.PP
There also exists a special condition in which a subbuf is empty
(does not hold any buffered packets, fill level equals 0),
but is still considered active.
This condition can occur only in \fBFLOWING\fP state, and is covered in
the respective section.
.NH 3
EMPTY and HUNT states
.PP
Upon initialization or reset, each \fBtwjit\fP instance begins life in
\fBEMPTY\fP state.
As soon as the first valid RTP packet is received, one subbuf is initialized
to hold this first packet; the total depth of this newly initialized subbuf
is 1 and the slot occupied by the initial packet is both the head and the tail.
The overall state of \fBtwjit\fP instance transitions to \fBHUNT\fP.
.PP
The purpose of \fBHUNT\fP state is to accumulate enough received packets,
necessarily belonging to a single flow as defined in \(sc2.1, until a
configured threshold is met for entry into \fBFLOWING\fP state.
The critically important configuration parameter is the flow-starting
fill level; it is the first number given on the \&\fCbuffer\-depth\fP vty
configuration line.
.PP
The flow-starting fill level is the fill level (total depth of the sole
active subbuf) required for transition from \fBHUNT\fP state into \fBFLOWING\fP
state.
This criterion is evaluated on every 20\ ms fixed timing tick when the
application polls \fBtwjit\fP for a required quantum of media; as a result of
this check, the \fBtwjit\fP instance either delivers its first output and
transitions into \fBFLOWING\fP, or returns \fBNULL\fP (``sorry, I got nothing'')
to the application and remains in \fBHUNT\fP state.
.PP
The significance of this threshold parameter, and guidelines for its tuning,
are best understood by looking at examples of RTP flows shown in \(sc2.2.
The minimum allowed setting for this parameter is 1; with this minimum setting,
the first tick of the fixed timing system after reception of any RTP packet
always causes transition into \%\fBFLOWING\fP state,
and the packet received just prior to this transition-causing tick
is delivered to the output on that tick.
This setting produces the lowest possible buffer-added latency: this latency
can be near-zero if the RTP packet arrived just prior to the fixed timing tick,
or just under 20\ ms if it arrives just after the previous tick.
.PP
However, if we look at Figures 1 and 2 in \(sc2.2, we can see the one big
problem with this lowest latency setting: the flow remains perfect under
absolutely ideal conditions of Figure\ 1, but as soon as we enter real-world
conditions as shown in Figure\ 2, we can easily encounter scenarios like
the RTP packet with sequence number 0x0636 in that figure.
If the RTP flow depicted in Figure\ 2 were to be received by a \fBtwjit\fP
instance whose flow-starting fill level is set to 1, the buffer would
experience an underrun on the tick of the fixed timing system that just barely
missed the slightly delayed packet; the user would then experience an equivalent
of packet loss (frame erasure) at a time when no actual packet loss occurred.
.PP
For this reason, the default and generally recommended setting for the
flow-starting fill level parameter is 2.
With this setting, two RTP packets with properly consecutive timestamps
must be received in \fBHUNT\fP state before \fBtwjit\fP transitions into
\fBFLOWING\fP state.
The buffer-added latency will be anywhere between 20 and 40 ms,
depending on the unpredictable phase alignment between arriving RTP packets
and ticks of the fixed timing system on the output side of \fBtwjit\fP.
As long as the jitter between flight times of different packets, or its
observable manifestation as interarrival jitter, remains below 20\ ms
(or below 16.9\ ms if the receiving element is OsmoBTS whose fixed time
base includes the inherent jitter of GSM Um multiframe structure),
there will not be an occurrence where the receiving system transforms jitter
into an effective equivalent of packet loss.
This amount of jitter tolerance is sufficient for most practical IP networks
in this author's experience.
.PP
But what if the IP network regularly exhibits packet delay jitter that is
significantly greater than 20\ ms?
Suppose the network regularly exhibits conditions similar to the aberration
depicted in Figure\ 4 \(em what then?
In this case the administrator of jitter-buffer-equipped network elements
has to make a trade-off between two different forms of degraded user experience:
either increase the flow-starting fill level setting and thereby increase the
experienced latency, or live with underruns (frame erasure effectively
equivalent to packet loss) whenever the IP network stops flowing smoothly
and decides to ``bunch up'' packets instead.
As just one example, if the amount of ``bunching up'' exhibited by the IP
network were exactly as depicted in Figure\ 4, and the desire were to eliminate
packet-loss-equivalent effects at the expense of added latency,
the required flow-starting fill level setting would be 7,
producing added latency between 120 and 140 ms.
.NH 4
Reception of additional packets in HUNT state
.PP
Every time an additional RTP packet is received when the \fBtwjit\fP instance
is already in \fBHUNT\fP state (after the first Rx packet that moved the
state from \fBEMPTY\fP to \fBHUNT\fP),
certain checks are made.
The first fundamental requirement of \fBHUNT\fP state is that all queued
packets belong to the same flow.
If the newly received RTP packet has a different SSRC, or if it exhibits
a timestamp increment that is numerically incompatible with being a member
of the same flow (not an integral multiple of samples-per-quantum constant),
all previously queued packets are discarded and the \fBHUNT\fP state is
reinitialized anew with the just-received packet.
This behavior is unavoidably necessary: the single subbuf of \fBHUNT\fP state
holds packets belonging to \fIone\fP particular flow, and given the choice
between a stale flow that appears to have just ended and the new flow that
appears to have just begun, the new flow is clearly the correct choice.
.PP
Once the same-flow requirement is met and the newly received packet is not
too old (packets whose RTP timestamps precede the current \&\fChead_ts\fP
have to be discarded), the new packet is inserted into the sole active
subbuf at its respective depth.
Most of the time, this insertion will increase the total depth or fill level
of this subbuf.
At this point the new fill level is checked against the flow-starting
fill level setting: if the flow-starting fill level has just been exceeded,
packets are discarded from the head of the subbuf and \&\fChead_ts\fP advances
forward until the remaining fill level is equal to or below the flow-starting
threshold.
.PP
This trimming of the subbuf to the flow-starting fill level is necessary to
ensure that the latency added by the jitter buffer will indeed be what the
administrator intended to set via the tunable parameter, as opposed to
potentially much higher added latency that could be caused by artifacts
at flow starting time.
Suppose that the IP network bunches up a significant number of packets
when the sender begins transmitting them 20\ ms apart, then delivers that
bunch all at once, and then begins to flow evenly:
.KS
.PS
Tx_line: line -> right 6i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 6i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 5.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

Tx0: Tx_line + 0.1i,0

# timing numbers are made up!
Land0: Rx_line + (0.1i + 0.02i * 127.5),0
Land1: Land0 + (0.02i * 1.542),0
Land2: Land1 + (0.02i * 3.417),0
Land3: Land2 + (0.02i * 0.273),0
Land4: Land3 + (0.02i * 0.440),0
Land5: Land4 + (0.02i * 0.115),0
Land6: Land5 + (0.02i * 6.467),0
Land7: Land6 + (0.02i * 20.013),0
Land8: Land7 + (0.02i * 20.009),0
Land9: Land8 + (0.02i * 19.992),0
Land10: Land9 + (0.02i * 20.522),0
Land11: Land10 + (0.02i * 19.509),0
Land12: Land11 + (0.02i * 20.211),0
Land13: Land12 + (0.02i * 19.741),0

arrow from Tx0 to Land0
arrow from Tx0 + (0.02i * 20),0 to Land1
arrow from Tx0 + (0.02i * 40),0 to Land2
arrow from Tx0 + (0.02i * 60),0 to Land3
arrow from Tx0 + (0.02i * 80),0 to Land4
arrow from Tx0 + (0.02i * 100),0 to Land5
arrow from Tx0 + (0.02i * 120),0 to Land6
arrow from Tx0 + (0.02i * 140),0 to Land7
arrow from Tx0 + (0.02i * 160),0 to Land8
arrow from Tx0 + (0.02i * 180),0 to Land9
arrow from Tx0 + (0.02i * 200),0 to Land10
arrow from Tx0 + (0.02i * 220),0 to Land11
arrow from Tx0 + (0.02i * 240),0 to Land12
arrow from Tx0 + (0.02i * 260),0 to Land13
.PE
.ce
Figure 8: Packets bunched together at the beginning of flow
.KE
.PP
If the step of trimming the subbuf in \fBHUNT\fP state to the flow-starting
fill level were omitted, then in the scenario depicted in Figure\ 8,
the fill level on entry into \fBFLOWING\fP state would be 7 instead of 2
or whatever flow-starting fill level is configured by the administrator,
significantly increasing the latency experienced by the user.
.PP
If the flow-starting fill level is set to 1, the total depth
of the sole active subbuf in \fBHUNT\fP state will never equal anything
other than 1; if the flow-starting fill level is set to 2 (the default),
the total depth of the subbuf in \fBHUNT\fP state will always equal either
1 or 2, with both head and tail slots always filled.
Empty slots in this sole active subbuf cannot exist when the flow-starting
fill level is set to 1 or 2.
However, if the flow-starting fill level is set to 3 or greater, empty
slots in the subbuf in \fBHUNT\fP state become possible: both head and tail
slots are still always filled in \fBHUNT\fP state, but with higher settings
of the flow-starting fill level configuration parameter, it becomes possible
to have empty slots in the middle, produced by packet loss or reordering.
.NH 4
Additional time delta guards
.PP
Let us once again consider the scenario depicted in Figure\ 8.
The step of trimming the subbuf to the flow-starting fill level prevents
induction of significantly increased latency by initial floods arriving
while the \fBtwjit\fP instance is still in \fBHUNT\fP state
\(em but suppose the transition from \fBHUNT\fP into \fBFLOWING\fP occurs
while an initial flood, similar to that depicted in Figure\ 8,
is still ongoing.
As covered in the following section, once the overall state of \fBtwjit\fP
instance is \fBFLOWING\fP, no more simple head trimming can occur: there is
a much slower-acting standing queue thinning mechanism, but any extra latency
that was induced at the start of the flow can only be dissipated very slowly,
and with an unavoidable side effect of phase shifts in the delivered flow.
.PP
In order to produce better performance in IP network environments where
scenarios like Figure\ 8 are expected,
there is an additional check, optionally enabled per configuration,
gating the transition from \fBHUNT\fP into \fBFLOWING\fP state:
it is \&\fCstart\-min\-delta\fP vty setting.
When this optional parameter is set, it specifies the minimum required
time-of-arrival delta in milliseconds between the most recently received
RTP packet and the one received just prior; this minimum ToA delta must hold
in order for transition from \fBHUNT\fP into \fB\%FLOWING\fP to be allowed.
.PP
For the sake of symmetry, there is also an optional \&\fCstart\-max\-delta\fP
vty setting.
When this optional parameter is set, it specifies the maximum allowed
ToA delta in \fBHUNT\fP and \fBHANDOVER\fP states:
if the ToA delta between successively received packets exceeds this
threshold, previously queued packets are discarded
(regarded as remnants of a stale previous flow)
and the hunt process begins anew with the latest received packet.
.NH 3
FLOWING state
.PP
When the global state of a given \fBtwjit\fP instance is \fBFLOWING\fP,
there is only one active subbuf, just like in \fBHUNT\fP state.
Newly received RTP packets that belong to the same flow (same SSRC,
timestamp increments meet expectations) are likewise added to this subbuf
just as they were during \fBHUNT\fP.
However, the same subbuf is also flowing out: on every tick of the fixed
timing system on the output side of \fBtwjit\fP,
the head slot of the subbuf is consumed and \&\fChead_ts\fP advances
accordingly.
.PP
Unlike \fBHUNT\fP state, \fBFLOWING\fP state allows the head slot of
the sole active subbuf to be empty.
This situation will occur if the received flow experiences a gap
(packet loss, reordering or an intentional gap emitted by the RTP stream
source), the last received packet before the gap is consumed,
but there are still more packets at greater depth,
such that the subbuf is not entirely empty.
If the head slot remains empty on the fixed timing tick that consumes it,
the application on the output side of \fBtwjit\fP receives a gap
in the stream,
but this event is \fBnot\fP regarded as an underrun.
.NH 4
Handling of underruns
.PP
It is possible for the flowing-out subbuf to be empty, but not incur
an underrun just yet.
Suppose the total depth (see \(sc2.3.2) of the flowing-out subbuf
equals 1 at the time of an output poll: the head slot is also the tail slot,
and the previously received RTP packet consumed on this tick is the very last
one received till this moment.
After this output poll tick, the subbuf is empty (total depth equals 0),
but it is still valid in the sense that the overall state remains \fBFLOWING\fP
(does not transition to \fBEMPTY\fP)
and \&\fChead_ts\fP is still regarded as valid, equal to the timestamp
of the last delivered packet plus 160.
If another RTP packet, belonging to the same flow, is received before the
next output poll tick, the flow continues without underrun or any other
undesirable interruptions.
This situation occurs all the time in normal operation when the flow-starting
fill level configuration parameter is optimally tuned, adding just enough
buffering latency to handle the amount of jitter that actually occurs,
but no more.
.PP
A true underrun occurs on the next output poll tick after the one that
leaves the flowing-out subbuf empty while still valid.
At this point the overall state of the \fBtwjit\fP instance transitions to
\fBEMPTY\fP.
Any subsequently received RTP packet, whatever its SSRC and timestamp may be,
causes a transition from \fBEMPTY\fP into \fBHUNT\fP, and the process of
latching onto a flow begins anew.
The application on the output of the jitter buffer will keep receiving
\fBNULL\fP (``sorry, I got nothing'')
starting with the output poll tick on which the underrun occurs
and continuing until the new flow after the underrun (if there is one)
reaches the flow-starting fill level.
.PP
For the benefit of network operations staff looking at stats counters
logged upon call completion (see Chapter\ 3 regarding stats and analytics),
the \&\fCunderruns\fP counter is incremented not at the point where the
actual underrun occurs, but upon receipt of the next RTP packet
(if there is one) that makes the transition from \fBEMPTY\fP into \fBHUNT\fP.
This implementation detail results in not counting the final underrun
that often occurs upon call teardown, instead counting only those underrun
events that are true indications of problematic network conditions
or insufficient jitter buffering.
.NH 4
Standing queue thinning mechanism
.PP
Suppose that the beginning of an RTP flow (acquisition in \fBHUNT\fP state,
then transition into \fBFLOWING\fP) happens when the IP network path
experiences a spike in latency, then later that spike subsides and
latency along the IP network path returns to a lower baseline.
This scenario may look as follows:
.KS
.PS
Tx_line: line -> right 5i
"RTP Tx:" at Tx_line.start - 0.1,0 rjust
"time" at Tx_line.end + 0.1,0 ljust

vdist = 0.8i
move to Tx_line - 0,vdist
Rx_line: line -> right 5i
"RTP Rx:" at Rx_line.start - 0.1,0 rjust
"time" at Rx_line.end + 0.1,0 ljust
for x = 0.2i to 4.8i by 0.4i do {
	line from Rx_line + x,0 down 0.1i
}

Tx0: Tx_line + 0.1i,0

# timing numbers are made up!
Land0: Rx_line + (0.1i + 0.02i * 63),0
Land1: Land0 + (0.02i * 19.992),0
Land2: Land1 + (0.02i * 20.522),0
Land3: Land2 + (0.02i * 19.509),0
Land4: Land3 + (0.02i * 20.211),0
Land5: Land4 + (0.02i * 6.467),0
Land6: Land5 + (0.02i * 1.542),0
Land7: Land6 + (0.02i * 3.417),0
Land8: Land7 + (0.02i * 20.273),0
Land9: Land8 + (0.02i * 20.440),0
Land10: Land9 + (0.02i * 19.501),0
Land11: Land10 + (0.02i * 19.701),0

arrow from Tx0 to Land0
arrow from Tx0 + (0.02i * 20),0 to Land1
arrow from Tx0 + (0.02i * 40),0 to Land2
arrow from Tx0 + (0.02i * 60),0 to Land3
arrow from Tx0 + (0.02i * 80),0 to Land4
arrow from Tx0 + (0.02i * 100),0 to Land5
arrow from Tx0 + (0.02i * 120),0 to Land6
arrow from Tx0 + (0.02i * 140),0 to Land7
arrow from Tx0 + (0.02i * 160),0 to Land8
arrow from Tx0 + (0.02i * 180),0 to Land9
arrow from Tx0 + (0.02i * 200),0 to Land10
arrow from Tx0 + (0.02i * 220),0 to Land11
.PE
.ce
Figure 9: Period of high IP latency followed by lower latency
.KE
.PP
If the flow-starting fill level is set to 2 (the default),
the total depth of the active subbuf will alternate between 1 and 2
during the initial high latency phase: increase to 2 on each RTP packet
arrival, then go back down to 1 when the subsequent output poll tick
consumes the packet in the head slot.
However, following the transition from higher to lower IP network path
latency while \fBtwjit\fP is in \fBFLOWING\fP state, if the arriving
packets land where they do in Figure\ 9,
the subsequent total depth of the same active subbuf will alternate
between 3 and 4: rise to 4 when ``bunched up'' packets arrive,
then go down to 3 on each output poll tick and go back up to 4
as new RTP packets arrive in between those ticks.
.PP
The end result of such happenings is increased buffer-added latency
\(em a standing queue \(em
in the steady flow state after the latency of the IP network path went down.
In the present example, the standing queue latency added as a lasting
artifact of earlier network conditions at flow starting time is 40\ ms \(em
but it can be greater or smaller, in 20\ ms increments, depending on how
the IP network path changes between initial acquisition of a new RTP flow
and its subsequent steady state.
.PP
The design of \fBtwjit\fP includes a mechanism for thinning these standing
queues, gradually bringing buffer-added latency down to a maximum limit
set by the administrator.
The controlling parameter is the high water mark fill level;
it is the second number given on the \&\fCbuffer\-depth\fP vty
configuration line.
This parameter must be greater than or equal to the flow-starting fill level,
but it takes effect only in \fBFLOWING\fP state, not in \fBHUNT\fP.
Any time the total depth of the flowing-out subbuf exceeds this high water
mark on an output poll tick, tested just before consuming the head slot
and any RTP packet contained therein,
the standing queue thinning mechanism kicks in.
This mechanism deletes every \fIN\^\fPth packet from the stream being thinned,
where \fIN\fP is the \&\fCthinning\-interval\fP parameter set in vty config,
for as long as the total depth of the flowing-out subbuf exceeds the
high water mark fill level.
More precisely, every \fIN\^\fPth output poll tick that happens in the state
of high water mark being exceeded advances the head slot by two quantum
units instead of one, with the first consumed head slot always discarded
and the second consumed head slot passed to the output.
This operation remains the same irrespective of whether each of the two
thus consumed head slots holds a previously received RTP packet or is empty.
.PP
The act of deleting a quantum from the middle of an ongoing stream of
speech or CSData is always disruptive: in the case of speech, a 20\ ms
quantum, potentially in the middle of a speaker talking, suddenly disappears;
in the case of CSData, the effect may be even worse with a potentially
important data chunk likewise disappearing, plus a 20\ ms phase shift
in the stream is always incurred.
However, such disruptions are the only way to bring down a standing queue,
whose added latency is another form of evil \(em thus as usual,
engineering is all about trade-offs and compromises.
.PP
The default configuration for \fBtwjit\fP is
\&\fCbuffer\-depth\|\|\|2\|\|\|4\fP and \&\fCthinning\-interval\|\|\|17\fP:
the default high water mark fill level is 4,
and the default thinning interval is to delete every 17th packet, i.e.,
delete one 20\ ms quantum every 340\ ms.
The exact scenario depicted in Figure\ 9 will not invoke the standing queue
thinning mechanism with these default settings: in this depicted scenario,
the total depth of the active subbuf rises to 4 at its highest,
which is also the default high water mark fill level.
However, if this high water mark setting is lowered or if the latency spike
at the beginning of the flow is more substantial, then the standing queue
thinning mechanism will kick in when the IP latency spike subsides.
.PP
The default thinning interval of deleting every 17th packet was chosen
based on these considerations:
.IP a)
340\ ms is long enough to where 20\ ms quantum deletions spaced this far
apart should be tolerable, yet short enough to where a standing queue
would be reduced to the high water mark in reasonable time;
.IP b)
17 is a prime number, thereby reducing the probability that the thinning
mechanism will interfere badly with intrinsic features of the stream
being thinned.
.PP
The default high water mark fill level was chosen so as to provide some
margin above the flow-starting fill level (allow IP network path latency
variations without needless thinning followed by underrun and reacquisition),
while still maintaining a constraint against unbounded growth of a
standing queue.
As always, the optimal engineering trade-off will depend very strongly
on the actual characteristics of the IP network environment on top of which
a GSM network or IP-PSTN system is being built, hence careful attention is
required from the managing operator.
.NH 4
Guard against time traveler packets
.PP
Every time a new RTP packet is received in \fBFLOWING\fP state, a series
of checks are made to answer this question: should the newly received packet
be treated as a continuation of the current flow, or should it be
treated as belonging to a new flow and thus a handover event per \(sc2.1?
The first check is SSRC comparison: if the newly received RTP packet has a
different SSRC than the currently active flow, it is a handover.
.PP
The RTP timestamp is checked next.
In order to handle arbitrary starting 32-bit timestamps and wraparound of
the absolute 32-bit timestamp value at any point, \fBtwjit\fP code computes
the difference between current subbuf \&\fChead_ts\fP (subtrahend) and
the newly received timestamp (minuend),
and treats this difference as a signed 32-bit integer.
If this difference is negative, the newly received packet is treated as a
stale (too old) one, received with so much delay that it can no longer be
accepted: \&\fCtoo_old\fP stats counter is incremented, and the packet in
question is discarded without further processing.
After this check the timestamp increment, now confirmed to be non-negative,
is checked to see if it is an integral multiple of the samples-per-quantum
constant, which is usually 160.
If this integral multiple constraint is violated,
the new packet cannot belong to the same flow as the currently active one,
and it is necessary to invoke handover handling.
.PP
After these two checks, one final check is needed for robustness: a guard
against time traveler packets.
If the increment between current \&\fChead_ts\fP and the timestamp field
in the newly received RTP packet is positive after wraparound handling,
if it is an integral multiple of the samples-per-quantum constant,
but it is excessively large (at 8000 timestamp units per second,
the largest possible post-wraparound-handling RTP timestamp increment
is just over 3 days into the future),
such aberrant RTP packets are jocularly referred to as time travelers.
.PP
Assuming that actual time travel either does not exist at all
or at least does not happen in the present context,
we reason that when such ``time traveler'' RTP packets do arrive,
we must be dealing with the effect of a software bug or misdesign
or misconfiguration in whatever foreign network element is sending us RTP.
In any case, irrespective of the cause, we must be prepared for the
possibility of seeming ``time travel'' in the incoming RTP stream.
We implement an arbitrary threshold: if the received RTP timestamp
is too far into the future, we treat that packet as the
beginning of a new flow, same as SSRC change or non-quantum
timestamp increment, and invoke handover handling.
.PP
The threshold that guards against time traveler packets has 1\ s granularity,
which is sufficient for its intended purpose of catching gross errors.
It is set with \&\fCmax\-future\-sec\fP vty configuration line.
The default value is 10\ s: very generous, perhaps overly so,
to networks with really bad latency.
.NH 3
Handling of packet loss and gaps
.PP
The design of RTP makes it impossible to distinguish between packet loss
and intentional gaps in real time:
if a packet fails to arrive at the time when it is expected and needed
on the receiving end,
the receiver has no way of knowing \fIat that moment\fP
whether the cause of this lack of packet arrival is an intentional gap
emitted by the sender or packet loss along the way.
This distinction can be made later, after the fact: when subsequent
packets arrive, the receiver can examine the sequence number field
in the RTP header and thereby determine which of the two events
(intentional gap or packet loss) happened previously.
However, because this knowledge is not available at the time when it would
be needed, \fBtwjit\fP makes no distinction between these two possibilities
outside of analytics.
For the purpose of mapping received RTP packets to ticks of the fixed timing
system on the output side of \fBtwjit\fP,
any intentional gaps in the incoming RTP stream are treated indistinguishably
from packet loss.
(Please recall from \(sc1.2.1 that \fBtwjit\fP is designed for use with
continuous streaming, not intentional gaps.)
The operational (as opposed to analytics) part of \fBtwjit\fP looks only
at SSRC and timestamp fields in the RTP header; it does not consider
the sequence number at all.
.PP
The actual effect of a gap in the received RTP stream,
whether intentional or caused by packet loss,
depends on the size of the gap
(how many consecutive packets are lost or omitted)
and jitter buffer conditions at the time of its occurrence.
The critical question is whether or not the gap in RTP reception
incurs an underrun:
.IP \(bu
If the gap is small enough, or the running depth of the jitter buffer
is high enough, to where no underrun occurs, then the gap is presented
to the application on the output side of \fBtwjit\fP without distortion:
the application will receive \fBNULL\fP (absence of received packet)
in those quanta whose corresponding RTP packets (corresponding per RTP
timestamp) were not received, while all packets which did arrive will
be delivered correctly, each at its respective quantum point.
No phase shift is incurred in the received stream of media.
.IP \(bu
If the gap results in an underrun,
subsequent received packets after this gap will proceed as acquisition
of a new flow, passing through \fBHUNT\fP state before entering \fBFLOWING\fP.
Preservation of phase cannot be guaranteed under such conditions,
i.e., the gap as perceived by the fixed timing application may be lengthened
or shortened compared to the actual number of RTP packets lost or omitted.
.IP \(bu
If a gap incurs an underrun, then there is a single RTP packet following
this gap, then another gap, the lone RTP packet between the two gaps
will be dropped, assuming the default configuration with flow-starting fill
level set to 2.
This drop occurs because a single RTP packet following an underrun is not
sufficient to establish a new flow when the flow-starting fill level
is greater than 1,
and when another RTP packet arrives after the second gap, the first
between-gaps packet will be too stale.
This failure scenario is the reason why the combination of \fBtwjit\fP,
DTX and intentional gaps will not work.
.LP
If \fBtwjit\fP is deployed in an IP network environment where packet loss
occurs frequently enough to be a concern,
it may be necessary to increase the amount of buffering (by increasing
the flow-starting fill level) so that packet loss events do not turn
into underruns.
However, intentional gaps are always bad in principle and should be avoided
\(em enable continuous streaming instead.
.NH 3
Handling of packet reordering
.PP
As already covered in \(sc2.2, we (Themyscira Wireless) have no operational
experience with packet reordering, as it is a behavior which is not exhibited
by IP networks in our part of the world.
Let us consider nonetheless how \fBtwjit\fP would handle theoretically
envisioned cases of packet reordering that were presented in that section.
.PP
The hypothetical scenario depicted in Figure\ 5 calls for exactly the same
\fBtwjit\fP configuration as the real world scenario of Figure\ 4.
If the IP network frequently exhibits effects like those depicted in
Figure\ 4 and Figure\ 5,
the flow-starting fill level would need to be set to 7.
As long as episodes of packets bunched together, with or without reordering,
are separated by periods of smooth packet flow, \fBtwjit\fP would proceed
through its acquisition stage (\fBHUNT\fP state) in one of these smooth flow
periods, and then episodes of the form depicted in Figure\ 4 or Figure\ 5
would be handled gracefully, without any loss or distortion of transported
media.
.PP
The more fantastical scenario of Figure\ 6 would be handled well by
setting the flow-starting fill level to 4.
Visualizing the state of the sole active subbuf after each RTP packet arrival
and after each output poll tick in that figure is left as an exercise
for the reader \(em however, each media quantum carried by each of the packets
shown in the figure will be delivered to the application on the output side
of \fBtwjit\fP in the correct order, without any loss or distortion.
.NH 3
Handling of handovers
.PP
As covered in \(sc2.1, a handover in \fBtwjit\fP terminology is
a transition from one RTP flow to the next, within the context of a single
RTP stream.
A handover occurs when the incoming RTP stream exhibits a change of SSRC,
a timestamp increment that is not an integral multiple of the
samples-per-quantum constant,
or a ``time travel'' event as described in \(sc2.3.4.3.
.PP
In order to be treated as a handover by \fBtwjit\fP, the newly received RTP
packet that breaks the previous flow in one of the just-listed ways must
arrive while the previous flow (the one it breaks from) is still active,
while the state of the \fBtwjit\fP instance is \fBFLOWING\fP.
If a handover happens after the previous flow underruns, such that the
\fBtwjit\fP instance is in \fBEMPTY\fP state when the first packet of the
new flow arrives,
acquisition of the new flow proceeds via \fBHUNT\fP state in the same way
whether this new flow is continuous or discontinuous with the previous one.
Similarly, if a flow discontinuity (the kind that would be treated as a
handover if it occurred in \fB\%FLOWING\fP state) occurs in \fBHUNT\fP state,
it is handled by reinitializing the \fBHUNT\fP state, without entering
the special \fBHANDOVER\fP state, as detailed in \(sc2.3.3.1.
.PP
True handover handling happens when a flow-breaking RTP packet arrives
in \fBFLOWING\fP state.
This event causes a transition into the dedicated \fBHANDOVER\fP state,
described here.
In this state both subbufs of \fBtwjit\fP are active and valid:
the subbuf that was active in \fBFLOWING\fP state continues to flow out,
while the other subbuf is initialized for the new flow just like in
\fBHUNT\fP state.
Accounting for \fBHANDOVER\fP state, each \fBtwjit\fP instance has
a potentially valid write subbuf and a potentially valid read subbuf,
breaking down as follows:
.IP \(bu
In \fBEMPTY\fP state, there is neither a valid write subbuf nor a valid
read subbuf;
.IP \(bu
In \fBHUNT\fP state, there is a valid write subbuf, but no valid read subbuf;
.IP \(bu
In \fBFLOWING\fP state, the sole active subbuf is both the write subbuf
and the read subbuf;
.IP \(bu
In \fBHANDOVER\fP state, the read subbuf and the write subbuf are different,
and each is valid.
.LP
Once \fBHANDOVER\fP state has been entered, the code path that handles
incoming RTP packets operates like it does in \fBHUNT\fP state,
while the output path that executes on ticks of the fixed timing system
operates like it does in \%\fBFLOWING\fP, each operating on its
respective subbuf.
There are two possible exit conditions from this state:
.IP 1)
If the new write subbuf reaches ready state (the same criterion as applied
for transition from \fBHUNT\fP to \fBFLOWING\fP, covered in \(sc2.3.3)
before the old read subbuf underruns,
the \fBtwjit\fP instance transitions from \fBHANDOVER\fP back into
\fBFLOWING\fP state.
Any packets that remain in the old read subbuf are discarded, and the new
write subbuf becomes the sole active subbuf for both reading and writing.
.IP 2)
If the old read subbuf underruns before the new write subbuf is ready
to start flowing out,
a handover underrun occurs (same as a regular underrun, but increments
a different stats counter) and \fBtwjit\fP state transitions to \fBHUNT\fP.
This handover underrun will occur if the new write subbuf does not become
ready quickly enough, as the old read subbuf no longer receives any
new packets in \fBHANDOVER\fP state.
.NH 3
Handling of RTP marker bit
.PP
This feature of \fBosmo_twjit\fP does not originate from Themyscira
and is not present in \fCtwrtp\-native\fP version,
instead it was added to the Osmocom-integrated version of this library
per request of Osmocom reviewers.
Vty configuration parameter \fCmarker\-handling\fP controls how
\fBosmo_twjit\fP should react to incoming RTP packets that have
\fBM\fP bit set.
The two possible settings are \fChandover\fP and \fCignore\fP:
.IP \(bu
If \fCmarker\-handling\fP is set to \fChandover\fP, received
packets with \fBM\fP bit set are treated like SSRC changes:
if the previous state was \%\fBFLOWING\fP, the state of \fBosmo_twjit\fP
instance transitions to \%\fBHANDOVER\fP.
.IP \(bu
If \fCmarker\-handling\fP is set to \fCignore\fP, incoming marker bits
are ignored just like in \fCtwrtp\-native\fP version used by ThemWi
network elements.
.NH 3
Additional notes
.LP
Some additional notes about \fBtwjit\fP design that don't fit anywhere else:
.IP \(bu
Neither the payload type nor any of payload content are checked by \fBtwjit\fP:
all payload handling is the responsibility of the application.
.IP \(bu
RTP packets with zero-length payloads are treated as no different from
other valid packets; such packets may be needed to ensure continuous
streaming, as covered in \(sc1.2.1.
.IP \(bu
Only SSRC and timestamp fields in the RTP header (and possibly the marker bit)
are considered for the purpose of mapping received RTP packets to ticks
of the fixed timing system on the output of \fBtwjit\fP.
The sequence number field is examined only for analytics (see Chapter\ 3),
but not for actual operation.
.NH 2
Summary of configuration parameters
.PP
Applications that use \fBtwjit\fP, usually as part of \fBtwrtp\fP,
are expected to also use Osmocom vty system for configuration.
All tunable configuration parameters for \fBtwjit\fP are gathered into
a config structure, named \%\fCstruct\ osmo_twjit_config\fP in
the present Osmocom-integrated version;
this config structure must be provided every time a \fBtwjit\fP instance
is created.
Every application that uses \fBtwrtp\fP with \fBtwjit\fP is expected
to maintain one or more of these config structures, accessible
to tuning via vty.
Multiple \fBtwjit\fP configuration parameter sets in one application
may be needed if the application creates different kinds of RTP endpoints
that may need different \fBtwjit\fP tunings:
for example, \&\fCtw\-border\-mgw\fP has one \fBtwjit\fP configuration
parameter set for GSM RAN side and another for IP-PSTN side.
Vty configuration for \fBtwjit\fP looks like this
(excerpt from \&\fCtw\-border\-mgw.cfg\fP):
.DS
.ft C
.tr -\-
twjit-gsm
 buffer-depth 2 4
 thinning-interval 17
 max-future-sec 10
twjit-pstn
 buffer-depth 2 4
 thinning-interval 17
 max-future-sec 10
.ft
.DE
.tr --
.LP
All numbers in the example above are defaults for the respective settings.
Individual settings are as follows:
.IP \(bu
\&\fCbuffer\-depth\fP line controls the flow-starting fill level (first number)
and the high water mark fill level (second number), parameters that affect
the amount of latency added by \fBtwjit\fP in return for tolerance to jitter
and longer-term variations in IP network path delay.
The flow-starting fill level is described in detail in \(sc2.3.3;
the high water mark fill level is described in \(sc2.3.4.2.
.IP \(bu
\&\fCthinning\-interval\fP setting controls the interval at which quantum
units are deleted from the received stream when the standing queue
thinning mechanism kicks in \(em see \(sc2.3.4.2 for the detailed description.
.IP \(bu
\&\fCmax\-future\-sec\fP setting adjusts the guard against time traveler
packets, described in detail in \(sc2.3.4.3.
.IP \(bu
\&\fCstart\-min\-delta\fP and \&\fCstart\-max\-delta\fP optional settings
(each can be set or unset)
allow the managing operator to set additional timing constraints
that need to be met in order to start a new flow: see \(sc2.3.3.2
for full details.
.IP \(bu
\&\fCmarker\-handling\fP setting is described in \(sc2.3.8.
.NH 1
Stats and analytics
.PP
Every \fBtwjit\fP instance maintains a set of statistical counters,
collected into \&\fCstruct\ osmo_twjit_stats\fP in the present
Osmocom-integrated version.
The purpose of these counters is to assist network operations staff:
applications that use \fBtwrtp\fP with \fBtwjit\fP are expected
to provide vty introspection commands that display these statistical
counters in real time for ongoing calls or connections,
and then log any non-zero counters at call completion.
Implementors of new applications are encouraged to examine the source
for \%\fCtw\-border\-mgw\fP or \%\fCtw\-e1abis\-mgw\fP,
C modules named \%\fCend_stats.c\fP and \%\fCintrospect.c\fP,
for an example of how these functions should be implemented.
.PP
The rest of this chapter provides a description of every counter
in \fBtwjit\fP stats structure.
.NH 2
Normal operation counters
.PP
The following counters record events that are expected to occur in
normal operation, in the absence of any errors or adverse conditions:
.sp .3
.de St
.IP \fC\\$1\fP 22
..
.St rx_packets
This counter increments for every packet that was fed to \fBtwjit\fP input
and passed the basic RTP header validity check.
.St delivered_pkt
This counter increments for every packet that was pulled from the head of
a read subbuf for delivery to the fixed timing application
on the output side of \fBtwjit\fP.
.St handovers_in
This counter increments when \fBtwjit\fP state transitions from
\fB\%FLOWING\fP into \fB\%HANDOVER\fP, as described in \(sc2.3.7.
.St handovers_out
This counter increments when \fBtwjit\fP state transitions from
\fB\%HANDOVER\fP back to \fB\%FLOWING\fP \fIwithout\fP incurring a handover
underrun first, i.e., when the new (post-handover) packet flow becomes ready
to flow out before the old one underruns.
.St marker_resets
This counter increments when a packet is received with \fBM\fP bit set
other than in \fB\%EMPTY\fP state,
and this \fBosmo_twjit\fP instance is configured to treat it as a flow reset,
causing a handover or a reset of flow acquisition process.
.NH 2
Adverse event counters
.LP
The following counters record events that are undesirable,
but not totally unexpected:
.sp .3
.St too_old
This counter increments when an RTP packet received in \fBFLOWING\fP state
has a timestamp that precedes the active subbuf's \&\fChead_ts\fP.
This event can only occur if some packet reordering took place, such that
an earlier-sent packet arrived later than a later-sent one,
or if the buffer is in ``pre-underrun'' state (see \(sc2.3.4.1)
and the very last RTP packet that just flowed out is duplicated.
.St underruns
This counter increments when a \fBFLOWING\fP state underrun occurs,
followed by reception of
at least one post-underrun RTP packet that is then treated as the beginning
of a new flow \(em see \(sc2.3.4.1.
.St ho_underruns
This counter increments when an underrun occurs in \fBHANDOVER\fP state,
i.e., when the previous flow underruns before the new one is ready to
start flowing out.
.St output_gaps
This counter increments for every gap in the output stream from \fBtwjit\fP
that occurs in \fBFLOWING\fP or \fBHANDOVER\fP state \fIwithout\fP an underrun,
i.e., with the flow still continuing and further queued packets present
past the gap.
.St thinning_drops
This counter increments when the standing queue thinning mechanism
described in \(sc2.3.4.2 deletes a quantum from the stream delivered
to the application on the output of \fBtwjit\fP.
Please note that \&\fCdelivered_pkt\fP or \&\fCoutput_gaps\fP
is still incremented for the quantum that is pulled from the read subbuf,
but then artificially deleted by the thinning mechanism.
.NH 2
Error counters
.LP
The following counters record truly unusual and unexpected error events:
.sp .3
.St bad_packets
This counter increments when a packet that was fed to \fBtwjit\fP input
is too short for RTP (shorter than the minimum RTP header length of 12 bytes)
or has an unknown value in the RTP version field.
.St duplicate_ts
This counter increments when \fBtwjit\fP attempts to add a newly received
RTP packet to the active-for-write subbuf, but a previous packet is already
held with the same timestamp and thus at the same depth position.
For the sake of implementation simplicity in this error case that should not
occur in a correctly working system, \fBtwjit\fP drops the new packet
and keeps the old one.
.NH 2
Independent analytics
.PP
In addition to its main function of mapping received RTP packets
to ticks of the fixed timing system on its output,
\fBtwjit\fP performs some ``raw'' analytics on the stream of RTP packet
it receives.
These analytic steps are independent of \fBtwjit\fP algorithm details,
of any configuration settings summarized in \(sc2.4, and
independent of what happens on the output (fixed timing) side of \fBtwjit\fP
\(em thus they bear no direct relation to \fBtwjit\fP state transitions,
subbuf conditions and so forth.
Instead these analytics depend only on the shape of the incoming RTP stream
itself, same as if an analyst were looking at a pcap file after the fact.
Some of these analytic steps are performed in order to gather information
for the purpose of generating RTCP reception report blocks
(see Chapter\ 5),
but some simple analytic steps are done solely to produce some additional
stats counters that are expected to be valuable to network operations staff.
The following counters are maintained as part of these independent analytics:
.sp .3
.St ssrc_changes
This counter increments when the received RTP stream exhibits a change of SSRC,
or more precisely, every time an RTP packet arrives whose SSRC differs from
that of the packet received just prior.
.LP
All following counters record events that occur within a same-SSRC substream:
.sp .3
.St seq_skips
This counter increments every time a packet is received whose sequence number
increment (over the packet received just prior) is positive and greater than 1.
Such occurrence indicates either packet loss or reordering in the IP network.
.St seq_backwards
This counter increments every time a packet is received whose sequence number
goes backward, relative to the packet received just prior.
Such occurrence indicates packet reordering in the IP network.
.St seq_repeats
This counter increments every time a packet is received whose sequence number
is the same as the packet received just prior.
Such occurrence indicates packet duplication somewhere.
.St intentional_gaps
This counter increments every time a packet is received whose sequence number
increments by 1 over the packet received just prior,
indicating no packet loss or reordering at the hands of the transited
IP network,
the timestamp increment is positive and an integral multiple of the
samples-per-quantum constant,
but this increment does not equal exactly one quantum.
Such occurrence indicates that the RTP stream sender emitted
an intentional gap.
.St ts_resets
This counter increments every time a packet is received whose sequence number
increments by 1 over the packet received just prior,
but the timestamp relation between this packet and the previous one
is neither the expected single quantum increment
nor an increment of multiple quanta consistent with an intentional gap.
.St jitter_max
This reporting variable is not a counter, but a quantitative measure.
It reports the highest interarrival jitter that was encountered within
the present same-SSRC substream, measured as prescribed by RFC\ 3550:
the absolute value of the difference between the timestamp delta
of two adjacently-received packets and the \(*D in time of arrival,
converted from seconds and nanoseconds to RTP timestamp units.
.NH 1
RTP endpoint functionality
.PP
The previous two chapters covered \fBtwjit\fP, the jitter buffer component
of ThemWi RTP endpoint implementation.
However, this \fBtwjit\fP layer is not expected to be used directly
by applications: an application that needs to implement an RTP endpoint
will need an endpoint implementation that actually sends and receives
RTP packets, and possibly RTCP as well.
The top layer of ThemWi RTP endpoint library, named \fBtwrtp\fP,
provides this functionality.
.PP
This chapter describes the API to \fBosmo_twrtp\fP, the version of
\fBtwrtp\fP layer that has been integrated into \fClibosmo\-netif\fP.
.NH 2
Endpoint life cycle
.PP
Every \fBtwrtp\fP endpoint is represented by opaque \&\fCstruct\ osmo_twrtp\fP,
which is a talloc context.
These endpoints are created with \&\fCosmo_twrtp_create()\fP and freed
with \&\fCosmo_twrtp_destroy()\fP.
Every \fBtwrtp\fP instance (\&\fCstruct\ osmo_twrtp\fP) owns
the two UDP sockets that are bound to RTP and RTCP ports,
their corresponding \&\fCstruct\ osmo_io_fd\fP instances,
the subordinate \fBtwjit\fP instance if one exists,
and any buffered packets.
All of these resources are released upon \&\fCosmo_twrtp_destroy()\fP.
.NH 2
Supplying UDP sockets for RTP and RTCP
.PP
For every \fBtwrtp\fP endpoint, there is one file descriptor referring
to the UDP socket to be used for RTP, and another file descriptor
referring to the UDP socket to be used for RTCP.
How do these UDP sockets and file descriptors come into being?
Two ways are supported:
.IP 1)
In self-contained Osmocom applications where \fBtwrtp\fP is to be made
available as an alternative to Belledonne \fBortp\fP,
as well as \%\fCtw\-e1abis\-mgw\fP fitting in the place of OsmoMGW-E1,
\&\fCosmo_twrtp_bind_local()\fP (or its \fCtwrtp\-native\fP equivalent
in the case of \%\fCtw\-e1abis\-mgw\fP) creates both sockets and binds them
to a specified IP:port address, supporting both IPv4 and IPv6
and automatically incrementing the port number by 1 for RTCP.
.IP 2)
In Themyscira Wireless CN environment, there is a separate daemon process
that manages the pool of local UDP ports for RTP+RTCP pairs,
and that daemon passes allocated sockets to its clients
via UNIX domain socket file descriptor passing mechanism.
A network element that uses this mechanism will receive a pair of
file descriptors for already-bound UDP sockets from \&\fCthemwi\-rtp\-mgr\fP;
these two already-allocated and already-bound UDP socket
file descriptors are then passed to a dedicated \fBtwrtp\fP API function.
In \fCtwrtp\-native\fP this API function is \&\fCtwna_twrtp_supply_fds()\fP;
the present Osmocom-integrated version provides an equivalent in the form of
\&\fCosmo_twrtp_supply_fds()\fP.
.LP
Either way, the two UDP sockets and their file descriptors
are then owned by the containing \fBtwrtp\fP instance, and will be closed
upon \&\fCosmo_twrtp_destroy()\fP.
.NH 2
RTP remote address
.PP
The two UDP sockets for RTP and RTCP always remain unconnected
at the kernel level \(em instead the notion of the remote peer address
is maintained by \fBtwrtp\fP library.
This remote address needs to be set with \&\fCosmo_twrtp_set_remote()\fP;
until it is set, no RTP or RTCP packets can be sent or received.
Once the remote address is set, the library will send outgoing RTP and RTCP
packets to the correct destination,
and the same remote address is also used to filter incoming packets:
incoming RTP and RTCP packets are accepted only if the UDP source address
matches the currently set remote peer.
This remote peer address can be changed as needed throughout
the lifetime of the RTP endpoint.
.NH 2
RTP receive path
.PP
Applications using \fBtwrtp\fP can receive incoming RTP packets in two ways:
with or without \fBtwjit\fP.
Every application that uses \fBtwrtp\fP must decide, at the time of endpoint
creation via \&\fCosmo_twrtp_create()\fP,
whether or not this endpoint should be equipped with \fBtwjit\fP;
if a \fBtwjit\fP instance is needed along with \fBtwrtp\fP,
the application must provide a \&\fCstruct\ osmo_twjit_config\fP
\(em see \(sc2.4.
.PP
API functions for receiving incoming RTP traffic via \fBtwjit\fP, namely
\&\fCosmo_twrtp_twjit_rx_ctrl()\fP and \&\fCosmo_twrtp_twjit_rx_poll()\fP,
can be used only on \fBtwrtp\fP endpoints that were created with \fBtwjit\fP
included \(em
however, the other RTP Rx API, namely \&\fCosmo_twrtp_set_raw_rx_cb()\fP
for non-delayed unbuffered Rx path, is available with all \fBtwrtp\fP
endpoints.
Applications are allowed to mix \fBtwjit\fP and raw Rx paths:
if a raw Rx callback is set, that callback function is called first
for every received packet, and it can either consume the \fBmsgb\fP
passed to it, or leave it alone.
If the callback function returns \fBtrue\fP, indicating that it consumed
the \fBmsgb\fP, \fBtwrtp\fP Rx processing ends there;
if it returns \fBfalse\fP, or if there is no raw Rx callback installed,
then the packet is passed to \fBtwjit\fP if present and enabled,
otherwise it is discarded.
.PP
The ability to use both \fBtwjit\fP and the non-delayed unbuffered Rx path
at the same time is particularly useful for speech transcoder implementations
that support AMR codec on the RAN side:
such TC will use \fBtwjit\fP to feed the incoming RTP stream
to the speech decoder function that runs on fixed timing, but the
non-delayed Rx path can also be used to ``peek'' at received RTP packets
as they come in and extract the CMR field \(em to be fed to the speech
encoder element, which is separate from the speech decoder fed via \fBtwjit\fP.
.NH 2
RTP Tx output
.PP
The primary purpose of \fBtwrtp\fP library is to facilitate
implementation of bidirectional interfaces
between an RTP stream and a fixed timing system such as
GSM Um TCH or T1/E1 TDM.
Most of the work is in receiving the incoming RTP stream
and mapping incoming RTP packets to ticks of the fixed timing system,
as covered in Chapter\ 2 \(em however, output from the fixed timing system
to RTP also requires some consideration.
.NH 3
Choice of output SSRC
.PP
A random Tx SSRC is assigned to each \fBtwrtp\fP endpoint when it is
created with \&\fCosmo_twrtp_create()\fP.
No loop detection or SSRC collision logic is implemented:
if it so happens that both ends of the RTP link pick the same SSRC,
no adverse effects will occur for \fBtwrtp\fP.
If the foreign RTP implementation on the other end does object
to SSRC collisions and applies some logic along the lines of
RFC\ 3550 \(sc8.2, it is welcome to change its SSRC:
on \fBtwrtp\fP receiving end such incoming SSRC changes will be treated
by \fBtwjit\fP like any other handover.
However, the SSRC emitted by the local \fBtwrtp\fP end will remain
the same throughout the lifetime of the endpoint.
.NH 3
Starting, stopping and restarting Tx flow
.PP
The initial Tx flow is established when the application calls
\&\fCosmo_twrtp_tx_quantum()\fP for the first time on a given endpoint.
At this point the initial RTP timestamp for this Tx flow is set,
based on the current UTC time (CLOCK_REALTIME) reading plus an
optional random addend.
The current UTC reading at the moment of Tx flow start is used,
rather than a purely random number, for consistency with timestamp
computation in the case of restart, as we shall see momentarily.
Once the flow is started in this manner,
the application must commit to calling \&\fCosmo_twrtp_tx_quantum()\fP
or \&\fCosmo_twrtp_tx_skip()\fP every 20\ ms without fail;
each of those calls will increment the timestamp by the samples-per-quantum
constant, usually 160.
.PP
If this Tx flow continues uninterrupted for the lifetime of the RTP
endpoint, the receiving end will see a timestamp increment of one quantum
in every successive packet, forming a perfectly continuous flow.
In this case the starting absolute value of the RTP timestamp does not
matter at all; the UTC-based starting timestamp derivation used by \fBtwrtp\fP
is indistinguishable from a random number.
But what if the sending endpoint needs to interrupt and then restart
its output?
.PP
A dedicated mechanism is provided for such restarts after interruption.
If an application stops emitting packets via \&\fCosmo_twrtp_tx_quantum()\fP
but later restarts, it must call \&\fCosmo_twrtp_tx_restart()\fP any time
between the last quantum Tx call of the old flow and the first such call
of the new flow.
When \&\fCosmo_twrtp_tx_quantum()\fP is called with the internal restart
flag set, a timestamp reset is performed.
The new timestamp is computed from the current UTC reading just like
on initial Tx start, but then the resulting delta relative to timestamps
of the previous flow is checked, and the new timestamp may be adjusted
so that the timestamp increment seen by the remote peer is always positive
per 32-bit timestamp wraparound rules, and is \fBnot\fP an integral multiple
of the samples-per-quantum constant.
The resulting effect is that the far end will see a discontinuity which
\fBtwjit\fP would treat as a handover, yet the increment of the RTP timestamp
over this discontinuity gap is a best effort approximation of the actual
time difference.
.NH 3
Ability to emit intentional gaps
.PP
As already covered in other parts of this document, Themyscira Wireless
philosophy is opposed to the practice of intentional gaps in an RTP stream,
and \fBtwjit\fP receiver performs suboptimally in the presence of such.
However, \fBtwrtp\fP must be able to function as a drop-in replacement
for Belledonne \fBortp\fP library in the context of OsmoBTS application;
OsmoBTS defaults to intentional gaps unless
\&\fCrtp\ continuous\-streaming\fP vty option is set.
Therefore, \fBtwrtp\fP library provides the necessary support for
emitting intentional gaps: it is \&\fCosmo_twrtp_tx_skip()\fP function.
.NH 3
Setting RTP marker bit
.PP
In an environment that uses continuous streaming (no intentional gaps),
Themyscira recommendation is to set \fBM\fP bit to 1 on the very first
emitted RTP packet and on the first packet following a restart
(induced discontinuity), and set it to 0 on all other packets.
To produce this behavior with \fBtwrtp\fP, pass the first two Boolean
arguments to \&\fCosmo_twrtp_tx_quantum()\fP as \fBfalse\fP and \fBtrue\fP.
For other policies with respect to setting the \fBM\fP bit
(for example, as would be needed when using \fBtwrtp\fP in the place of
\fBortp\fP in OsmoBTS),
see \&\fCosmo_twrtp_tx_quantum()\fP API documentation.
.NH 2
No-delay forwarding between RTP endpoints
.PP
The present library supports building applications that forward RTP
packets from one \fBtwrtp\fP endpoint to another without passing through
\fBtwjit\fP and thus without adding buffering delay.
To establish such a shortcut path, register a raw (unbuffered) RTP
receiver on one endpoint via \&\fCosmo_twrtp_set_raw_rx_cb()\fP,
and in that callback function, pass the \fBmsgb\fP to
\&\fCosmo_twrtp_tx_forward()\fP.
Such cross-connect may be applied in one or both directions as needed.
.PP
Each endpoint that is involved in such cross-connection can switch
at any time between forwarding packets as just described and
emitting internally generated in-band tones or announcements;
the latter should be emitted with \&\fCosmo_twrtp_tx_quantum()\fP,
and be sure to also call \&\fCosmo_twrtp_tx_restart()\fP between
separate episodes of locally generated output.
The receiving RTP end will see handover events as SSRC switches between
the one emitted by \fBtwrtp\fP and the one coming from the other remote party.
Actual timing will also switch, as there is no realistic way that your own
20\ ms timing for announcement playout will exactly match the timing of the
RTP stream switched from the other remote party.
.NH 1
Support for RTCP
.PP
ThemWi RTP endpoint library includes a built-in receiver and parser
for RTCP packets: it knows how to parse SR and RR packets, it extracts
information from RTCP reception report blocks that may be useful
to the application,
and it saves information from the sender info portion of SR packets
for use in generating its own reception report blocks.
The library also includes a facility for generating its own RTCP packets,
either SR or RR,
using information from \fBtwjit\fP to fill out the reception report block.
This chapter describes all library facilities related to RTCP,
across both \fBtwrtp\fP and \fBtwjit\fP layers.
.NH 2
Collection of RR info in twjit
.PP
The analytic function of \fBtwjit\fP, described in \(sc3.4, collects
not only the set of statistical counters described in that section,
but also a set of info for the purpose of generating RTCP reception reports.
In the present version of \fBtwrtp\fP and \fBtwjit\fP,
these tidbits are collected into \&\fCstruct\ osmo_twjit_rr_info\fP;
this structure is to be retrieved from a \fBtwjit\fP instance
via \&\fCosmo_twjit_get_rr_info()\fP.
RTCP sender function in the upper layer of \fBtwrtp\fP uses this RR info
structure to fill out the reception report block.
.NH 2
RTCP receiver in twrtp
.PP
Every packet that arrives at a \fBtwrtp\fP endpoint's RTCP port,
coming from the correct source address that matches the current remote peer,
is parsed by the library.
The parser captures SR and RR information; since these two groups of data
are captured for different purposes, they are best studied separately.
.NH 3
Extraction of SR info from received RTCP packets
.PP
If the received RTCP packet is a correctly formed SR packet per
RFC\ 3550 \(sc6.4.1, \fBtwrtp\fP notes that an SR packet was received,
captures the local time (CLOCK_MONOTONIC) of its arrival,
notes the SSRC of the SR sender,
and saves the middle 32 bits of the 64-bit NTP timestamp in the SR.
This saved information will be used later if and when this \fBtwrtp\fP
instance generates its own reception report.
.NH 3
Extraction of RR info from received RTCP packets
.PP
If the received RTCP packet is either SR or RR (either packet type
is allowed to carry anywhere from 0 to 31 reception report blocks),
the RTCP receiver in the library checks every included RR block
to see if it describes our Tx SSRC, i.e., the one that was assigned
as described in \(sc4.5.1.
If such SSRC-matching RR block is seen, \fBtwrtp\fP sets a flag noting so,
and captures two words of useful info from the report: the word describing
packet loss and the word that expresses interarrival jitter.
Both words are described in RFC\ 3550 \(sc6.4.1.
These words are captured for retrieval by the application,
to be made accessible for vty introspection and logged upon call completion,
along with locally collected stats as described in Chapter\ 3.
.NH 2
Emitting RTCP packets
.LP
The library is capable of generating 3 forms of RTCP packet:
.IP \(bu
SR packet containing a single RR block;
.IP \(bu
SR packet containing no RR block;
.IP \(bu
RR packet containing a single reception report block.
.LP
The following sections describe how these RTCP packets
may be generated and emitted.
.NH 3
Setting SDES strings
.PP
RFC\ 3550 \(sc6.1 stipulates that every RTCP SR or RR packet also
needs to include an SDES block, containing at least a CNAME string.
These SDES strings (the mandatory CNAME and any optional ones)
are set with \&\fCosmo_twrtp_set_sdes()\fP API function;
the application must call this function before any SR or RR packets
can be emitted.
.NH 3
Emitting SR packets
.PP
In this library implementation, SR packets can be emitted in only one path:
together with locally generated (not forwarded) RTP data output,
as a result of the application calling \&\fCosmo_twrtp_tx_quantum()\fP.
There are two ways to cause \&\fCosmo_twrtp_tx_quantum()\fP to emit
RTCP SR in addition to its regular RTP data packet carrying
its normally emitted quantum of media:
.IP \(bu
The application can call \&\fCosmo_twrtp_set_auto_rtcp_interval()\fP
and thus configure the library to automatically emit an RTCP SR packet
after every so many regular RTP data packets sent via
\&\fCosmo_twrtp_tx_quantum()\fP.
.IP \(bu
The application can control directly which calls to
\&\fCosmo_twrtp_tx_quantum()\fP should emit RTCP SR via the last Boolean
argument to this function.
.LP
Whichever condition is used to trigger emission of RTCP SR packet,
the decision as to whether or not this SR packet will include an RR block
in addition to the required sender info is made by the library.
This RR block will be included if and only if:
.IP a)
this \fBtwrtp\fP instance is equipped with \fBtwjit\fP, and
.IP b)
at least one valid RTP packet has been received by this \fBtwjit\fP instance,
producing the necessary SSRC-keyed RR info structure.
.LP
The first 3 words in the RR block (the packet loss word,
extended highest sequence number received and interarrival jitter)
are always filled based on the info provided by \fBtwjit\fP via
\&\fCstruct\ osmo_twjit_rr_info\fP.
However, the last 2 words (LSR and DLSR) are filled based on info
captured by \fBtwrtp\fP layer's RTCP receiver, as described in \(sc5.2.1.
If an SR was previously received by this \fBtwrtp\fP endpoint
and the sender of that SR had the same SSRC as the one for which
we are producing our reception report
(the SSRC in \&\fCstruct\ osmo_twjit_rr_info\fP),
then information from that received SR
(its time of arrival and saved NTP timestamp bits)
is used to fill LSR and DLSR words in the generated RR block.
Otherwise, these two words are set to 0.
.NH 3
Emitting standalone RR packets
.PP
In most RTCP-enabled RTP applications, it is most useful to emit SR packets
and convey reception report blocks as part of them.
However, \fBtwrtp\fP library also provides a way to emit standalone RR
packets, which can be useful for applications that receive RTP via \fBtwjit\fP
but don't send out their own originated RTP traffic.
To generate a standalone RR packet, call \&\fCosmo_twrtp_send_rtcp_rr()\fP.
This operation will succeed only if SDES strings have been set,
if this \fBtwrtp\fP instance is equipped with \fBtwjit\fP, if that \fBtwjit\fP
instance was actually used to receive traffic, and if at least one RTP packet
has been received.
The content of the generated standalone RR packet is exactly the same
as the RR block that is more commonly included in an SR packet,
as described in the previous section.
.NH 2
RTCP support limitations
.PP
RTCP support in \fBtwrtp\fP is subject to the following limitations:
.IP \(bu
Sender reports (SR packets) emitted by \fBtwrtp\fP can only describe
traffic that is generated locally via \&\fCosmo_twrtp_tx_quantum()\fP,
not forwarded traffic that is emitted via \&\fCosmo_twrtp_tx_forward()\fP.
There is no way to generate SR packets at all outside of
\&\fCosmo_twrtp_tx_quantum()\fP.
.IP \(bu
The library can only generate reception reports (either standalone RR packets
or as part of SR packets) for traffic that is received via \fBtwjit\fP,
but not for traffic that is received via non-delayed unbuffered path
\(em see \(sc4.4.
.IP \(bu
The built-in RTCP receiver and parser can only extract potentially useful
RR info (reports of packet loss and interarrival jitter) from far end
reception reports when those far end RRs describe our own Tx SSRC
(see \(sc4.5.1), not some foreign SSRC we forward per \(sc4.6.
.LP
The summary of these limitations is that \fBtwrtp\fP has truly functional
RTCP support only when \fBtwrtp\fP is used to implement a full endpoint,
one that interfaces between RTP and a fixed timing system such as GSM Um TCH,
T1/E1 TDM or a software transcoder that runs on its own CLOCK_MONOTONIC
timerfd time base.
``Light'' RTP endpoints that omit some components of this full endpoint
ensemble will most likely be unable to support RTCP.
.NH 2
Usefulness of RTCP
.PP
In the opinion of \fBtwrtp\fP author, RTCP is most useful in IP-PSTN
environment where RTP traffic is exchanged between peer entities under
different ownership and different administrative control,
traveling across public Internet.
In that environment, proper implementation of RTCP can be seen as
good netizenship: the administrator of one fiefdom can see \fBtwjit\fP stats
(or full pcap when needed for deeper debugging)
on RTP traffic \fIreceived\fP by her queendom, but she can only know if her
outgoing traffic suffers from packet loss or jitter if administrators of
other fiefdoms have configured \fItheir\fP systems to emit RTCP reception
reports.
For this reason, \&\fCtw\-border\-mgw\fP instances at Themyscira MSCs
are configured to dutifully emit RTCP SR (which includes RR block)
on IP-PSTN side
every 5\ s, or after every 250 RTP data packets sent every 20\ ms.
.PP
On the other hand,
RTCP is \fBnot\fP really useful in a single-administration GSM RAN,
i.e., in environments where both ends of the RTP transport leg
are controlled by the same administration.
In Themyscira environment, each GSM-codec-carrying RTP transport leg
runs between \&\fCtw\-border\-mgw\fP or other ThemWi CN components on one end,
located at an MSC site, and either OsmoBTS or \&\fCtw\-e1abis\-mgw\fP
on the other end, located at a cell site, carried across public Internet
in a WireGuard tunnel.
Because transport across public Internet is involved, RTP performance
needs to be closely monitored with an eye out for packet loss, jitter or
even reordering, and \fBtwjit\fP configuration needs to be carefully tuned.
However, direct examination of \fBtwjit\fP stats on both CN and BSS ends
will yield much more detailed information than the constrained data model
of RTCP \(em hence RTCP is not really useful.
.NH 2
Non-RTCP operation
.PP
If \fBtwrtp\fP needs to be used in an environment where RTCP is not needed,
or even one where use of RTCP is forbidden,
nothing special needs to be done to achieve non-RTCP operation.
No RTCP packets will be emitted if the application never calls
\&\fCosmo_twrtp_set_sdes()\fP;
any received RTCP packets will still be parsed as described in \(sc5.2,
but the existence of saved bits from this parsing can be simply ignored.
RR info from \fBtwjit\fP, collected as described in \(sc5.1, can be
likewise ignored.
.PP
As an additional feature in \fBosmo_twrtp\fP, it is also possible to
disable RTCP completely by not binding a UDP socket for the odd-numbered
RTCP port and not having an active file descriptor or
\%\fCstruct\ osmo_io_fd\fP for it.
Referring to \(sc4.2 for socket binding or file descriptor initialization
procedures, such non-RTCP operation can be achieved by passing \fBfalse\fP
as the last Boolean argument to \%\fCosmo_twrtp_bind_local()\fP or by
passing a negative RTCP file descriptor to \%\fCosmo_twrtp_supply_fds()\fP.
.NH 1
Stats at twrtp level
.PP
In addition to \fBtwjit\fP stats counters described in Chapter\ 3,
\fBtwrtp\fP layer has its own stats structure with a few additional counters,
dealing with both RTP and RTCP packets in both Rx and Tx directions.
This stats structure is \%\fCstruct\ osmo_twrtp_stats\fP
in the present Osmocom-integrated version.
Here is a description of all counters in this set:
.sp .3
.de St
.IP \fC\\$1\fP 24
..
.St rx_rtp_pkt
This counter increments for every packet that is received on the RTP UDP
socket \fBand\fP has a source address that matches the current remote peer
set with \%\fCosmo_twrtp_set_remote()\fP.
.St rx_rtp_badsrc
This counter counts packets that were received on the RTP UDP socket,
but then discarded because their source address was wrong.
.St rx_rtcp_pkt
This counter increments for every packet that is received on the RTCP UDP
socket \fBand\fP has a source address that matches the current remote peer
set with \%\fCosmo_twrtp_set_remote()\fP.
.St rx_rtcp_badsrc
This counter counts packets that were received on the RTCP UDP socket,
but then discarded because their source address was wrong.
.St rx_rtcp_invalid
This counter counts packets that were received on the RTCP UDP socket,
passed the source address check, but were deemed invalid in parsing.
.St rx_rtcp_wrong_ssrc
This counter increments for every parsed reception report block within
a received RTCP SR or RR packet that describes an SSRC other than
our Tx SSRC of \(sc4.5.1.
.St tx_rtp_pkt
This counter increments for every RTP data packet emitted via
\%\fCosmo_twrtp_tx_quantum()\fP;
it is also emitted in RTCP SR packets in the ``sender's packet count'' word.
Packets transmitted via \%\fCosmo_twrtp_tx_forward()\fP are \fBnot\fP
counted here; as explained in \(sc5.4, there is no RTCP support in \fBtwrtp\fP
for this path.
.St tx_rtp_bytes
This counter counts payload bytes transmitted via
\%\fCosmo_twrtp_tx_quantum()\fP;
it is also emitted in RTCP SR packets in the ``sender's octet count'' word.
Just like \%\fCtx_rtp_pkt\fP, this counter is not affected by
\%\fCosmo_twrtp_tx_forward()\fP path.
.St tx_rtcp_pkt
This counter increments for every RTCP packet emitted by this
\fBtwrtp\fP instance.
