# asuswrt-merlin-xtables

The files in this repo have been copied directly from the [Xtables-addons-1.47.1 source code distribution](https://sourceforge.net/projects/xtables-addons/files/Xtables-addons/xtables-addons-1.47.1.tar.xz/download), and organized into the appropriate Asuswrt-Merlin folder structure, for the purpose of compiling the modules directly into the firmware.  They are kept in a `.tar.gz` archive to preserve the original file timestamps.  All Xtables-addons source files appearing in this repo are original and unmodified.  *A few modules were not included because additional work would be required to get them to compile.*

This repo adds new capabilities to Asuswrt-Merlin for iptables **targets** (CHAOS, DELUDE, RAWSNAT, RAWDNAT, STEAL, TARPIT) and iptables **matches** (fuzzy, iface, ipv4options, lscan, pknock, psd, quota2).  To test this functionality on your Asus router, flash the Blackfuel version of Asuswrt-Merlin.


## Targets

###CHAOS target
Causes confusion on the other end by doing odd things with incoming packets.
CHAOS will randomly reply (or not) with one of its configurable subtargets:

**--delude**  
Use the REJECT and DELUDE targets as a base to do a sudden or deferred
connection reset, fooling some network scanners to return non-deterministic
(randomly open/closed) results, and in case it is deemed open, it is actually
closed/filtered.

**--tarpit**  
Use the REJECT and TARPIT target as a base to hold the connection until it
times out. This consumes conntrack entries when connection tracking is loaded
(which usually is on most machines), and routers inbetween you and the Internet
may fail to do their connection tracking if they have to handle more
connections than they can.

The randomness factor of not replying vs. replying can be set during load-time
of the `xt_CHAOS` module or during runtime in `/sys/modules/xt_CHAOS/parameters`.

See http://jengelh.medozas.de/projects/chaostables/ for more information
about CHAOS, DELUDE and lscan.


###DELUDE target
The DELUDE target will reply to a SYN packet with SYN-ACK, and to all other
packets with an RST. This will terminate the connection much like REJECT, but
network scanners doing TCP half-open discovery can be spoofed to make them
belive the port is open rather than closed/filtered.


###RAWSNAT and RAWDNAT targets
The RAWSNAT and RAWDNAT targets provide stateless network address
translation.

The RAWDNAT target will rewrite the destination address in the IP header,
much like the NETMAP target.

**--to-destination addr[/mask]**  
Network address to map to. The resulting address will be constructed the
following way: All 'one' bits in the mask are filled in from the new
address. All bits that are zero in the mask are filled in from the
original address.

The RAWSNAT target will rewrite the source address in the IP header, much
like the NETMAP target. RAWSNAT (and RAWDNAT) may only be
used in the raw or rawpost tables, but can be used in all chains,
which makes it possible to change the source address either when the packet
enters the machine or when it leaves it. The reason for this table constraint
is that RAWNAT must happen outside of connection tracking.

**--to-source addr[/mask]**  
Network address to map to. The resulting address will be constructed the
following way: All 'one' bits in the mask are filled in from the new
address. All bits that are zero in the mask are filled in from the
original address.

As an example, changing the destination for packets forwarded from an internal
LAN to the internet:
```
-t raw -A PREROUTING -i lan0 -d 212.201.100.135 -j RAWDNAT --to-destination 199.181.132.250;
-t rawpost -A POSTROUTING -o lan0 -s 199.181.132.250 -j RAWSNAT --to-source 212.201.100.135;
```
Note that changing addresses may influence the route selection! Specifically,
it statically NATs packets, not connections, like the normal DNAT/SNAT targets
would do. Also note that it can transform already-NATed connections, as
said, it is completely external to Netfilter's connection tracking/NAT.

If the machine itself generates packets that are to be rawnat'ed, you need a
rule in the OUTPUT chain instead, just like you would with the stateful NAT
targets.

It may be necessary that in doing so, you also need an extra RAWSNAT rule, to
override the automatic source address selection that the routing code does
before passing packets to iptables. If the connecting socket has not been
explicitly bound to an address, as is the common mode of operation, the address
that will be chosen is the primary address of the device through which the
packet would be routed with its initial destination address - the address as
seen before any RAWNAT takes place.


###STEAL target
Like the DROP target, but does not throw an error like DROP when used in the
OUTPUT chain.

###TARPIT target
Adds a TARPIT target to iptables, which captures and holds
incoming TCP connections using no local per-connection resources.
Connections are accepted, but immediately switched to the persist
state (0 byte window), in which the remote side stops sending data
and asks to continue every 60-240 seconds. Attempts to close the
connection are ignored, forcing the remote side to time out the
connection in 12-24 minutes.

This offers similar functionality to LaBrea
<http://www.hackbusters.net/LaBrea/>, but does not require dedicated
hardware or IPs. Any TCP port that you would normally DROP or REJECT
can instead become a tarpit.


## Matches

###FUZZY match
This module matches a rate limit based on a fuzzy logic controller (FLC).

**--lower-limit number**  
Specifies the lower limit, in packets per second.

**--upper-limit number**  
Specifies the upper limit, also in packets per second.

###IFACE match
Allows you to check interface states. First, an interface needs to be selected
for comparison. Exactly one option of the following three must be specified:

**--iface name**  
Check the states on the given interface.

**--dev-in**  
Check the states on the interface on which the packet came in. If the input
device is not set, because for example you are using `-m iface` in the OUTPUT
chain, this submatch returns false.

**--dev-out**  
Check the states on the interface on which the packet will go out. If the
output device is not set, because for example you are using `-m iface` in the
INPUT chain, this submatch returns false.

Following that, one can select the interface properties to check for:

**[!] --up, [!] --down**  
Check the UP flag.

**[!] --broadcast**  
Check the BROADCAST flag.

**[!] --loopback**  
Check the LOOPBACK flag.

**[!] --pointtopoint**  
Check the POINTTOPOINT flag.

**[!] --running**  
Check the RUNNING flag. Do NOT rely on it!

**[!] --noarp, [!] --arp**  
Check the NOARP flag.

**[!] --promisc**  
Check the PROMISC flag.

**[!] --multicast**  
Check the MULTICAST flag.

**[!] --dynamic**  
Check the DYNAMIC flag.

**[!] --lower-up**  
Check the LOWER_UP flag.

**[!] --dormant**  
Check the DORMANT flag.


###IPV4OPTIONS match
The "ipv4options" module allows to match against a set of IPv4 header options.

**--flags [!]symbol[,[!]symbol...]**  
Specify the options that shall appear or not appear in the header. Each
symbol specification is delimited by a comma, and a '!' can be prefixed to
a symbol to negate its presence. Symbols are either the name of an IPv4 option
or its number. See examples below.

**--any**  
By default, all of the flags specified must be present/absent, that is, they
form an AND condition. Use the --any flag instead to use an OR condition
where only at least one symbol spec must be true.

Known symbol names (and their number):

1 nop
2 security RFC 1108
3 lsrr Loose Source Routing, RFC 791
4 timestamp RFC 781, 791
7 record-route RFC 791
9 ssrr Strict Source Routing, RFC 791
11 mtu-probe RFC 1063
12 mtu-reply RFC 1063
18 traceroute RFC 1393
20 router-alert RFC 2113

Examples:

- Match packets that have both Timestamp and NOP:  
  ```
    -m ipv4options --flags nop,timestamp
  ```
- that have either of Timestamp or NOP, or both:  
  ```
    --flags nop,timestamp --any
  ```
- that have Timestamp and no NOP:  
  ```
    --flags '!nop,timestamp'
  ```
- that have either no NOP or a timestamp (or both conditions):  
  ```
    --flags '!nop,timestamp' --any
  ```


###LSCAN match
Detects simple low-level scan attemps based upon the packet's contents.
(This is different from other implementations, which also try to match the rate of new
connections.) Note that an attempt is only discovered after it has been carried
out, but this information can be used in conjunction with other rules to block
the remote host's future connections. So this match module will match on the
(probably) last packet the remote side will send to your machine.

**--stealth**  
Match if the packet did not belong to any known TCP connection
(Stealth/FIN/XMAS/NULL scan).

**--synscan**  
Match if the connection was a TCP half-open discovery (SYN scan), i.e. the
connection was torn down after the 2nd packet in the 3-way handshake.

**--cnscan**  
Match if the connection was a TCP full open discovery (connect scan), i.e. the
connection was torn down after completion of the 3-way handshake.

**--grscan**  
Match if data in the connection only flew in the direction of the remote side,
e.g. if the connection was terminated after a locally running daemon sent its
identification. (E.g. openssh, smtp, ftpd.) This may falsely trigger on
warranted single-direction data flows, usually bulk data transfers such as
FTP DATA connections or IRC DCC. Grab Scan Detection should only be used on
ports where a protocol runs that is guaranteed to do a bidirectional exchange
of bytes.

NOTE: Some clients (Windows XP for example) may do what looks like a SYN scan,
so be advised to carefully use `xt_lscan` in conjunction with blocking rules,
as it may lock out your very own internal network.


###PKNOCK match
Pknock match implements so-called "port knocking", a stealthy system
for network authentication: a client sends packets to selected
ports in a specific sequence (*simple mode*, see example 1 below), or a HMAC
payload to a single port (*complex mode*, see example 2 below),
to a target machine that has pknock rule(s) installed. The target machine
then decides whether to unblock or block (again) the pknock-protected port(s).
This can be used, for instance, to avoid brute force
attacks on ssh or ftp services.

**Example prerequisites:**  
```
modprobe cn

modprobe xt_pknock
```
**Example 1 (TCP mode, manual closing of opened port not possible):**  
```
iptables -P INPUT DROP

iptables -A INPUT -p tcp -m pknock --knockports 4002,4001,4004 --strict --name SSH --time 10 --autoclose 60 --dport 22 -j ACCEPT
```
The rule will allow tcp port 22 for the attempting IP address after the successful reception of TCP SYN packets
to ports 4002, 4001 and 4004, in this order (a.k.a. port-knocking).
Port numbers in the connect sequence must follow the exact specification, no
other ports may be "knocked" inbetween. The rule is named 'SSH', a file of
the same name for tracking port knocking states will be created in
`/proc/net/xt_pknock`.

Successive port knocks must occur with delay of at most 10 seconds. Port 22 (from the example) will
be automatiaclly dropped after 60 minutes after it was previously allowed.

**Example 2 (UDP mode, non-replayable and non-spoofable, manual closing
of opened port possible, secure, also called "SPA" = Secure Port
Authorization):**  
```
iptables -A INPUT -p udp -m pknock --knockports 4000 --name FTP --opensecret foo --closesecret bar --autoclose 240 -j DROP

iptables -A INPUT -p tcp -m pknock --checkip --name FTP --dport 21 -j ACCEPT
```
The first rule will create an "ALLOWED" record in `/proc/net/xt_pknock/FTP` after
the successful reception of an UDP packet to port 4000. The packet payload must be
constructed as a HMAC256 using "foo" as a key. The HMAC content is the particular 
client's IP address as a 32-bit network byteorder quantity,
plus the number of minutes since the Unix epoch, also as a 32-bit value.
(This is known as Simple Packet Authorization, also called "SPA".)
In such case, any subsequent attempt to connect to port 21 from the client's IP
address will cause such packets to be accepted in the second rule.

Similarly, upon reception of an UDP packet constructed the same way, but with
the key "bar", the first rule will remove a previously installed "ALLOWED" state
record from `/proc/net/xt_pknock/FTP`, which means that the second rule will
stop matching for subsequent connection attempts to port 21.
In case no close-secret packet is received within 4 hours, the first rule
will remove "ALLOWED" record from `/proc/net/xt_pknock/FTP` itself.

Things worth noting:

**General:**  

Specifying `--autoclose 0` means that no automatic close will be performed at all.

`xt_pknock` is capable of sending information about successful matches
via a netlink socket to userspace, should you need to implement your own
way of receiving and handling portknock notifications.
Be sure to read the documentation in the `doc/pknock/` directory,
or visit the original site, http://portknocko.berlios.de/.

**TCP mode:**  

This mode is not immune against eavesdropping, spoofing and
replaying of the port knock sequence by someone else (but its use may still
be sufficient for scenarios where these factors are not necessarily
this important, such as bare shielding of the SSH port from brute-force attacks).
However, if you need these features, you should use UDP mode.

It is always wise to specify three or more ports that are not monotonically
increasing or decreasing with a small stepsize (e.g. 1024,1025,1026)
to avoid accidentally triggering
the rule by a portscan.

Specifying the inter-knock timeout with `--time` is mandatory in TCP mode,
to avoid permanent denial of services by clogging up the peer knock-state tracking table
that `xt_pknock` internally keeps, should there be a DDoS on the
first-in-row knock port from more hostile IP addresses than what the actual size
of this table is (defaults to 16, can be changed via the "peer_hasht_ents" module parameter).
It is also wise to use as short a time as possible (1 second) for `--time`
for this very reason. You may also consider increasing the size
of the peer knock-state tracking table. Using `--strict` also helps,
as it requires the knock sequence to be exact. This means that if the
hostile client sends more knocks to the same port, `xt_pknock` will
mark such attempt as failed knock sequence and will forget it immediately.
To completely thwart this kind of DDoS, knock-ports would need to have
an additional rate-limit protection. Or you may consider using UDP mode.

**UDP mode:**  

This mode is immune against eavesdropping, replaying and spoofing attacks.
It is also immune against DDoS attack on the knockport.

For this mode to work, the clock difference on the client and on the server
must be below 1 minute. Synchronizing time on both ends by means
of NTP or rdate is strongly suggested.

There is a rate limiter built into `xt_pknock` which blocks any subsequent
open attempt in UDP mode should the request arrive within less than one
minute since the first successful open. This is intentional;
it thwarts eventual spoofing attacks.

Because the payload value of an UDP knock packet is influenced by client's IP address,
UDP mode cannot be used across NAT.

For sending UDP "SPA" packets, you may use either `knock.sh` or
`knock-orig.sh`. These may be found in `doc/pknock/util`.


###PSD match
Attempt to detect TCP and UDP port scans. This match was derived from
Solar Designer's scanlogd.

**--psd-weight-threshold threshold**  
Total weight of the latest TCP/UDP packets with different
destination ports coming from the same host to be treated as port
scan sequence.

**--psd-delay-threshold delay**  
Delay (in hundredths of second) for the packets with different
destination ports coming from the same host to be treated as
possible port scan subsequence.

**--psd-lo-ports-weight weight**  
Weight of the packet with privileged (<=1024) destination port.

**--psd-hi-ports-weight weight**  
Weight of the packet with non-priviliged destination port.



###QUOTA2 match
The "quota2" implements a named counter which can be increased or decreased
on a per-match basis. Available modes are packet counting or byte counting.
The value of the counter can be read and reset through procfs, thereby making
this match a minimalist accounting tool.

When counting down from the initial quota, the counter will stop at 0 and
the match will return false, just like the original "quota" match. In growing
(upcounting) mode, it will always return true.

**--grow**  
Count upwards instead of downwards.

**--no-change**  
Makes it so the counter or quota amount is never changed by packets matching
this rule. This is only really useful in "quota" mode, as it will allow you to
use complex prerouting rules in association with the quota system, without
counting a packet twice.

**--name name**  
Assign the counter a specific name. This option must be present, as an empty
name is not allowed. Names starting with a dot or names containing a slash are
prohibited.

**[!] --quota iq**  
Specify the initial quota for this counter. If the counter already exists,
it is not reset. An "!" may be used to invert the result of the match. The
negation has no effect when --grow is used.

**--packets**  
Count packets instead of bytes that passed the quota2 match.

Because counters in quota2 can be shared, you can combine them for various
purposes, for example, a bytebucket filter that only lets as much traffic go
out as has come in:
```
-A INPUT -p tcp --dport 6881 -m quota --name bt --grow;
-A OUTPUT -p tcp --sport 6881 -m quota --name bt;
```


# References

**Website:** https://sourceforge.net/projects/xtables-addons/files/Xtables-addons/  
**Download:** https://sourceforge.net/projects/xtables-addons/files/Xtables-addons/xtables-addons-1.47.1.tar.xz/download  

