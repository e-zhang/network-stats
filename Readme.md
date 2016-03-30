# Network Stats

## sample C++ libpcap program that measures some simple network capture statistics

## Building and Running
  * change CXX in makefile if g++ is not in standard path
  * add to LDFLAGS if libpcap.so is not in standard path
  * make should create NetworkStats
  * run with ./NetworkStats <interface name> 
    * ./NetworkStats eth0 
    * must have root permissions
  * tested with GCC 4.9.1 and Centos 6.4


## Files
  * main.cpp: takes a single argument for interface name
  * PcapListener.h, PcapListener.cpp: 
    * handles wrapping libpcap objects / function calls
    * stores interval stats
    * prints stats every 10 seconds to stdout
  * Stats.h:
    * stats objects
    * handles resets and pretty printing individual stats


## Sample output:

>Total Stats:
>
>        packets: 1151311
>        total size (bytes): 1221635596
>        min size (bytes): 54
>        max size (bytes): 2974
>        avg size (bytes): 1061
>        max rate (bytes/s): 319069270
>        max rate (pkts/s): 300598
>
>IPv4 Stats:
>
>        packets: 1151306
>        total size (bytes): 1221635033
>        min size (bytes): 54
>        max size (bytes): 2974
>        avg size (bytes): 1061
>        max rate (bytes/s): 319069150
>        max rate (pkts/s): 300596
>
>IPv4 TCP Stats:
>
>        packets: 1475
>        total size (bytes): 1317808
>        min size (bytes): 54
>        max size (bytes): 2974
>        avg size (bytes): 893
>        max rate (bytes/s): 587122
>        max rate (pkts/s): 519
>
>IPv4 UDP Stats:
>
>        packets: 845
>        total size (bytes): 81083
>        min size (bytes): 82
>        max size (bytes): 243
>        avg size (bytes): 95
>        max rate (bytes/s): 9014
>        max rate (pkts/s): 94
>
>IPv6 UDP Stats:
>
>        packets: 0
>        total size (bytes): 0
>
>Drops: 20969
>Cumulative Drops: 50984
> 

Some interesting stats to look at per 10 second interval:
  * total packets
  * total bytes captured
  * min/max/avg packet size
  * max byte rate (stores 10 - 1 second buckets that counts the total number of bytes/s to give us more granular rates)
  * max packet rate (stores 10 - 1 second buckets that counts the total number of packets/s to give us more granular rates)

Total (all network packets)
  * IPv4 (all ipv4 packets)
   * IPv4 TCP (only ipv4 tcp packets)
   * IPv4 UDP (only ipv4 udp packets)
  * IPv6 traffic

Drops show RX buffer drops in the last interval
Cumulative drops show total RX buffer drops since start of capture

## Inducing Drops

First thing I thought to try was to artifically backup the libpcap reads.
However, even with large sleeps in the consuming threads, the OS did not record
drops. My guess is that even if libpcap could not keep up with consuming the
network capture, the drops would happen at the packet sniffing application level 
and so from the kernels perspective, the actual consuming app didn't drop.

After some googling around, I thought I could try using iptables to simulate
drops. This did work in dropping packets, but again it did not trigger the count
in netstat/ifconfig, so the drops must be happening at a higher level in this
process.

The next I tried was to mess with the socket buffers in sysctl.conf and the
ethtool ring buffers. I turned down the buffers to as small as I could (without
losing my ssh connection). From a separate box, I ran ping in flood mode. With
some tuning with the preload (-l) and packetsize (-s) I managed to force RX drops
on the interface that I captured. 

Turns out, with those ping parameters, I could turn my socket buffers back to
their original values. I had to turn up both number of preload packets and the
packet sizes, but I could still induce RX drops in the kernel with pings.

> ping -f -s 2048 -l 4500


## Future work

  * Might be interesting to split out RX/TX
  * For libpcaps that have both ps_drop and ps_ifdrop, would be interesting to see NIC level drops as well as kernel level drops
