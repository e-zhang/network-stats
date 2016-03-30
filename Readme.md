# Network Stats

## sample C++ libpcap program that measures some simple network capture statistics

## Building and Running
  * change CXX in makefile if g++ is not in standard path
  * add to LDFLAGS if libpcap.so is not in standard path
  * make should create NetworkStats
  * run with ./NetworkStats <interface name> 
    * ./NetworkStats eth0 


## Files
  * main.cpp: takes a single argument for interface name
  * PcapListener.h, PcapListener.cpp: 
    * handles wrapping libpcap objects / function calls
    * stores interval stats
    * prints stats every 10 seconds to stdout


## Sample output:

> ======== Tue Mar 29 20:36:50 2016
> 
> Total Stats: 
>
>         packets: 177799
>         min size (bytes): 54
>         max size (bytes): 6022
>         avg size (bytes): 101
>         max rate (pkts/s): 176916
>
> IPv4 Stats: 
>
>         packets: 177793
>         min size (bytes): 54
>         max size (bytes): 6022
>         avg size (bytes): 101
>         max rate (pkts/s): 176912
>
> IPv4 TCP Stats: 
>
>         packets: 7660
>         min size (bytes): 54
>         max size (bytes): 6022
>         avg size (bytes): 169
>         max rate (pkts/s): 7571
>
> IPv4 UDP Stats: 
>
>         packets: 876
>         min size (bytes): 86
>         max size (bytes): 106
>         avg size (bytes): 95
>         max rate (pkts/s): 105
>
> IPv6 UDP Stats: 
>
>         packets: 0
>
> Drops: 16210
> Cumulative Drops: 200171

Some interesting stats to look at per 10 second interval:
  * total packets
  * min/max/avg packet size
  * max rate (stores 10 - 1 second buckets that counts the total number of packets/s to give us more granular packet rates)

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


## Future work

  * Might be interesting to split out RX/TX
  * For libpcaps that have both ps_drop and ps_ifdrop, would be interesting to see NIC level drops as well as kernel level drops
