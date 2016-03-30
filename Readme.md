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


## Future work

  * Might be interesting to split out RX/TX
  * For libpcaps that have both ps_drop and ps_ifdrop, would be interesting to see NIC level drops as well as kernel level drops
