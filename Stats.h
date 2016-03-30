#ifndef STATS_H
#define STATS_H

#include <sys/time.h>

#include <cstring>
#include <limits>

constexpr static int STAT_INTERVAL_SECONDS = 10; // 10s print stat interval

struct Stats
{
  // packet size measurements
  int min;
  int max;
  int total;
  
  // packet count
  int count;
  // TODO: if 1 second intervals is not granular enough, we can increase the
  // array size to achieve more granular measurements. this is interesting in
  // the case of bursts
  int rates[STAT_INTERVAL_SECONDS]; // per second packet rate

  void Reset() 
  {
    min = std::numeric_limits<int>::max();
    max = 0;
    total = 0;
    count = 0;
    memset( rates, 0, sizeof( rates ) ); 
  }
};

struct StatsCollection
{
  // time_t is really just a long int
  time_t baseTime; // seconds since epoch that this collection started
  Stats ip_tcp;
  Stats ip_udp; 
  Stats ip;
  Stats ipv6;  // if there is enough adoption, maybe split ipv6 out into udp/tcp
  Stats total;

  void Reset( const time_t base )
  {
    baseTime = base;
    ip_tcp.Reset();
    ip_udp.Reset();
    ip.Reset();
    ipv6.Reset();
    total.Reset();
  }
};

#endif
