#ifndef PCAP_LISTENER_H
#define PCAP_LISTENER_H

#include <pcap.h>
#include <string>
#include <limits>

class PcapListener 
{
public:
  PcapListener() = default;
  ~PcapListener();

  /** 
   * Start will create and activate pcap listening on the default device 
   * input: string representation of interface to capture packets
   * return: true if successful, false if failed to start listening process
   * output: prints errors to stderr
   **/
  bool Start( const std::string& iface );

  /**
   * Process will read the next packet (blocking) from the capture and update the
   * stats
   **/
  void Process();

private:
  constexpr static int STAT_INTERVAL_SECONDS = 10; // 10s print stat interval

  struct Stats
  {
    // packet size measurements
    int min = std::numeric_limits<int>::max();
    int max = 0;
    int total = 0;
    
    // packet count
    int count = 0;
    // TODO: if 1 second intervals is not granular enough, we can increase the
    // array size to achieve more granular measurements. this is interesting in
    // the case of bursts
    int rates[STAT_INTERVAL_SECONDS] = {0}; // per second packet rate
  };

  struct StatsCollection
  {
    // time_t is really just a long int
    time_t baseTime = 0; // seconds since epoch that this collection started
    Stats ip_tcp;
    Stats ip_udp; 
    Stats ip;
    Stats ipv6;  // if there is enough adoption, maybe split ipv6 out into udp/tcp
    Stats total;
  };

  void ProcessPacket( const pcap_pkthdr* pktHdr, const u_char* pktData );
  void IncrementStats( Stats& stat, const pcap_pkthdr* pktHdr ) const;
  void ResetStats( const timeval& ts );
  void PrintStats( const timeval& ts );
  void PrintStat( const Stats& stat ) const;

  pcap_t* _pcapFd = nullptr;
  StatsCollection _stats;
  int _pcapDrops = 0;
};


#endif 
