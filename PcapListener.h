#ifndef PCAP_LISTENER_H
#define PCAP_LISTENER_H

#include <pcap.h>
#include <string>

#include "Stats.h"

class PcapListener 
{
public:
  PcapListener();
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
  void ProcessPacket( const pcap_pkthdr* pktHdr, const u_char* pktData );
  void IncrementStats( Stats& stat, const pcap_pkthdr* pktHdr ) const;
  int GetDropCount();
  void PrintStats( const timeval& ts, const int dropCount );

  pcap_t* _pcapFd = nullptr;
  StatsCollection _stats;
};


#endif 
