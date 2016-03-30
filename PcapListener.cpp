#include "PcapListener.h"

#include <net/ethernet.h>
#include <netinet/ip.h>

#include <cassert>
#include <ctime>

PcapListener::PcapListener()
{
  // initialize stats containers
  _stats.Reset( 0, 0 );
}

PcapListener::~PcapListener()
{
  // make sure we clean up the pcap capture handle!
  // TODO: alternatively use a std::unique_ptr with a custom deleter that calls
  // close rather than delete
  if( _pcapFd != nullptr )
  {
    pcap_close( _pcapFd );
  }
}


bool PcapListener::Start( const std::string& iface )
{
  char pcapErrorBuf[PCAP_ERRBUF_SIZE] = { 0 };

  std::cout << "Opening pcap listening on device: " << iface << std::endl;

  // create pcap device
  _pcapFd = pcap_create( iface.c_str(), pcapErrorBuf );

  if( _pcapFd == nullptr )
  {
    std::cerr << "Couldn't create pcap handle: " << pcapErrorBuf << std::endl;
    return false;
  }

  // set snapshot length to something that will allow us to capture the entire
  // packet. per docs, suggest that 64k is usually enough
  int error = pcap_set_snaplen( _pcapFd, 65535 );
  if( error < 0 )
  {
    std::cerr << "Couldn't set snapshot len for pcap handle: " << error << std::endl;
    return false;
  }

  // start live capture
  error = pcap_activate( _pcapFd );
  if( error < 0 )
  {
    std::cerr << "Couldn't activate live capture for pcap handle: " << error << std::endl;
    return false;
  }
  
  // make sure we only have Ethernet headers
  // wifi should be faked with ethernet headers by the network adapter
  if( pcap_datalink( _pcapFd ) != DLT_EN10MB )
  {
    std::cerr << "Capture device isn't Ethernet: " << error << std::endl;
    return false;
  }

  return true;
}

void PcapListener::Process()
{
  // we don't own these, so do not free
  pcap_pkthdr* pktHdr;  
  const u_char* pktData;

  int result = pcap_next_ex( _pcapFd, &pktHdr, &pktData );

  switch( result )
  {
    case 1: // success read
      ProcessPacket( pktHdr, pktData );
      break;
    case 0: // didn't read whole packet / timeout
      break;
    case -1: // read error
      std::cerr << "Pcap capture read error: " << pcap_geterr( _pcapFd ) << std::endl;
      break; 
    default: // should not ever get here during live capture
      assert( false );
      break;
  }
}

void PcapListener::ProcessPacket( const pcap_pkthdr* pktHdr, const u_char* pktData )
{
  // first packet
  if( _stats.baseTime == 0 )
  {
    _stats.baseTime = pktHdr->ts.tv_sec;
  }

  // we've reached our 10 second limit
  // TODO: this essentially is triggered by receiving capture data which should
  // be a pretty good assumption, but in case of rare packet captures, we can
  // always add a timer thread or some signal to print. This would also require
  // us to move to non-blocking reads from libpcap so that we can select between
  // reads and checking time
  if( pktHdr->ts.tv_sec - _stats.baseTime >= STAT_INTERVAL_SECONDS )
  {
    // if printing is too much work, we can also offload the stats struct to a
    // queue and pass it off to a background thread to do the logging
    int dropCount = GetDropCount();
    PrintStats( pktHdr->ts, dropCount );
    _stats.Reset( pktHdr->ts.tv_sec, dropCount );
  }

  // update totals
  IncrementStats( _stats.total, pktHdr );

  if( pktHdr->caplen > sizeof( ether_header ) )
  {
    const auto etherHdr = reinterpret_cast<const ether_header*>( pktData );
    switch( ntohs( etherHdr->ether_type ) )
    {
      case ETHERTYPE_IP:
      {
        // if we have enough data for ip hdr
        if( pktHdr->caplen > sizeof( ether_header ) + sizeof( ip ) )
        {
          const auto ipHdr = reinterpret_cast<const ip*>( pktData + sizeof( ether_header ) );
          switch( ipHdr->ip_p )
          {
            case IPPROTO_TCP:
              IncrementStats( _stats.ip_tcp, pktHdr );
              break;
            case IPPROTO_UDP:
              IncrementStats( _stats.ip_udp, pktHdr );
              break;
            default: break;
          }
        }

        IncrementStats( _stats.ip, pktHdr );
        break;
      }
      case ETHERTYPE_IPV6:
      {
        IncrementStats( _stats.ipv6, pktHdr );
        break;
      }
    }
  }
}

void PcapListener::IncrementStats( Stats& stat, const pcap_pkthdr* pktHdr ) const
{
  int rateIndex = pktHdr->ts.tv_sec - _stats.baseTime;
  //TODO: turn this into a hard check if we think its possible to happen (i.e.
  //      pkt hdr times come out of sequence)
  assert( rateIndex < STAT_INTERVAL_SECONDS && rateIndex >= 0 );
  
  ++stat.count; 
  ++stat.packetRates[rateIndex];
  stat.byteRates[rateIndex] += pktHdr->len;
  stat.total += pktHdr->len;
  stat.min = std::min<int>( stat.min, pktHdr->len );
  stat.max = std::max<int>( stat.max, pktHdr->len );
}

int PcapListener::GetDropCount()
{
  // get pcap stats if they exist
  pcap_stat pcapStats;
  if( pcap_stats( _pcapFd, &pcapStats ) < 0 ) return 0;
 
  /* if supported, we can get nic drops here
   * pcapStats.ps_ifdrop 
   */
  return pcapStats.ps_drop; 
}

void PcapListener::PrintStats( const timeval& ts, const int dropCount )
{
  // pretty formatting
  std::cout << "======== " << std::ctime( &ts.tv_sec ) << std::endl;

  std::cout << "Total Stats: " << std::endl;
  _stats.total.Print();

  std::cout << "IPv4 Stats: " << std::endl;
  _stats.ip.Print();

  std::cout << "IPv4 TCP Stats: " << std::endl;
  _stats.ip_tcp.Print();

  std::cout << "IPv4 UDP Stats: " << std::endl;
  _stats.ip_udp.Print();

  std::cout << "IPv6 UDP Stats: " << std::endl;
  _stats.ipv6.Print();

  // looks like pcap_stats returns kernel drops due to socket bufs overflowing
  // pcap stats is running tally of total drops, so we keep track of last total
  // to get interval count
  std::cout << "Drops: " << (dropCount - _stats.drops) << std::endl; 
  std::cout << "Cumulative Drops: " << dropCount << std::endl; 

  std::cout << std::endl;
}

