#include "PcapListener.h"

#include <iostream>

int main( int argc, const char** argv )
{
  if( argc < 2 ) 
  {
    std::cout << "Must pass an interface to listen on" << std::endl;
    return -1;
  }

  std::string iface = argv[1];

  PcapListener pcap;

  if( !pcap.Start( iface ) )
  {
    std::cout << "Couldn't start live capture. Exiting..." << std::endl;
    return -1;
  }


  // run 
  while( true )
  {
    pcap.Process();
  }

  return 0;
}
