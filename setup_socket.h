#if !defined(SETUP_SOCKET_H__)
#define SETUP_SOCKET_H__

#include <netpacket/packet.h>
#include <netinet/if_ether.h>

//extern int setup_socket(const char *device, sockaddr_ll& sockaddr_ll, const ether_addr& dst_mac_addr);
extern int setup_socket(sockaddr_ll& sockaddr_ll, const char *device, const ether_addr& dst_mac_addr);
extern bool if_ether_addr(int sockfd, const char *device, ether_addr& ether_addr);

#endif
