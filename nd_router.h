#if !defined(ND_ROUTER_H__)
#define ND_ROUTER_H__

#include <net/ethernet.h>
#include <netinet/in.h>

namespace rs
{
extern void get_dst_mac_addr(ether_addr& dst_mac_addr); //, const in6_addr& target_ip6_addr);
extern void get_all_router_multicast_addr(in6_addr& ip6_addr);
}

#endif
