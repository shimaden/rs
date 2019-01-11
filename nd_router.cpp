#include "nd_router.h"

#include <stdio.h>
#include <memory.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <netdb.h>


namespace rs
{

//const uint8_t icmp6_type = ND_ROUTER_SOLICIT;

// Destination MAC address
void get_dst_mac_addr(ether_addr& dst_mac_addr) //, const in6_addr& target_ip6_addr)
{
    // RS multicast (All router multicast address)
    //   Dest MAC : 33:33:00:00:00:02
    //   Dest IPv6: ff02::2
    // RA multicast (All node multicast address)
    //   Dest MAC : 33:33:00:00:00:01
    //   Dest IPv6: ff:02::1
    dst_mac_addr.ether_addr_octet[0] = 0x33;
    dst_mac_addr.ether_addr_octet[1] = 0x33;
    dst_mac_addr.ether_addr_octet[2] = 0x00;
    dst_mac_addr.ether_addr_octet[3] = 0x00;
    dst_mac_addr.ether_addr_octet[4] = 0x00;
    dst_mac_addr.ether_addr_octet[5] = 0x02;
}

// Destination IPv6 address
//void get_dst_ip6_addr(in6_addr& ip6_dst_addr)
void get_all_router_multicast_addr(in6_addr& ip6_addr)
{
    // ff02::2 = All Router Multicast Address
    // ff02::1 = All Node Multicast Address
    memset(ip6_addr.s6_addr, 0, sizeof ip6_addr.s6_addr);
    ip6_addr.s6_addr[ 0] = 0xFF;
    ip6_addr.s6_addr[ 1] = 0x02;
    ip6_addr.s6_addr[15] = 0x02;
}

}

#if defined(ND_ROUTER_TEST_1)
int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        fprintf(stderr, "need cmdline arg.\n");
        return 1;
    }
    const char *device = argv[1];
    ether_addr src_mac_addr;
    rs::get_src_mac_addr(src_mac_addr, device);
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", device,
        src_mac_addr.ether_addr_octet[0],
        src_mac_addr.ether_addr_octet[1],
        src_mac_addr.ether_addr_octet[2],
        src_mac_addr.ether_addr_octet[3],
        src_mac_addr.ether_addr_octet[4],
        src_mac_addr.ether_addr_octet[5]
    );


    return 0;
}

#elif defined(ND_ROUTER_TEST_2)
int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        fprintf(stderr, "need cmdline arg.\n");
        return 1;
    }

    const char *device = argv[1];
    in6_addr ip6_src_addr;
    bool result = rs::get_src_ip6_addr(ip6_src_addr, device);

    return 0;
}
#endif
