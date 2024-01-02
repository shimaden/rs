// Send a Router Solicitate and receive a Router Advertisement.
//
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#include <thread>
//#include <mutex>
#include <atomic>
#include <unistd.h>
#include <libgen.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <string>

#include "setup_socket.h"
#include "iface.h"
#include "nd_router.h"
#include "eui64.h"
#include "checksum.h"
#include "compose_ip6_hdr.h"
#include "compose_icmp6_hdr.h"

//std::mutex g_mutex;

//
// Compose a Router Solicitation packet.
//
static bool compose_rs(uint8_t *packet, const char *device, ethif::addr_type_t addr_type)
{
    ip6_hdr *ip6_hdr = (struct ip6_hdr *)packet;
    nd_router_solicit *icmp6_hdr = ((nd_router_solicit *)(packet + sizeof(::ip6_hdr)));

    in6_addr ip6_src_addr;
    bool is_success = ethif::get_iface_addr(device, addr_type, ip6_src_addr);
    if(!is_success)
    {
        return false;
    }

    in6_addr ip6_dst_addr;
    rs::get_all_router_multicast_addr(ip6_dst_addr);

    uint16_t payload_len = 0;
    ip6::compose_ip6_hdr(ip6_hdr, payload_len, ip6_src_addr, ip6_dst_addr);

    icmp6::compose_icmp6_rs_hdr(icmp6_hdr);
    ip6_hdr->ip6_plen = htons(sizeof *icmp6_hdr);

    uint16_t chksum = icmp6checksum(packet);
    icmp6_hdr->nd_rs_cksum = htons(chksum);

    return true;
}

//
// Send a Router Solicitation packet.
//
static bool send_rs(int                sockfd,
                    const char        *device,
                    const uint8_t     *packet,
                    size_t             packet_len,
                    const sockaddr_ll& sockaddr_ll)
{
    int flags = 0;
    ssize_t result = sendto(sockfd, packet, packet_len, flags,
                          (struct sockaddr *)&sockaddr_ll, sizeof sockaddr_ll);
    if(result == -1)
    {
        perror("send_rs()");
        return false;
    }

    return true;
}

//
// Attach pointers of the structures for RA options to the packet.
//
static bool attach_ra_opts(
                const nd_router_advert *ra,
                uint16_t nd_ra_len,
                ether_addr **src_ether_addr,
                nd_opt_prefix_info **prefix_info,
                nd_opt_mtu **mtu)
{
    bool has_error = false;

    *src_ether_addr = 0;
    *prefix_info = 0;
    *mtu = 0;

    const uint8_t *opt_pos = (uint8_t *)ra + sizeof(::nd_router_advert);
    const uint8_t *const opt_base = opt_pos;

    while(opt_pos < opt_base + nd_ra_len - sizeof(::nd_router_advert))
    {
        if(opt_pos[0] == ND_OPT_SOURCE_LINKADDR) // 1
        {
            nd_opt_hdr *hdr = (::nd_opt_hdr *)opt_pos;
            if(hdr->nd_opt_len != 1)
            {
                has_error = true;
                break;
            }
            *src_ether_addr = (::ether_addr *)(opt_pos + 2);
            opt_pos += sizeof(::nd_opt_hdr) + sizeof(::ether_addr);
        }
        else if(opt_pos[0] == ND_OPT_PREFIX_INFORMATION) // 3
        {
            nd_opt_prefix_info *hdr = (::nd_opt_prefix_info *)opt_pos;
            if(hdr->nd_opt_pi_len != 4)
            {
                has_error = true;
                break;
            }
            *prefix_info = hdr;
            opt_pos += sizeof(::nd_opt_prefix_info);
        }
        else if(opt_pos[0] == ND_OPT_MTU)  // 5
        {
            nd_opt_mtu *hdr = (::nd_opt_mtu *)opt_pos;
            if(hdr->nd_opt_mtu_len != 1)
            {
                has_error = true;
                break;
            }
            *mtu = hdr;
            opt_pos += sizeof(::nd_opt_mtu);
        }
        else
        {
            has_error = true;
            break;
        }
    }

    if(has_error)
    {
        fprintf(stderr, "Illegal type of RA option type: %u\n", opt_pos[0]);
        return false;
    }

    return true;
}


#if DEBUG
//
// Print a Router Advertisement.
//
static void print_ra(uint8_t *pkt, size_t pktlen)
{
    const ip6_hdr *ip6_hdr = (::ip6_hdr *)pkt;
    const nd_router_advert *nd_ra = (::nd_router_advert *)(pkt + sizeof(::ip6_hdr));
    char srcbuf[INET6_ADDRSTRLEN];
    char dstbuf[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, ip6_hdr->ip6_src.s6_addr, srcbuf, sizeof srcbuf);
    inet_ntop(AF_INET6, ip6_hdr->ip6_dst.s6_addr, dstbuf, sizeof dstbuf);

    printf("IP ver       : %d\n", ip6_hdr->ip6_vfc >> 4);
    printf("plen         : %u\n", ntohs(ip6_hdr->ip6_plen));
    printf("Src          : %s\n", srcbuf);
    printf("Dst          : %s\n", dstbuf);
    printf("Type         : %d\n", nd_ra->nd_ra_type);
    printf("Code         : %d\n", nd_ra->nd_ra_code);
    printf("Chksum       : 0x%04X\n", ntohs(nd_ra->nd_ra_cksum));
    printf("Cur Hop Limit: 0x%02X\n", nd_ra->nd_ra_curhoplimit);
    printf("M            : %d\n", !!(nd_ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED));
    printf("O            : %d\n", !!(nd_ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER));
    printf("H            : %d\n", !!(nd_ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT));
    printf("Router L.Time: %04X\n", ntohs(nd_ra->nd_ra_router_lifetime));
    printf("Reachable Tm : %04X\n", ntohl(nd_ra->nd_ra_reachable));
    printf("Returns Tm   : %04X\n", ntohl(nd_ra->nd_ra_retransmit));

    ether_addr         *src_mac_addr;
    nd_opt_prefix_info *prefix_info;
    nd_opt_mtu         *mtu;
    bool is_success = attach_ra_opts(
                        nd_ra,
                        ntohs(ip6_hdr->ip6_plen),
                        &src_mac_addr,
                        &prefix_info, &mtu);
    if(!is_success)
    {
        fprintf(stderr, "Broken RA packet.\n");
        return;
    }

    if(src_mac_addr != 0)
    {
        const uint8_t *e = src_mac_addr->ether_addr_octet;
        printf("Source link addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
                                  e[0], e[1], e[2], e[3], e[4], e[5]);
    }
    if(prefix_info != 0)
    {
        char prefixbuf[INET6_ADDRSTRLEN];
        const uint8_t *prefix = prefix_info->nd_opt_pi_prefix.s6_addr;
        uint8_t flags = prefix_info->nd_opt_pi_flags_reserved;
        uint32_t valid_time = ntohl(prefix_info->nd_opt_pi_valid_time);
        uint32_t preferred_time = ntohl(prefix_info->nd_opt_pi_preferred_time);

        printf("Prefix length     : %d\n", prefix_info->nd_opt_pi_prefix_len);
        printf("L flag            : %s\n", (flags & ND_OPT_PI_FLAG_ONLINK) ? "Yes" : "No");
        printf("A flag            : %s\n", (flags & ND_OPT_PI_FLAG_AUTO) ? "Yes" : "No");
        printf("Valid lifetime    : 0x%08X (%u sec)\n", valid_time,  valid_time);
        printf("Preferred lifetime: 0x%08X (%u sec)\n", preferred_time,  preferred_time);
        printf("Prefix            : %s/%d\n",
            inet_ntop(AF_INET6, prefix, prefixbuf, sizeof prefixbuf),
            prefix_info->nd_opt_pi_prefix_len);
    }
    if(mtu != 0)
    {
        printf("Recommended MTU   : %u\n", ntohl(mtu->nd_opt_mtu_mtu));
    }
}
#endif

//
// Receive a Router Advertisement
//
static bool recv_ra(int sockfd, uint8_t *recvbuf, int bufsize,
        ether_addr **src_mac_addr, nd_opt_prefix_info **prefix_info,
        nd_opt_mtu **mtu, ethif::addr_type_t src_addr_type)
{
    *src_mac_addr = 0;
    *prefix_info = 0;
    *mtu = 0;

    int flags = 0;
    ssize_t n = recv(sockfd, recvbuf, bufsize, flags);
    if(n == -1)
    {
        perror("recv_ra()");
        fprintf(stderr, "recv_ra(): n = %ld\n", n);
        return false;
    }

    const ip6_hdr *ip6_hdr = (::ip6_hdr *)recvbuf;
    const nd_router_advert *nd_ra = (::nd_router_advert *)(recvbuf + sizeof(::ip6_hdr));

    bool is_received = (n >= (ssize_t)(sizeof(::ip6_hdr) + sizeof(::nd_router_advert)))
            && ip6::is_ipv6(ip6_hdr) && icmp6::is_ra(&nd_ra->nd_ra_hdr);

    if(is_received)
    {
        ethif::addr_type_t recv_addr_type = ethif::addr_type(ip6_hdr->ip6_src);
        bool is_success = attach_ra_opts(
                            nd_ra,
                            ntohs(ip6_hdr->ip6_plen),
                            src_mac_addr,
                            prefix_info,
                            mtu);
        if(!is_success)
        {
            fprintf(stderr, "Broken RA packet.\n");
            return false;
        }
        if(recv_addr_type != src_addr_type)
        {
            return false;
        };

        return true;
    }
    else
    {
        return false;
    }
}

static bool get_my_ip6_addr(
                int fd,
                uint8_t *recvbuf,
                size_t recvbuf_size,
                const char *device,
                const uint8_t *pktbuf,
                const sockaddr_ll& sockaddr_ll,
                ether_addr **src_mac_addr,
                nd_opt_prefix_info **prefix_info,
                nd_opt_mtu **mtu,
                ethif::addr_type_t src_addr_type)
{
    bool ret = true;

    std::atomic<bool> is_received;
    is_received.store(false);
    try
    {
        // 2.3 Send an RS ICMPv6 packet from link-local address 
        //     in another thread.
        std::thread t([&is_received, fd, device, &sockaddr_ll, pktbuf]{
            const timespec req = {.tv_sec = 1, .tv_nsec = 0};
            timespec       rem = {.tv_sec = 0, .tv_nsec = 0};
            while(true)
            {
                if(is_received.load()) // Rewritten by the receive routine below.
                {
                    break;
                }
                const ip6_hdr *ip6_hdr = (::ip6_hdr *)pktbuf;
                size_t packet_size = sizeof(::ip6_hdr) + ntohs(ip6_hdr->ip6_plen);
                send_rs(fd, device, pktbuf, packet_size, sockaddr_ll);
                nanosleep(&req, &rem);
            }
        });
        t.detach();

        // 2.4 Wait until receiving an RA in the main thread.
        while(!is_received.load())
        {
            ether_addr *src_mac_addr_;
            nd_opt_prefix_info *prefix_info_;
            nd_opt_mtu *mtu_;
            is_received.store(
                            recv_ra(
                                fd,
                                recvbuf,
                                recvbuf_size,
                                &src_mac_addr_,
                                &prefix_info_,
                                &mtu_, src_addr_type
                            )
            );
            *src_mac_addr = src_mac_addr_;
            *prefix_info  = prefix_info_;
            *mtu          = mtu_;
        }
    }
    catch(std::exception& e)
    {
        fprintf(stderr, "thread: %s\n", e.what());
        ret = false;
    }
    return ret;
}

static std::string ip6addr_str(const in6_addr& ip6_addr, bool is_full = true)
{
    if(is_full)
    {
        char buf[40];
        const uint8_t *p = ip6_addr.s6_addr;
        sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
                     ":%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
                     p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15]);
        return buf;
    }
    else
    {
        char buf[INET6_ADDRSTRLEN];
        return inet_ntop(AF_INET6, ip6_addr.s6_addr, buf, sizeof buf);
    }
}

//
// Print usage.
//
static void usage(const char *cmd)
{
    char buf[strlen(cmd) + 1];
    strcpy(buf, cmd);
    fprintf(stderr, "Usage: %s <iface>\n", basename(buf));
}

//
// Main routine.
//
int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        usage(argv[0]);
        return 1;
    }
    const char *device = argv[1];
    if(strlen(device) > IFNAMSIZ)
    {
        fprintf(stderr, "Too long iface name.\n");
        return 1;
    }

    const int option_size = 0;
    const int sendbuf_size = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + option_size;
    uint8_t sendbuf[sendbuf_size];
    memset(sendbuf, 0, sizeof sendbuf);

    // 1. Open a socket.
    ether_addr dst_mac_addr;
    rs::get_dst_mac_addr(dst_mac_addr);
    sockaddr_ll sockaddr_ll;
    int fd = setup_socket(sockaddr_ll, device, dst_mac_addr);

    // 2. Send an RS from a link-local address to get a global prefix.

    // 2.1 Get the IPv6 link-local address of the interface specified
    in6_addr linklocal_addr;
    bool is_found = ethif::get_iface_addr(device, ethif::linklocal_unicast, linklocal_addr);
    if(!is_found)
    {
        fprintf(stderr, "Can't get info of %s.\n", device);
        return 1;
    }

    // 2.2 Compose an RS packet.
    bool is_compose_success = compose_rs(sendbuf, device, ethif::linklocal_unicast);
    if(!is_compose_success)
    {
        fprintf(stderr, "Couldn't compose an RS packet.\n");
        return 1;
    }

    uint8_t recvbuf[8192];
    ether_addr         *router_mac_addr = 0;
    nd_opt_prefix_info *prefix_info = 0;
    nd_opt_mtu         *mtu = 0;

    bool result = get_my_ip6_addr(
                        fd,
                        recvbuf,
                        sizeof recvbuf,
                        device,
                        sendbuf,
                        sockaddr_ll,
                        &router_mac_addr,
                        &prefix_info,
                        &mtu,
                        ethif::linklocal_unicast);
    if(!result)
    {
        fprintf(stderr, "Can't get an RA from its link-local address\n");
        return 1;
    }

#if DEBUG
    print_ra(recvbuf, sizeof recvbuf);
#endif

    const ip6_hdr *recv_ip6_hdr = (ip6_hdr *)recvbuf;

    printf("My link-local address    : %s\n", ip6addr_str(linklocal_addr).c_str());
    printf("Router link-local address: %s\n", ip6addr_str(recv_ip6_hdr->ip6_src).c_str());

    // 3. Now we have a global prefix.
    //    Build my global address using the prefix and an interface ID.
    //    The interface ID (suffix of IPv6 address) is calculated by EUI-64.
    const uint8_t *prefix = prefix_info->nd_opt_pi_prefix.s6_addr;
    if(prefix_info)
    {
        uint8_t flags = prefix_info->nd_opt_pi_flags_reserved;
        uint32_t valid_time = ntohl(prefix_info->nd_opt_pi_valid_time);
        uint32_t preferred_time = ntohl(prefix_info->nd_opt_pi_preferred_time);

        printf("Flags                    : L %-3s A %-3s\n",
               (flags & ND_OPT_PI_FLAG_ONLINK) ? "Yes" : "No",
               (flags & ND_OPT_PI_FLAG_AUTO) ? "Yes" : "No");
        printf("Valid lifetime           : %u sec\n", valid_time);
        printf("Preferred lifetime       : %u sec\n", preferred_time);
        printf("Prefix                   : %s/%d\n", ip6addr_str(*(in6_addr *)prefix).c_str(),
                                            prefix_info->nd_opt_pi_prefix_len);
    }
    // Now we have an IPv6 global address.
    ether_addr my_mac_addr;
    in6_addr   my_g_addr;
    if_ether_addr(fd, device, my_mac_addr);
    eui64::eui64(my_g_addr.s6_addr, prefix, my_mac_addr.ether_addr_octet);
    printf("My global address        : %s\n", ip6addr_str(my_g_addr).c_str());

    // 5. Figure out the router's global address by sending a Neighbor 
    //    Solicit ICMPv6 packet(s).
    //    (Prefix + eui64(MAC address of the router))
    in6_addr router_g_addr;
    eui64::eui64(router_g_addr.s6_addr, prefix, router_mac_addr->ether_addr_octet);

    printf("Estimated router address : %s\n", ip6addr_str(router_g_addr).c_str());

    close(fd);
    return 0;
}

