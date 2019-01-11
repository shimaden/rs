#if !defined(COMPOSE_IP6_HDR_H__)
#define COMPOSE_IP6_HDR_H__

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#define IP6_VERSION 6

namespace ip6 {

extern bool is_ipv6(const ip6_hdr *ip6_hdr);

extern void compose_ip6_hdr(
    ip6_hdr        *ip6_hdr,
    uint16_t        payload_len,
    const in6_addr& ip6_src_addr,
    const in6_addr& ip6_dst_addr);

}

#endif
