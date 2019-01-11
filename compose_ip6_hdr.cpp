#include "compose_ip6_hdr.h"

namespace ip6 {

bool is_ipv6(const ip6_hdr *ip6_hdr)
{
    return (ip6_hdr->ip6_vfc >> 4) == 6;
}

void compose_ip6_hdr(
    ip6_hdr        *ip6_hdr,
    uint16_t        payload_len,
    const in6_addr& ip6_src_addr,
    const in6_addr& ip6_dst_addr)
{
    /* IPv6 header */
    ip6_hdr->ip6_vfc  = IP6_VERSION * 0x10;
    ip6_hdr->ip6_plen = htons(payload_len);
    ip6_hdr->ip6_nxt  = IPPROTO_ICMPV6;
    ip6_hdr->ip6_hlim = 0xFF; /* Hop limit (TTL) */
    ip6_hdr->ip6_src  = ip6_src_addr;
    ip6_hdr->ip6_dst  = ip6_dst_addr;
}

}
