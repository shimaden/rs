#if !defined(COMPOSE_ICMP6_HDR_H__)
#define COMPOSE_ICMP6_HDR_H__

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

namespace icmp6 {

extern bool is_ra(const icmp6_hdr *icmp6_hdr);

extern void compose_icmp6_echo_request_hdr(
    icmp6_hdr *icmp6_hdr,
    uint8_t    icmp6_type,
    uint8_t    icmp6_code);

extern void compose_icmp6_ns_hdr(
    nd_neighbor_solicit *icmp6_hdr,
    uint8_t              icmp6_code,
    const in6_addr&      target_addr);

void compose_icmp6_rs_hdr(nd_router_solicit *rs_hdr);

}

#endif
