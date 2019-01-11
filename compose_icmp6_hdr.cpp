#include "compose_icmp6_hdr.h"

namespace icmp6 {

bool is_ra(const icmp6_hdr *icmp6_hdr)
{
    return icmp6_hdr->icmp6_type == ND_ROUTER_ADVERT;
}

void compose_icmp6_echo_request_hdr(
    icmp6_hdr *icmp6_hdr,
    uint8_t    icmp6_type,
    uint8_t    icmp6_code)
{
    /* ICMPv6 header */
    icmp6_hdr->icmp6_type  = icmp6_type;
    icmp6_hdr->icmp6_code  = icmp6_code;
    icmp6_hdr->icmp6_cksum = 0;
    /* icmp6_id: An optional identification field that can be *used to help 
     * in matching Echo Request and Echo Reply messages.
     */
    icmp6_hdr->icmp6_id  = 0;
    /* icmp6_seq: Additional optional data to be sent along with the message. 
     * If this is sent in the Echo Request it is copied into the Echo Reply 
     * to be sent back to the source.
     */
    icmp6_hdr->icmp6_seq = 0;
}

void compose_icmp6_ns_hdr(
    nd_neighbor_solicit *icmp6_hdr,
    uint8_t              icmp6_code,
    const in6_addr&      target_addr)
{
    /* ICMPv6 header */
    struct nd_neighbor_solicit *icmp6_ns = (struct nd_neighbor_solicit *)icmp6_hdr;
    icmp6_ns->nd_ns_type  = ND_NEIGHBOR_SOLICIT;
    icmp6_ns->nd_ns_code  = icmp6_code;
    icmp6_ns->nd_ns_cksum = 0;
    icmp6_ns->nd_ns_reserved = 0;
    memcpy(icmp6_ns->nd_ns_target.s6_addr, target_addr.s6_addr, sizeof(in6_addr));
}

//
// Compose an ICMPv6 header for Router Solicitation
//
void compose_icmp6_rs_hdr(nd_router_solicit *rs_hdr)
{
    memset(rs_hdr, 0, sizeof(struct nd_router_solicit));
    rs_hdr->nd_rs_type     = ND_ROUTER_SOLICIT;
    rs_hdr->nd_rs_code     = 0;
    rs_hdr->nd_rs_cksum    = 0;
    rs_hdr->nd_rs_reserved = 0;
}

}

