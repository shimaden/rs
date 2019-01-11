#include "eui64.h"

#include <memory.h>

namespace eui64
{

void eui64(uint8_t *ip6_addr, const uint8_t *prefix, const uint8_t *mac_addr)
{
    const size_t prefix_size= 64 / 8;  // Assume prefix length is 64 bits for now.
    memset(ip6_addr, 0, sizeof(::in6_addr));
    memcpy(ip6_addr, prefix, prefix_size);

    ip6_addr[ 8] = mac_addr[0] ^ 0x02;
    ip6_addr[ 9] = mac_addr[1];
    ip6_addr[10] = mac_addr[2];
    ip6_addr[11] = 0xFF;
    ip6_addr[12] = 0xFE;
    ip6_addr[13] = mac_addr[3];
    ip6_addr[14] = mac_addr[4];
    ip6_addr[15] = mac_addr[5];
}


}
