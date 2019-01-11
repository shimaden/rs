#if !defined(EUI64_H__)
#define EUI64_H__

#include <netinet/ip6.h>

namespace eui64
{
extern void eui64(uint8_t *ip6_addr, const uint8_t *prefix, const uint8_t *mac_addr);
}

#endif
