/* Referrences:
 *   "基礎からわかるTCP/IPネットワーク実験プログラミング",
 *   村山公保, オーム社
 *   p.93, 2.8.3 チェックサム計算プログラム 
 */

#include "checksum.h"

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v) (v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v) ((unsigned short)(v) << 8)
#else
# define ODDBYTE(v) htons((unsigned short)(v) << 8)
#endif

#if 0
register unsigned short *w = addr;
sum += ODDBYTE(*(unsigned char *)w);    /* le16toh() may be unavailable on old systems */
#endif

#include <stdio.h>

/* The sum of ene's complement is independent on byte order. */

/* data:
 *   (as byte stream): HH LL HH LL ...
 *   (as uint16_t   ): LL HH LL HH ... (in little endian)
 */
static inline uint16_t ones_complement(const uint16_t *data, int bytes)
{
    register uint32_t        sum    = 0;
    register const uint16_t *data_  = data;
    register int             bytes_ = bytes;

    /* Sum up by 2 bytes. */
    for( ; bytes_ > 1 ; bytes_ -= 2)
    {
        sum += ntohs(*data_);  /* sum: HH LL in little endian */
        ++data_;
        if(sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    /* If the data has odd bytes. */
    if(bytes_ == 1)
    {
        const uint8_t b = *((uint8_t *)data_ + 0);
        sum += ntohs(b);
    }

    /* Fold overflow. */
    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum;
}

uint16_t icmp6checksum(const uint8_t *packet)
{

    struct ip6_hdr   *ip6_hdr   = (struct ip6_hdr *)packet;
    struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(packet + sizeof(struct ip6_hdr));

    const uint16_t cksum_backup = icmp6_hdr->icmp6_cksum;

    icmp6_hdr->icmp6_cksum = 0;

    /* IPv6 header */
    register uint32_t sum = 0;
    sum += ones_complement(ip6_hdr->ip6_src.s6_addr16, sizeof(ip6_hdr->ip6_src.s6_addr16));
    sum += ones_complement(ip6_hdr->ip6_dst.s6_addr16, sizeof(ip6_hdr->ip6_dst.s6_addr16));
    sum += ones_complement(&ip6_hdr->ip6_plen, sizeof(ip6_hdr->ip6_plen));
    sum += IPPROTO_ICMPV6;

    /* ICMPv6 header */
    sum += ones_complement((uint16_t *)icmp6_hdr, ntohs(ip6_hdr->ip6_plen));

    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    icmp6_hdr->icmp6_cksum = cksum_backup;

    return (uint16_t)~sum;
}
