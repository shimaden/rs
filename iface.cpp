#include "iface.h"

#include <stdio.h>
#include <string.h>

#include <fstream>
#include <regex>

/* The 4th field of /proc/net/if_inet6 */
#define IPV6_ADDR_GLOBAL        0x0000U
#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U
#define IPV6_ADDR_COMPATv4      0x0080U

namespace ethif
{

const uint8_t *and128(uint8_t answer[16], const uint8_t a[16], const uint8_t b[16])
{
    const uint64_t *a_hi = (uint64_t *)&a[8];
    const uint64_t *a_lo = (uint64_t *)&a[0];
    const uint64_t *b_hi = (uint64_t *)&b[8];
    const uint64_t *b_lo = (uint64_t *)&b[0];
    uint64_t *ans_hi = (uint64_t *)&answer[8];
    uint64_t *ans_lo = (uint64_t *)&answer[0];

    *ans_hi = *a_hi & *b_hi;
    *ans_lo = *a_lo & *b_lo;

    return answer;
}


enum addr_type_t addr_type(const in6_addr& ip6_addr)
{
    static const uint8_t unspec_mask[16]    = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t loopback_mask[16]  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const uint8_t multicast_mask[16] = {0xFF,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t linklocal_mask[16] = {0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    uint8_t answer[16];

    if(memcmp(ip6_addr.s6_addr, unspec_mask, 16) == 0)
        return unspecified;
    else if(memcmp(ip6_addr.s6_addr, loopback_mask, 16) == 0)
        return loopback;
    else if(memcmp(and128(answer, ip6_addr.s6_addr, multicast_mask), multicast_mask, 16) == 0)
        return multicast;
    else if(memcmp(and128(answer, ip6_addr.s6_addr, linklocal_mask), linklocal_mask, 16) == 0)
        return linklocal_unicast;
    else
        return global_unicast;
}

// for sscanf()
#if IFNAMSIZ != 16
#error "IFNAMSIZ != 16"
#endif


bool ether_info(const char *device, ether_info_list& ether_info_list)
{
    using namespace std;

    regex re(string("\\b") + string(device) + string("\\b"));

    const char *procfile = "/proc/net/if_inet6";
    ifstream f(procfile);
    if(!f)
    {
        fprintf(stderr, "Can't open %s.\n", procfile);
        return false;
    }

    struct ether_info info;
    uint8_t *a = info.ip6_addr.s6_addr;
    string line;
    while(getline(f, line))
    {
        if(regex_search(line, re))
        {
            //printf("%s\n", line.c_str());
            sscanf(line.c_str(),
                "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx"
                "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx"
                " %x %x %x %x %16s",
                &a[0], &a[1], &a[2],  &a[3],  &a[4],  &a[5],  &a[6],  &a[7],
                &a[8], &a[9], &a[10], &a[11], &a[12], &a[13], &a[14], &a[15],
                &info.index, &info.prefix_len, &info.scope, &info.dad_status,
                info.if_name
            );
            info.addr_type = addr_type(info.ip6_addr);

            ether_info_list.push_back(info);

        }
    }

    return true;
}

bool get_iface_addr(const char *device, addr_type_t addr_type, in6_addr& ip6_addr)
{
    typedef ether_info_list::const_iterator iter;
    ether_info_list list;
    bool success = ether_info(device, list);
    bool found = false;
    for(iter it = list.begin() ; !found && it != list.end() ; ++it)
    {
        if(it->addr_type == addr_type)
        {
            ip6_addr = it->ip6_addr;
            found = true;
        }
    }
    return success && found;
}



}

#if defined(IFACE_TEST)

#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        fprintf(stderr, "Too few arguments.\n");
        return 1;
    }
    const char *device = argv[1];
    ethif::ether_info_list list;
    bool is_success = ethif::ether_info(device, list);
    if(!is_success)
    {
        fprintf(stderr, "error\n");
        return 1;
    }

    typedef ethif::ether_info_list::const_iterator iter;

    for(iter it = list.begin() ; it != list.end() ; ++it)
    {
        const uint8_t *a = it->ip6_addr.s6_addr;
        printf("%02x%02x%02x%02x%02x%02x%02x%02x"
               "%02x%02x%02x%02x%02x%02x%02x%02x"
               " %02x %02x %02x %02x   %-16s %d\n",
               a[0], a[1], a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
               a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
               it->index, it->prefix_len, it->scope, it->dad_status,
               it->if_name, it->addr_type
        );
    }

    printf("\n");

    in6_addr linklocal;
    bool is_found = ethif::get_iface_addr(device, ethif::linklocal_unicast, linklocal);
    if(is_found)
    {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, linklocal.s6_addr, buf, sizeof buf);
        printf("Link-local: %s\n", buf);
    }

    in6_addr global;
    is_found = ethif::get_iface_addr(device, ethif::global_unicast, global);
    if(is_found)
    {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, global.s6_addr, buf, sizeof buf);
        printf("Global    : %s\n", buf);
    }
    return 0;
}

#endif
