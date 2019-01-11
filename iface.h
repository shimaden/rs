#if !defined(IFACE_H__)
#define IFACE_H__

#include <net/if.h>
#include <netinet/ip6.h>
#include <vector>

namespace ethif
{

enum addr_type_t {
    unspecified       = 0,
    loopback          = 1,
    multicast         = 2,
    linklocal_unicast = 3,
    global_unicast    = 4
};

struct ether_info
{
    struct in6_addr ip6_addr;
    /* The type of the 4 below members must be unsigned int for sscanf() */
    unsigned int index;
    unsigned int prefix_len;
    unsigned int scope;
    unsigned int dad_status;
    char if_name[IFNAMSIZ + 1];
    enum addr_type_t addr_type;
};

typedef std::vector<struct ether_info> ether_info_list;

extern bool ether_info(const char *device, ether_info_list& ether_info_list);
extern bool get_iface_addr(const char *device, addr_type_t addr_type, in6_addr& ip6_addr);
extern enum addr_type_t addr_type(const in6_addr& ip6_addr);


}
#endif
