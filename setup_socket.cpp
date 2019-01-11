#include "setup_socket.h"

#include <stdio.h>
#include <memory.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>

static void set_sockaddr(
                int sock_fd,
                int if_index,
                const ether_addr& dst_mac_addr,
                sockaddr_ll& sockaddr_ll)
{
    // Fields that aren't be used should be set with zero.
    memset(&sockaddr_ll, 0x00, sizeof(sockaddr_ll));
    sockaddr_ll.sll_family   = AF_PACKET;
    sockaddr_ll.sll_protocol = htons(ETH_P_IPV6);
    sockaddr_ll.sll_ifindex  = if_index;
    // Destination MAC address.
    memcpy(sockaddr_ll.sll_addr, dst_mac_addr.ether_addr_octet, ETH_ALEN);
    // Length of the MAC address.
    sockaddr_ll.sll_halen = ETH_ALEN;
}

static int get_iface_index(int sock_fd, const char *device)
{
    struct ifreq if_request;
    memset(&if_request, 0, sizeof if_request);
    strncpy(if_request.ifr_name, device, IFNAMSIZ - 1);
    if_request.ifr_name[IFNAMSIZ - 1] = '\0';
    if(ioctl(sock_fd, SIOCGIFINDEX, &if_request) == -1)
    {
        perror("ioctl SIOCGIFINDEX");
        close(sock_fd);
        return -1;
    }
    return sock_fd;
}

static bool flush_recv_buf(int sock_fd)
{
	uint8_t buf[1024];
	int result;
    struct timeval t;

    int ret = 1;
    do
    {
	    fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock_fd, &readfds);

        memset(&t, 0, sizeof t);
        result = select(sock_fd + 1, &readfds, NULL, NULL, &t);
        if(result > 0)
        {
            recv(sock_fd, buf, sizeof buf, 0);
        }
        else if(result == -1)
        {
            perror("select()");
            ret = 0;
            break;
        }
    } while(result != 0);

    return ret;
}

int setup_socket(sockaddr_ll& sockaddr_ll, const char *device, const ether_addr& dst_mac_addr)
{
    /* Create a socket. */
    int sock_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
    if(sock_fd < 0)
    {
        perror("socket()");
        return -1;
    }

    /* Get the interface index for device. */
    int iface_index = get_iface_index(sock_fd, device);
    if(iface_index == -1)
    {
        return -1;
    }

    /* Bind sock_fd with dst_mac_addr in sockaddr_ll. */
    set_sockaddr(sock_fd, iface_index, dst_mac_addr, sockaddr_ll);
    if(bind(sock_fd, (sockaddr *)&sockaddr_ll, sizeof(sockaddr_ll)) == -1)
    {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    /* Flush receive buffer. */
    const bool flush_success =flush_recv_buf(sock_fd);
    if(!flush_success)
    {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

bool if_ether_addr(int sockfd, const char *device, ether_addr& ether_addr)
{
    ifreq if_request;
    strncpy(if_request.ifr_name, device, IFNAMSIZ - 1);
    if_request.ifr_name[IFNAMSIZ - 1] = '\0';
    if(ioctl(sockfd, SIOCGIFHWADDR, &if_request) == -1)
    {
        perror("ioctl SIOCGIFHWADDR");
        return false;
    }
    memcpy(ether_addr.ether_addr_octet, if_request.ifr_hwaddr.sa_data, sizeof(::ether_addr));
    return true;
}
