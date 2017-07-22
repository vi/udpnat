// socat -t9999999 exec:./udpnat  tun:10.0.0.0/32,tun-name=qwe,iff-up,iff-promisc,iff-no-pi,iff-noarp
// echo 2 > /proc/sys/net/ipv4/conf/qwe/rp_filter
// ip tuntap add dev udpnat mode tun

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <fcntl.h>

#include "tunudp.h"

uint16_t ip_id=1;

char buf[4096];
char buf_reply[4096];



int main(int argc, char* argv[]) {
    if (argc!=3 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-?")) {
        printf("Usage: udpnat /dev/net/tun ifname\n");
        printf("  If creates a TUN device which does UDP-only IPv4 NAT\n");
        printf("  Mind /proc/sys/net/ipv4/conf/*/rp_filter\n");
        return 1;
    }
    
    const char* devnettun = argv[1];
    const char* devname = argv[2];
    
    int tundev = open_tun(devnettun, devname, 0);
    
    if (tundev == -1) { return 2; }
    
    for(;;) {
        struct sockaddr_in src;
        struct sockaddr_in dst;
        
        uint8_t *data;
        
        int ret = receive_udp_packet_from_tun(
                tundev, 
                (char*)buf, sizeof buf, 
                &src, &dst, 
                (char**)&data);
        
        if (-1 == ret) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return 3;
        }
        
        // Mirror back
        send_udp_packet_to_tun(
                tundev, (char*)buf_reply, sizeof buf_reply,
                &dst, &src,
                (const char*)data, ret,
                &ip_id);
    }
   
    return 0;
}

