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

#define MAXCONNS 1024

struct connection {
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t ttl;
};

struct connection connections[MAXCONNS] = {{0,0,0}};


static int find_connection(struct sockaddr_in c) {
    // TODO: index
    
    int i;
    for (i=0; i<MAXCONNS; ++i) {
        if (connections[i].src_ip  == c.sin_addr.s_addr && connections[i].src_port == c.sin_port) {
            return i;
        }
    }
    return -1;
}

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
        
        int s = find_connection(src);
        if (s == -1) {
            fprintf(stderr, "New connection: %s:%d ->",inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            fprintf(stderr, "%s:%d. Created socket ", inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
            s = socket(AF_INET, SOCK_DGRAM, 0);
            fprintf(stderr, "%d\n", s);
            if (s == -1) continue; // FIXME: send ICMP dest unreach
            if (s >= MAXCONNS) {
                close(s); // FIXME: send ICMP dest unreach
            }
            connections[s].src_ip = src.sin_addr.s_addr;
            connections[s].src_port = src.sin_port;
            connections[s].ttl = 60;
        } else {
            fprintf(stderr, "Old connection: %s:%d ->",inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            fprintf(stderr, "%s:%d. Associated socket", inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
            fprintf(stderr, " is %d\n", s);
        }
        
        sendto(s, data, ret, 0, (struct sockaddr*)&dst, sizeof(dst));
        
        // Mirror back
        send_udp_packet_to_tun(
                tundev, (char*)buf_reply, sizeof buf_reply,
                &dst, &src,
                (const char*)data, ret,
                &ip_id);
    }
   
    return 0;
}

