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

#include <linux/if.h>
#include <linux/if_tun.h>

#include <fcntl.h>


// http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22656
uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    size_t i;
    for (i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}



uint8_t buf[4096];
uint8_t buf_reply[4096];
/*
int receive_udp_packet_from_tun(uint8_t *buf, size_t bufsize, sockaddr_in src, sockaddr_in dst)
{
    
}*/

int main(int argc, char* argv[]) {
    if (argc!=3 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-?")) {
        printf("Usage: udpnat /dev/net/tun ifname\n");
        printf("  If creates a TUN device which does UDP-only IPv4 NAT\n");
        printf("  Mind /proc/sys/net/ipv4/conf/*/rp_filter\n");
        return 1;
    }
    
    const char* devnettun = argv[1];
    const char* devname = argv[2];
    
    int tundev = open(devnettun, O_RDWR);
    if (tundev == -1) { perror("open(tun)"); return 2; }
    
    {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_NOARP;
        strncpy(ifr.ifr_name, devname, IFNAMSIZ);
        if(-1 == ioctl(tundev, TUNSETIFF, (void *) &ifr)) {
            perror("ioctl(TUNSETIFF)");
            return 2;
        }
    }
    
    uint16_t ipid=1;
    int debug = 1;
    for(;;) {
        memset(buf, 0, sizeof buf);
        int ret = read(tundev, buf, sizeof buf);
        if (debug) {
            fprintf(stderr, "ret=%4d ", ret);
            if (ret != -1) {
                int i;
                for(i=0; i<ret; ++i) {
                    fprintf(stderr, "%02X", (int)buf[i]);
                }
            }
            fprintf(stderr, "\n");
        }
        
        struct ip* hi = (struct ip*)buf;
        struct udphdr *hu = (struct udphdr*)(buf + hi->ip_hl*4);
        
        if (debug) {
            fprintf(stderr, "ip_hl=%d ip_v=%d ip_p=%d ip_len=%d ip_ttl=%d ",
                    hi->ip_hl,
                    hi->ip_v,
                    hi->ip_p,
                    ntohs(hi->ip_len),
                    hi->ip_ttl);
            fprintf(stderr, "%s:%d -> ",
                    inet_ntoa(hi->ip_src),
                    ntohs(hu->uh_sport));
            fprintf(stderr, "%s:%d len=%d\n",
                    inet_ntoa(hi->ip_dst),
                    ntohs(hu->uh_dport),
                    ntohs(hu->uh_ulen));
            fprintf(stderr, "Content: ");
            int i;
            for (i=hi->ip_hl*4 + sizeof *hu; i<ret; ++i) {
                fprintf(stderr, "%02X", (int)buf[i]);
            }
            fprintf(stderr, "\n");
        }
        
        if (hi->ip_v != 4) continue;
        if (hi->ip_p != 17) continue;
        
        
        // Mirror back
        struct ip* hi_r = (struct ip*)buf_reply;
        hi_r->ip_v = 4;
        hi_r->ip_p = 17;
        hi_r->ip_hl = 5;
        hi_r->ip_tos = 0;
        hi_r->ip_len = htons(32);
        hi_r->ip_id = htons(ipid++);
        hi_r->ip_off = htons(0);
        hi_r->ip_ttl=63;
        hi_r->ip_sum = htons(0);
        hi_r->ip_src = hi->ip_dst;
        hi_r->ip_dst = hi->ip_src;
        struct udphdr *hu_r = (struct udphdr*)(buf_reply + hi_r->ip_hl*4);
        hu_r->uh_sport = hu->uh_dport;
        hu_r->uh_dport = hu->uh_sport;
        hu_r->uh_ulen = htons(8+4);
        hu_r->uh_sum = 0;
        uint8_t *data = buf_reply + hi_r->ip_hl*4 + sizeof(*hu_r);
        
        hi_r->ip_sum = ip_checksum(hi_r, 20);
        
        memcpy(data, "ABC\n", 4);
        
        write(tundev, buf_reply, hi_r->ip_hl*4 + sizeof(*hu_r) + 4);
    }
    // 450000218EB940003F|11|F8680|A000000|55555555|CFB8|4444|000DA8A6|414243440A
    
    // $1 = {ip_hl = 5, ip_v = 4, ip_tos = 0 '\000', ip_len = 8192, ip_id = 51635, ip_off = 64, ip_ttl = 63 '?', ip_p = 17 '\021', ip_sum = 22995,  ip_src = {s_addr = 10}, ip_dst = {s_addr = 1431655765}}
// $2 = {{{uh_sport = 47311, uh_dport = 17476, uh_ulen = 3072, uh_sum = 58034}, {source = 47311, dest = 17476, len = 3072, check = 58034}}}
    return 0;
}
/*
struct ip {
    unsigned int ip_hl:4;
    unsigned int ip_v:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct udphdr {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
};
*/
