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

int tunudp_debug = 0;

// http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22656
static uint16_t ip_checksum(void* vdata1,size_t length1, void* vdata2, size_t length2) {
    // Cast the data pointer to one that can be indexed.
    char* data1=(char*)vdata1;
    char* data2=(char*)vdata2;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    size_t i;
    if (vdata1) {
        // Handle complete 16-bit blocks.
        for (i=0;i+1<length1;i+=2) {
            uint16_t word;
            memcpy(&word,data1+i,2);
            acc+=ntohs(word);
            if (acc>0xffff) {
                acc-=0xffff;
            }
        }
    
        // Handle any partial block at the end of the data.
        if (length1&1) {
            uint16_t word=0;
            memcpy(&word,data1+length1-1,1);
            acc+=ntohs(word);
            if (acc>0xffff) {
                acc-=0xffff;
            }
        }
    }

    if (vdata2) {
        // Handle complete 16-bit blocks.
        for (i=0;i+1<length2;i+=2) {
            uint16_t word;
            memcpy(&word,data2+i,2);
            acc+=ntohs(word);
            if (acc>0xffff) {
                acc-=0xffff;
            }
        }
    
        // Handle any partial block at the end of the data.
        if (length2&1) {
            uint16_t word=0;
            memcpy(&word,data2+length2-1,1);
            acc+=ntohs(word);
            if (acc>0xffff) {
                acc-=0xffff;
            }
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}


static void send_icmp_packet_to_tun(
            int tundev, char *buf_reply, size_t bufsize,
            uint8_t type, uint8_t code, const struct ip* orighdr);

int open_tun(const char* devnettun, const char* devname, int extraflags) {
    int tundev = open(devnettun, O_RDWR);
    if (tundev == -1) { perror("open(tun)"); return -1; }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_NOARP | extraflags;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);
    if(-1 == ioctl(tundev, TUNSETIFF, (void *) &ifr)) {
        perror("ioctl(TUNSETIFF)");
        close(tundev);
        return -1;
    }
    return tundev;
}

int receive_udp_packet_from_tun(
            int tundev, char *buf, size_t bufsize,
            struct sockaddr_in *src, struct sockaddr_in *dst, char **data)
{
    memset(buf, 0, bufsize);
    int ret = read(tundev, buf, bufsize);
    if (tunudp_debug) {
        fprintf(stderr, "ret=%4d ", ret);
        if (ret != -1) {
            int i;
            for(i=0; i<ret; ++i) {
                fprintf(stderr, "%02X", (int)buf[i]);
            }
        }
        fprintf(stderr, "\n");
    }
    if (ret == -1) return -1;
    
    struct ip* hi = (struct ip*)buf;
    struct udphdr *hu = (struct udphdr*)(buf + hi->ip_hl*4);
    
    size_t dataoffset = hi->ip_hl * 4 + sizeof *hu;
    
    if (tunudp_debug) {
        fprintf(stderr, "ip_v=%d ip_hl=%d ip_p=%d ip_flags=%c ip_off=%d ip_len=%d ip_ttl=%d ",
                hi->ip_v,
                hi->ip_hl,
                hi->ip_p,
                "_FD!@#$%"[ntohs(hi->ip_off) >> 13],
                ntohs(hi->ip_off) & 0x1FFF,
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
    
    if (hi->ip_v != 4) { errno=EPROTONOSUPPORT; return -1;}
    if (hi->ip_p != 17) { 
        // not UDP
        
        // 3 - destination unreachable, 2 - protocol unreachable
        send_icmp_packet_to_tun( tundev, buf+28, bufsize-28,
                                 3, 2, hi);
        
        errno=ESOCKTNOSUPPORT; 
        return -1;
    }
    if (dataoffset > ret) { errno=ENOBUFS; return -1;}
    if (ntohs(hi->ip_off) & 0x2000) {
        // fragmented; 11 - TTL exceed;  1 - fragmentation time exceed
        send_icmp_packet_to_tun( tundev, buf+28, bufsize-28,
                                 11, 1, hi);
        
        errno=EOPNOTSUPP; 
        return -1;
    }
    if ((ntohs(hi->ip_off) & 0x1FFF) != 0) {
        // not the first fragment
        errno=EOPNOTSUPP;
        return -1;
    }
    size_t ll = ntohs(hu->uh_ulen) - sizeof(hu);
    
    if (ll > ret - dataoffset) {
        errno=EBADMSG;
        return -1;
    }
    
    {
        uint8_t pseudoheader[12];
        memcpy(pseudoheader+0, &hi->ip_src, 4);
        memcpy(pseudoheader+4, &hi->ip_dst, 4);
        *(uint16_t*)(pseudoheader+8 ) = htons(IPPROTO_UDP);
        *(uint16_t*)(pseudoheader+10) = htons(ll + sizeof(hu));
        
        uint16_t savesum = hu->uh_sum;
        hu->uh_sum = 0;
        
        uint16_t calcsum = ip_checksum(pseudoheader, 12, hu, sizeof(hu) + ll);
        
        if (tunudp_debug) {
            fprintf(stderr, "UDP checksum: %04X calculated: %04X len %d\n",
                    (int)savesum, (int)calcsum, (int)ll);
        }
        if (savesum != calcsum) {
            errno=EBADMSG;
            return -1;
        }
    }
    
    if (src) {
        memset(src, 0, sizeof(*src));
        src->sin_family = AF_INET;
        src->sin_addr = hi->ip_src;
        src->sin_port = hu->uh_sport;
    }
    if (dst) {
        memset(dst, 0, sizeof(*dst));
        dst->sin_family = AF_INET;
        dst->sin_addr = hi->ip_dst;
        dst->sin_port = hu->uh_dport;
    }
    
    *data = buf + dataoffset;
    return ll;
}

int send_udp_packet_to_tun(
            int tundev, char *buf_reply, size_t bufsize,
            const struct sockaddr_in *src, const struct sockaddr_in *dst, 
            const char *data, size_t datalen, uint16_t *ip_id)
{
    size_t reqsize = 20 + sizeof(struct udphdr) + datalen;
    if (bufsize < reqsize) { 
        errno = EMSGSIZE;
        return -1; 
    }
    if (!src || !dst || src->sin_family != AF_INET || dst->sin_family != AF_INET) {
        errno = ENOTSUP;
        return -1;
    }
    
    struct ip* hi_r = (struct ip*)buf_reply;
    hi_r->ip_v = 4;
    hi_r->ip_p = 17;
    hi_r->ip_hl = 5;
    hi_r->ip_tos = 0;
    hi_r->ip_len = htons(reqsize);
    hi_r->ip_id = htons((*ip_id)++);
    hi_r->ip_off = htons(0);
    hi_r->ip_ttl=63;
    hi_r->ip_sum = htons(0);
    hi_r->ip_src = src->sin_addr;
    hi_r->ip_dst = dst->sin_addr;
    struct udphdr *hu_r = (struct udphdr*)(buf_reply + hi_r->ip_hl*4);
    hu_r->uh_sport = src->sin_port;
    hu_r->uh_dport = dst->sin_port;
    hu_r->uh_ulen = htons(8+datalen);
    hu_r->uh_sum = 0;
    
    char *data_ = buf_reply + hi_r->ip_hl*4 + sizeof(*hu_r);
    
    hi_r->ip_sum = ip_checksum(hi_r, 20, NULL, 0);
    
    memcpy(data_, data, datalen);
    
    {
        uint8_t pseudoheader[12];
        memcpy(pseudoheader+0, &hi_r->ip_src, 4);
        memcpy(pseudoheader+4, &hi_r->ip_dst, 4);
        *(uint16_t*)(pseudoheader+8 ) = htons(IPPROTO_UDP);
        *(uint16_t*)(pseudoheader+10) = htons(datalen + sizeof(hu_r));

        uint16_t calcsum = ip_checksum(pseudoheader, 12, hu_r, sizeof(hu_r) + datalen);
        hu_r->uh_sum = calcsum;
    }
    
    return write(tundev, buf_reply, reqsize);
}

static void send_icmp_packet_to_tun(
            int tundev, char *buf_reply, size_t bufsize,
            uint8_t type, uint8_t code, const struct ip* orighdr)
{
    size_t reqsize = 20 + 36;
    if (bufsize < reqsize) { 
        return;
    }
    if (orighdr->ip_ttl == 0) return;
    
    struct ip* hi_r = (struct ip*)buf_reply;
    hi_r->ip_v = 4;
    hi_r->ip_p = 1;
    hi_r->ip_hl = 5;
    hi_r->ip_tos = 0;
    hi_r->ip_len = htons(36+20);
    hi_r->ip_id = 0;
    hi_r->ip_off = htons(0);
    hi_r->ip_ttl=orighdr->ip_ttl - 1;
    hi_r->ip_sum = htons(0);
    hi_r->ip_src = orighdr->ip_dst;
    hi_r->ip_dst = orighdr->ip_src;
    hi_r->ip_sum = ip_checksum(hi_r, 20, NULL, 0);
    
    buf_reply[20] = type;
    buf_reply[21] = code;
    buf_reply[22] = 0; // checksum
    buf_reply[23] = 0; // checksum
    buf_reply[24] = 0; // unused
    buf_reply[25] = 0; // unused
    buf_reply[26] = 0; // unused
    buf_reply[27] = 0; // unused
    memcpy(buf_reply+28, orighdr, 20+8);
    *(uint16_t*)&buf_reply[22] = ip_checksum(buf_reply+20, 36, NULL, 0);
    
    write(tundev, buf_reply, 20+36);
}


/*
 // 450000218EB940003F|11|F8680|A000000|55555555|CFB8|4444|000DA8A6|414243440A
    
    // $1 = {ip_hl = 5, ip_v = 4, ip_tos = 0 '\000', ip_len = 8192, ip_id = 51635, ip_off = 64, ip_ttl = 63 '?', ip_p = 17 '\021', ip_sum = 22995,  ip_src = {s_addr = 10}, ip_dst = {s_addr = 1431655765}}
// $2 = {{{uh_sport = 47311, uh_dport = 17476, uh_ulen = 3072, uh_sum = 58034}, {source = 47311, dest = 17476, len = 3072, check = 58034}}} 
 
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
