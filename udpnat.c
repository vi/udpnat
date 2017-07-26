// echo 2 > /proc/sys/net/ipv4/conf/qwe/rp_filter
// ip tuntap add dev udpnat mode tun

#define _GNU_SOURCE // F_SETSIG

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

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

#include <signal.h>

#include "tunudp.h"
#include "robinhoodhash.h"

uint16_t ip_id=1;

char buf[4096];
char buf_reply[4096];

#define MAXCONNS 8192
int TTL = 60;
#define SCAN_INTERVAL 5

struct ipport {
    uint32_t ip;
    uint16_t port;
};

struct connection {
    struct ipport src;
    uint16_t ttl;
};

struct connection connections[MAXCONNS] = {{{0,0},0}};

// hash map from src.ip:src.port to socket fd
uint16_t addr2sock[0x10001];

#define addr2sock_setvalue(index, key_, val_) \
            addr2sock[index]=val_;
#define addr2sock_setnil(index) \
            addr2sock[index] = 0xFFFF;
#define addr2sock_swap(index1, index2) \
            uint16_t tmp = addr2sock[index1]; \
            addr2sock[index1] = addr2sock[index2]; \
            addr2sock[index2] = tmp;
#define addr2sock_nilvalue        0xFFFF
#define addr2sock_getvalue(index) addr2sock[index]
#define addr2sock_getkey(index)   connections[addr2sock[index]].src
#define addr2sock_keysequal(key1, key2) (key1.ip == key2.ip && key1.port == key2.port)
#define addr2sock_isnil(index)    addr2sock[index]==0xFFFF
#define addr2sock_n_elem          0x10001
#define addr2sock_getbucket(key)  ((ntohl(key.ip)&0xFFFF) ^ key.port)+1
#define addr2sock_overflow        abort()
#define addr2sock_removefailed(key)  abort()


static int find_connection(struct sockaddr_in c) {
    struct ipport key = { c.sin_addr.s_addr, c.sin_port };
    uint16_t val;
    
    ROBINHOOD_HASH_GET(addr2sock, key, val);
    if (val == 0xFFFF) return -1;
    
    return val;
}

static int expire_connections() {
    int i;
    for (i=0; i<MAXCONNS; ++i) {
        struct connection *c = connections+i;
        if (!c->src.ip) continue;
        if (c->ttl < SCAN_INTERVAL) {
            fprintf(stderr, "Expired connection from %s:%d. Closing socket %d\n",inet_ntoa(*(struct in_addr*)&c->src.ip), ntohs(c->src.port), i);
            
            ROBINHOOD_HASH_DEL(addr2sock, c->src);
            memset(&connections[i], 0, sizeof(connections[i]));
            close(i);
        } else {
            c->ttl -= SCAN_INTERVAL;
        }
    }
    return -1;
}


static void serve_tundev(int tundev) {
    int ret;
    for(;;) {
        struct sockaddr_in src;
        struct sockaddr_in dst;
        
        uint8_t *data;
        
        ret = receive_udp_packet_from_tun(
                tundev, 
                (char*)buf, sizeof buf, 
                &src, &dst, 
                (char**)&data);
        
        if (-1 == ret) {
            if (errno == EAGAIN) return;
            if (errno == EINTR || 
                errno == EPROTONOSUPPORT ||
                errno == ESOCKTNOSUPPORT || 
                errno == EOPNOTSUPP) continue;
            return;
        }
        
        if (src.sin_addr.s_addr == 0) continue;
        
        int s = find_connection(src);
        if (s == -1) {
            fprintf(stderr, "New connection: %s:%d -> ",inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            fprintf(stderr, "%s:%d. Created socket ", inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
            s = socket(AF_INET, SOCK_DGRAM, 0);
            
            if (s == -1) continue; // FIXME: send ICMP dest unreach
            // Optional bind to port
            struct sockaddr_in sbind;
            memset(&sbind, 0, sizeof(sbind));
            sbind.sin_family = AF_INET;
            sbind.sin_addr.s_addr = 0;
            sbind.sin_port = src.sin_port;
            bind(s, (struct sockaddr*)&sbind, sizeof(sbind));
            
            fprintf(stderr, "%d\n", s);
            if (s >= MAXCONNS) {
                close(s); // FIXME: send ICMP dest unreach
            }
            connections[s].src.ip = src.sin_addr.s_addr;
            connections[s].src.port = src.sin_port;
            connections[s].ttl = TTL;
            fcntl(s, F_SETSIG, SIGRTMIN);
            fcntl(s, F_SETOWN, getpid());
            fcntl(s, F_SETFL, O_ASYNC|O_RDWR|O_NONBLOCK);
            
            ROBINHOOD_HASH_SET(addr2sock, connections[s].src, s);
        } else {
            //printf(stderr, "Old connection: %s:%d -> ",inet_ntoa(src.sin_addr), ntohs(src.sin_port));
            //fprintf(stderr, "%s:%d. Associated socket", inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
            //fprintf(stderr, " is %d\n", s);
            connections[s].ttl = TTL;
        }
        
        sendto(s, data, ret, 0, (struct sockaddr*)&dst, sizeof(dst));
    }
}

static void serve_sock(int fd, int tundev) {
    int ret;
    if (fd >= MAXCONNS || fd < 0) {
        fprintf(stderr, "Invalid FD from signal: %d\n", fd);
        return;
    }
    
    struct connection* c = connections+fd;
    //fprintf(stderr, "Incoming data on fd %d\n", fd);
    
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = c->src.ip;
    dst.sin_port = c->src.port;
    
    for(;;) {
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);
        
        ret = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr*)&src, &src_len);
        
        if (ret == -1) {
            if (errno == EAGAIN) return;
            // else just wait for socket to be closed
            return;
        }
        
        // Reply to tun
        send_udp_packet_to_tun(
                tundev, (char*)buf_reply, sizeof(buf_reply),
                &src, &dst,
                (const char*)buf, ret,
                &ip_id);
    }
}

int main(int argc, char* argv[]) {
    if (argc!=4 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-?")) {
        printf("Usage: udpnat /dev/net/tun ifname expire_seconds\n");
        printf("  If creates a TUN device which does UDP-only IPv4 NAT\n");
        printf("  Mind /proc/sys/net/ipv4/conf/*/rp_filter\n");
        printf("  Also mind ulmit -n\n");
        return 1;
    }
    
    const char* devnettun = argv[1];
    const char* devname = argv[2];
    TTL = atoi(argv[3]);
    
    int tundev = open_tun(devnettun, devname, 0);
    
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGRTMIN);
    sigaddset(&sigs, SIGALRM);
    sigaddset(&sigs, SIGIO);
    sigprocmask(SIG_BLOCK, &sigs, NULL);
    
    fcntl(tundev, F_SETOWN, getpid());
    fcntl(tundev, F_SETSIG, SIGRTMIN);
    fcntl(tundev, F_SETFL, O_ASYNC|O_RDWR|O_NONBLOCK);
    
    if (tundev == -1) { return 2; }
    
    alarm(SCAN_INTERVAL);
    
    int ret;
    
    ROBINHOOD_HASH_CLEAR(addr2sock);
    
    for(;;) {
        siginfo_t si;
        ret = sigwaitinfo(&sigs, &si);
        
        if (ret == SIGALRM) {
            expire_connections();
            alarm(SCAN_INTERVAL);
        }
        
        if (ret == SIGIO) {
            fprintf(stderr, "Lost some signals?\n");
            serve_tundev(tundev);
            int i;
            for(i=0; i<MAXCONNS; ++i) {
                if (connections[i].src.ip != 0) {
                    serve_sock(i, tundev);
                }
            }
        }
        
        if (ret != SIGRTMIN) continue;
        
        
        if (si.si_fd == tundev) {
            serve_tundev(tundev);
        } else {
            serve_sock(si.si_fd, tundev);
        }
    }
   
    return 0;
}

