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

uint16_t ip_id=1;

char buf[4096];
char buf_reply[4096];

#define MAXCONNS 8192
int TTL = 60;
#define SCAN_INTERVAL 5

struct connection {
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t ttl;
};

struct connection connections[MAXCONNS] = {{0,0,0}};

// find_connection accelerator
int pseudomap[256] = {0};

static int find_connection(struct sockaddr_in c) {
    uint8_t psmi = (c.sin_port >> 8) ^ (c.sin_port & 0xFF);
    int i = pseudomap[psmi];
    if (connections[i].src_ip  == c.sin_addr.s_addr && 
        connections[i].src_port == c.sin_port) {
            return i;
    }
    
    for (i=0; i<MAXCONNS; ++i) {
        if (connections[i].src_ip  == c.sin_addr.s_addr && connections[i].src_port == c.sin_port) {
            pseudomap[psmi] = i;
            return i;
        }
    }
    return -1;
}

static int expire_connections() {
    int i;
    for (i=0; i<MAXCONNS; ++i) {
        struct connection *c = connections+i;
        if (!c->src_ip) continue;
        if (c->ttl < SCAN_INTERVAL) {
            fprintf(stderr, "Expired connection from %s:%d. Closing socket %d\n",inet_ntoa(*(struct in_addr*)&c->src_ip), ntohs(c->src_port), i);
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
            connections[s].src_ip = src.sin_addr.s_addr;
            connections[s].src_port = src.sin_port;
            connections[s].ttl = TTL;
            fcntl(s, F_SETSIG, SIGRTMIN);
            fcntl(s, F_SETOWN, getpid());
            fcntl(s, F_SETFL, O_ASYNC|O_RDWR|O_NONBLOCK);
            
            uint8_t psmi = (src.sin_port >> 8) ^ (src.sin_port & 0xFF);
            pseudomap[psmi] = s;
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
    dst.sin_addr.s_addr = c->src_ip;
    dst.sin_port = c->src_port;
    
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
                if (connections[i].src_ip != 0) {
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

