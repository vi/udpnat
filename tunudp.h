#pragma once


#include <netinet/in.h>

// You may want IFF_UP as extraflags
int open_tun(const char* devnettun, const char* devname, int extraflags);

int receive_udp_packet_from_tun(
            int tundev, 
            char *buf, size_t bufsize, // storage
            struct sockaddr_in *src, struct sockaddr_in *dst,
            char **data // datagram content, length is returned int
            );


int send_udp_packet_to_tun(
            int tundev, char *buf_reply, size_t bufsize,
            const struct sockaddr_in *src, const struct sockaddr_in *dst, 
            const char *data, size_t datalen, uint16_t *ip_id);
