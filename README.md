# udpnat

P2P-friendly UDP-only NAT for Linux.

Usually NAT is set up on Linux box with this command:

    iptables -t nat -A POSTROUTING -j MASQUERADE

This makes port-restricted cone NAT which is not friendly to UDP hole punching used by peer-to-peer applications.

This program is a simple user-space NAT that decodes UDP packets sent to TUN interface and uses usual non-raw sockets for outgoing connections, somewhat like SLiRP.

```
host@user$ stun stun.counterpath.net
Primary: Independent Mapping, Port Dependent Filter, preserves ports, no hairpin

gateway@root# ip tuntap add dev udpnat mode tun user udpnat_user
gateway@root# ip link set udpnat up
gateway@root# echo 0 > /proc/sys/net/ipv4/conf/udpnat/rp_filter
gateway@root# echo 1 > /proc/sys/net/ipv4/conf/udpnat/forwarding
gateway@root# iptables -t mangle -I PREROUTING -i tun0 -p udp ! --dport 53 -j MARK --set-xmark 44
gateway@root# iptables -t mangle -I PREROUTING -i udpnat -p udp -j MARK --set-xmark 45
gateway@root# iptables -t nat -I POSTROUTING -m mark --mark 44 -j RETURN
gateway@root# iptables -t nat -I POSTROUTING -m mark --mark 45 -j RETURN
gateway@root# ip route add default dev udpnat table 44
gateway@root# ip rule add fwmark 44 table 44
gateway@udpnat_user$ ulimit -n 8192
gateway@udpnat_user$ udpnat /dev/net/tun udpnat 60

host@user$ stun stun.counterpath.net
Primary: Independent Mapping, Independent Filter, preserves ports, no hairpin
```

Limitations:

* IPv4 only
* No fragmented packets support
* Limited error handling
* Limited scalability (O_ASYNC-based event loop) - use multipath (nexthop) routing if you want more than 5000 connections. 1 routed packet = 4 syscalls.
* Limited configurability
* Security issues if naively used (for example, the snippet above is insecure)
* No UDP checksums

There is x86_64 static musl-based version on Github releases.

License: MIT or Apache 2.0.
