CFLAGS=-Wall -ggdb
udpnat: udpnat.o tunudp.o

udpnat_static: udpnat.c tunudp.c
	musl-gcc -static -Os -flto  -Wall -I /mnt/src/git/kernel-headers-for-musl/generic/include  -I /mnt/src/git/kernel-headers-for-musl/x86/include/  udpnat.c tunudp.c -o udpnat_static
