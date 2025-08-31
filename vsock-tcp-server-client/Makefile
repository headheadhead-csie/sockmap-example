all: tcp-client-sock_map tcp-server-sock_map

tcp-server-sock_map: bpf-verdict.o tcp-server-sock_map.c sock_map.h bpf-verdict.skel.h
	gcc tcp-server-sock_map.c -lbpf -o tcp-server-sock_map -Wall

tcp-client-sock_map: bpf-verdict.o tcp-client-sock_map.c sock_map.h bpf-verdict.skel.h
	gcc tcp-client-sock_map.c -lbpf -o tcp-client-sock_map -Wall

bpf-verdict.skel.h: bpf-verdict.o
	sudo bpftool gen skeleton bpf-verdict.o > bpf-verdict.skel.h

bpf-verdict.o: bpf-verdict.c
	clang -O2 -g -Wall -target bpf -c bpf-verdict.c -o bpf-verdict.o

clean:
	rm tcp-client-sock_map tcp-server-sock_map bpf-verdict.o bpf-verdict.skel.h
