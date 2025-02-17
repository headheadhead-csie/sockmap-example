all: host-sock_map guest-sock_map

host-sock_map: bpf-verdict.o host-sock_map.c bpf-verdict.skel.h
	gcc host-sock_map.c -lbpf -o host-sock_map

guest-sock_map: bpf-verdict.o guest-sock_map.c bpf-verdict.skel.h
	gcc guest-sock_map.c -lbpf -o guest-sock_map

bpf-verdict.skel.h: bpf-verdict.o
	sudo bpftool gen skeleton bpf-verdict.o > bpf-verdict.skel.h

bpf-verdict.o: bpf-verdict.c
	clang -O2 -g -Wall -target bpf -c bpf-verdict.c -o bpf-verdict.o

clean:
	rm host-sock_map bpf-verdict.o bpf-verdict.skel.h guest-sock_map
