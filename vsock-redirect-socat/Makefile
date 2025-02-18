all: sock_map

sock_map: bpf-verdict.o sock_map.c bpf-verdict.skel.h
	gcc sock_map.c -lbpf -o sock_map

bpf-verdict.skel.h: bpf-verdict.o
	sudo bpftool gen skeleton bpf-verdict.o > bpf-verdict.skel.h

bpf-verdict.o: bpf-verdict.c
	clang -O2 -g -Wall -target bpf -c bpf-verdict.c -o bpf-verdict.o

clean:
	rm sock_map bpf-verdict.o bpf-verdict.skel.h
