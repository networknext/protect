
server_xdp.o: server_xdp.c
	clang -D__linux__ -D__BPF__ -O2 -g -Ilibbpf/src -target bpf -c server_xdp.c -o server_xdp.o
