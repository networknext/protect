
server_xdp_xdp.o: server_xdp_xdp.c server_xdp_shared.h server_xdp_constants.h
	clang -D__linux__ -D__BPF__ -O2 -g -Ilibbpf/src -target bpf -c server_xdp_xdp.c -o server_xdp_xdp.o
