
KERNEL = $(shell uname -r)

.PHONY: build
build: *.c *.h client_backend_xdp_source.h
	gcc -DCOMPILE_WITH_BPF=1 -O2 -g client_backend.c client_backend_platform.c client_backend_base64.c client_backend_main.c client_backend_bpf.c client_backend_config.c -o client_backend -lxdp -lsodium -lcurl -lbpf -lz -lelf

.PHONY: clean
clean:
	rm -f client_backend
	rm -f client_backend_xdp_source.h
	rm -f *.o

client_backend_xdp.o: client_backend_xdp.c client_backend_shared.h client_backend_constants.h
	clang -O2 -g -Ilibbpf/src -target bpf -c client_backend_xdp.c -o client_backend_xdp.o

client_backend_xdp_source.h: Makefile client_backend_xdp.c client_backend_shared.h client_backend_constants.h
	mkdir -p client_backend_xdp_source
	cp Makefile client_backend_xdp_source
	cp client_backend_xdp.c client_backend_xdp_source
	cp client_backend_shared.h client_backend_xdp_source
	cp client_backend_constants.h client_backend_xdp_source
	cd client_backend_xdp_source && tar -zcvf ../client_backend_xdp_source.tar.gz * && cd ..
	rm -rf client_backend_xdp_source
	xxd -i client_backend_xdp_source.tar.gz > client_backend_xdp_source.h
