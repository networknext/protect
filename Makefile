# Network Next Makefile

.PHONY: build
build: build/Makefile
	cd build && make -j --no-print-directory

.PHONY: clean
clean: build/Makefile
	cd build && make clean --no-print-directory
	rm -rf dist/*

build/Makefile: build/CMakeLists.txt
	cd build && cmake -DCMAKE_BUILD_TYPE=Release .
