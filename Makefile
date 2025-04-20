LIBBPF_HEADERS := external/libbpf/src/install-dir/usr/include
LIBBPF_SOURCE  := external/libbpf/src/install-dir/usr/lib64
CXXFLAGS = -I$(LIBBPF_HEADERS) -g -Wall

LOADER := loader
BPF_PROG := load_balancer.bpf.o
BUILD_DIR := build

all: $(LOADER) $(BPF_PROG)

$(BUILD_DIR)/loader.o: src/loader.cpp
	mkdir -p $(BUILD_DIR)
	g++ $(CXXFLAGS) -c $< -o $@

$(LOADER): $(BUILD_DIR)/loader.o
	mkdir -p $(BUILD_DIR)
	g++ -o build/$@ $^ $(LIBBPF_SOURCE)/libbpf.a -lelf -lz

$(BPF_PROG): src/load_balancer.bpf.c
	mkdir -p $(BUILD_DIR)
	clang -target bpf -I$(LIBBPF_HEADERS) -I/usr/include/aarch64-linux-gnu -O2 -c $^ -o $(BUILD_DIR)/$(BPF_PROG)

clean:
	rm -r $(BUILD_DIR)/*
