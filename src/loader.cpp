#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <csignal>

// to unload  lb ip link set dev veth6 xdpgeneric off

extern "C" {
#include "common.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		std::cerr << "ERROR - Usage is: " << argv[0]
				  << " <BPF_FILE> <PROG_NAME> <INTERFACE>"
				  << "\n";
		return 1;
	}

	// Open and load the BPF program
	auto obj = bpf_object__open(argv[1]);
	if (bpf_object__load(obj)) {
		std::cerr << "Failed to load program\n";
		return 1;
	}

	auto prog = bpf_object__find_program_by_name(obj, argv[2]);
	bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
	auto progFd = bpf_program__fd(prog);
	auto progName = bpf_program__name(prog);
	std::cout << "Loaded XDP prog with fd " << progFd << " and name "
			  << progName << '\n';

	return 0;
}
