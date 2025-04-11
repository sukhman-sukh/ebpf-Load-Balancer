#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include <string.h>
#include "common.h"


struct ipv4_psd_header {
	uint32_t src_addr; /* IP address of source host. */
	uint32_t dst_addr; /* IP address of destination host. */
	uint16_t len;	   /* L4 length. */
};

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";