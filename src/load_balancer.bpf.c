#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include <string.h>
#include "common.h"

#define NUM_SERVERS 2
#define HASH_SEED 0xDEADBEEF

#define MAX_OPT_WORDS 10 // 40 bytes for options
#define MAX_TARGET_COUNT 64
#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END) \
	(((void *)PTR) + OFFSET > ((void *)END))

struct ipv4_psd_header
{
	uint32_t src_addr; /* IP address of source host. */
	uint32_t dst_addr; /* IP address of destination host. */
	uint8_t zero;	   /* zero. */
	uint8_t proto;	   /* L4 protocol type. */
	uint16_t len;	   /* L4 length. */
};

/**
 * Map that holds the information for the target servers
 * You can assume that this map will always have two elements populated when
 * loading the XDP program
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct ip_mac_pair);
	__uint(max_entries, MAX_TARGET_COUNT);
} targets_map SEC(".maps");

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	if (CHECK_OUT_OF_BOUNDS(data, sizeof(struct ethhdr), data_end))
		return XDP_DROP;

	/* Extract the ethernet header. */
	struct ethhdr *eth = data;

	/* Extract the IP header. */
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (CHECK_OUT_OF_BOUNDS(ip, sizeof(struct iphdr), data_end))
		return XDP_DROP;

	/* Allow the packet to pass if not TCP. */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* Extract the TCP header. */
	struct tcphdr *tcph = data + sizeof(struct ethhdr) + (ip->ihl * 4);
	if (CHECK_OUT_OF_BOUNDS(tcph, sizeof(struct tcphdr), data_end))
		return XDP_DROP;

	/* Lookup IP and MAC addresses for client, load balancer and severs. */
	__u32 local_config_key = 0;
	__u32 client_config_key = 1;
	__u32 server_config_key = get_target_key(ip->saddr, ip->daddr, tcph->source, tcph->dest, ip->protocol);

	struct ip_mac_pair *server_config = bpf_map_lookup_elem(&targets_map, &server_config_key);

	/* Set the source IP and ethernet addresses. */
	ip->saddr = htonl(server_config->ip);
	memcpy(&eth->h_source, server_config->mac.addr, 6);

	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";