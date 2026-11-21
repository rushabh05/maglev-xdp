// XDP data plane for maglev-xdp: an L4 load balancer for IPv4 TCP and UDP.
//
// For each packet addressed to a configured VIP (address, port, protocol):
//   1. If the flow is in the connection-tracking map and its backend still
//      exists, use that backend.
//   2. Otherwise hash the 5-tuple, pick the backend from the VIP's Maglev
//      table, and remember the choice in the connection-tracking map.
//   3. Forward with XDP_TX, either by rewriting the MAC addresses (L2 mode) or
//      by wrapping the packet in an outer IPv4 header (IP-in-IP mode).
// Everything else (non-IPv4, IP options, fragments, other protocols, traffic
// for other addresses) is passed to the kernel untouched.
//
// The Go control plane (package dataplane) builds the Maglev tables and fills
// the maps. FlowHash in dataplane/flowhash.go must stay in step with
// flow_hash() below; TestDataplaneMatchesGo checks that they agree.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_VIPS 16
#define MAX_BACKENDS 4096
#define CONNTRACK_ENTRIES 65536

#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

enum mode {
	MODE_L2 = 0,
	MODE_IPIP = 1,
};

enum stat {
	STAT_RX,              // packets seen
	STAT_PASS,            // not for a VIP: handed to the kernel
	STAT_TX,              // forwarded to a backend
	STAT_DROP_NO_BACKEND, // for a VIP that has no backends
	STAT_DROP_ERROR,      // could not encapsulate
	STAT_CT_HIT,          // backend came from connection tracking
	STAT_CT_MISS,         // backend came from the Maglev table
	STAT_MAX,
};

// Set by the loader before the program is loaded (they live in .rodata, so
// the verifier sees them as constants).
volatile const __u32 table_size = 65537; // Maglev table size M per VIP (prime)
volatile const __u32 mode = MODE_L2;
volatile const __be32 lb_addr = 0; // outer source address in IP-in-IP mode

struct vip_key {
	__be32 addr;
	__be16 port;
	__u8 proto;
	__u8 pad;
};

struct vip_info {
	__u32 index; // which MAX_VIPS slice of `tables` holds this VIP's table
};

struct backend {
	__be32 addr;
	__u8 mac[ETH_ALEN]; // next-hop MAC for reaching addr
	__u16 pad;
};

struct flow {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8 proto;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_VIPS);
	__type(key, struct vip_key);
	__type(value, struct vip_info);
} vips SEC(".maps");

// MAX_VIPS Maglev tables back to back: slot s of VIP i is at
// i * table_size + s. Values are backend IDs; 0 means "no backend". The
// loader sets max_entries to MAX_VIPS * table_size.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} tables SEC(".maps");

// Backend ID -> where to send. IDs are never reused, so a connection-tracking
// entry can't end up pointing at a different backend than it was made for.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct backend);
} backends SEC(".maps");

// Flow -> backend ID, so established flows keep their backend when the
// Maglev table changes. Least recently used entries are evicted when full.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CONNTRACK_ENTRIES);
	__type(key, struct flow);
	__type(value, __u32);
} conntrack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// Make the enum visible in BTF so bpf2go can generate Go constants for it.
const enum stat *unused_stat __attribute__((unused));

static __always_inline void count(__u32 stat)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &stat);
	if (v)
		*v += 1;
}

static __always_inline __u32 rotl32(__u32 x, __u32 r)
{
	return (x << r) | (x >> (32 - r));
}

static __always_inline __u32 murmur_round(__u32 h, __u32 k)
{
	k *= 0xcc9e2d51;
	k = rotl32(k, 15);
	k *= 0x1b873593;
	h ^= k;
	h = rotl32(h, 13);
	return h * 5 + 0xe6546b64;
}

// MurmurHash3_x86_32 of the 16-byte flow key (saddr, daddr, sport, dport,
// proto, 3 zero bytes) as the bytes appear in the packet, read as four
// little-endian words. This program is built for little-endian targets only.
static __always_inline __u32 flow_hash(const struct flow *f)
{
	__u32 h = 0x4d474c56; // seed: "MGLV"

	h = murmur_round(h, f->saddr);
	h = murmur_round(h, f->daddr);
	h = murmur_round(h, (__u32)f->sport | ((__u32)f->dport << 16));
	h = murmur_round(h, f->proto);

	h ^= 16; // input length in bytes
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

static __always_inline struct backend *pick_backend(const struct vip_info *vip,
						    struct flow *f)
{
	__u32 *pinned = bpf_map_lookup_elem(&conntrack, f);
	if (pinned) {
		struct backend *be = bpf_map_lookup_elem(&backends, pinned);
		if (be) {
			count(STAT_CT_HIT);
			return be;
		}
		// The backend was removed: fall through and pick a new one.
	}
	count(STAT_CT_MISS);

	__u32 slot = vip->index * table_size + flow_hash(f) % table_size;
	__u32 *id = bpf_map_lookup_elem(&tables, &slot);
	if (!id || *id == 0)
		return NULL;

	__u32 backend_id = *id;
	struct backend *be = bpf_map_lookup_elem(&backends, &backend_id);
	if (!be)
		return NULL;

	bpf_map_update_elem(&conntrack, f, &backend_id, BPF_ANY);
	return be;
}

static __always_inline __u16 ip_checksum(const struct iphdr *iph)
{
	const __u16 *p = (const __u16 *)iph;
	__u32 sum = 0;

#pragma unroll
	for (int i = 0; i < (int)(sizeof(*iph) / 2); i++)
		sum += p[i];
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

// L2 mode (direct server return): keep the IP packet as is, send the frame to
// the backend's MAC. The backend must be on the same L2 segment and accept
// traffic for the VIP (for example, VIP on its loopback interface).
static __always_inline int forward_l2(struct ethhdr *eth, const struct backend *be)
{
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);
	count(STAT_TX);
	return XDP_TX;
}

// IP-in-IP mode: prepend an outer IPv4 header from lb_addr to the backend.
// The backend decapsulates (an ipip tunnel device) and replies to the client
// directly.
static __always_inline int forward_ipip(struct xdp_md *ctx, const struct backend *be)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *old_eth = data;
	struct iphdr *inner = (void *)(old_eth + 1);
	if ((void *)(inner + 1) > data_end)
		return XDP_DROP;

	// Read everything needed from the old headers before moving them.
	__u8 lb_mac[ETH_ALEN];
	__builtin_memcpy(lb_mac, old_eth->h_dest, ETH_ALEN);
	__u16 inner_len = bpf_ntohs(inner->tot_len);
	__u8 tos = inner->tos;
	if (inner_len > 0xffff - sizeof(struct iphdr)) {
		count(STAT_DROP_ERROR);
		return XDP_DROP;
	}

	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr))) {
		count(STAT_DROP_ERROR);
		return XDP_DROP;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *outer = (void *)(eth + 1);
	if ((void *)(outer + 1) > data_end) {
		count(STAT_DROP_ERROR);
		return XDP_DROP;
	}

	__builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, lb_mac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	outer->version = 4;
	outer->ihl = 5;
	outer->tos = tos;
	outer->tot_len = bpf_htons(inner_len + sizeof(struct iphdr));
	outer->id = 0;
	outer->frag_off = 0;
	outer->ttl = 64;
	outer->protocol = IPPROTO_IPIP;
	outer->check = 0;
	outer->saddr = lb_addr;
	outer->daddr = be->addr;
	outer->check = ip_checksum(outer);

	count(STAT_TX);
	return XDP_TX;
}

static __always_inline int pass(void)
{
	count(STAT_PASS);
	return XDP_PASS;
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	count(STAT_RX);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return pass();
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return pass();

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return pass();
	// No IP options, and no fragments: only the first fragment has ports.
	if (iph->version != 4 || iph->ihl != 5)
		return pass();
	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return pass();
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return pass();

	// TCP and UDP both start with the source and destination ports.
	__be16 *ports = (void *)(iph + 1);
	if ((void *)(ports + 2) > data_end)
		return pass();

	struct vip_key vk = {};
	vk.addr = iph->daddr;
	vk.port = ports[1];
	vk.proto = iph->protocol;
	struct vip_info *vip = bpf_map_lookup_elem(&vips, &vk);
	if (!vip)
		return pass();

	struct flow f = {};
	f.saddr = iph->saddr;
	f.daddr = iph->daddr;
	f.sport = ports[0];
	f.dport = ports[1];
	f.proto = iph->protocol;

	struct backend *be = pick_backend(vip, &f);
	if (!be) {
		count(STAT_DROP_NO_BACKEND);
		return XDP_DROP;
	}

	if (mode == MODE_IPIP)
		return forward_ipip(ctx, be);
	return forward_l2(eth, be);
}

// The kernel requires a license string; this is a placeholder until the
// project picks a license.
char LICENSE[] SEC("license") = "Dual MIT/GPL";
