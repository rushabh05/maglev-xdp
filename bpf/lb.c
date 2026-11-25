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
	STAT_DROP_HEAVY,      // from a flagged heavy hitter, with drop_heavy on
	STAT_MAX,
};

// Sketch dimensions. docs/MATH.md derives the guarantees they give.
enum sketch_params {
	CM_DEPTH = 5,      // d = ceil(ln(1/delta)): delta = e^-5 ~ 0.0067
	CM_LOG_WIDTH = 12, // w = 2^12 = 4096 >= e/epsilon: epsilon = e/4096 ~ 6.6e-4
	CM_WIDTH = 1 << CM_LOG_WIDTH,
	HLL_P = 14, // m = 2^14 registers: standard error ~ 1.04/sqrt(m) ~ 0.81%
	HLL_REGISTERS = 1 << HLL_P,
	HEAVY_ENTRIES = 1024,
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

// ---- Traffic sketches (VIP traffic only) -----------------------------------
//
// Count-Min (per-source packet counts) and HyperLogLog (distinct sources per
// VIP), both per CPU so updates need no atomics. Userspace merges the CPUs
// exactly: Count-Min by summing counters, HyperLogLog by taking the
// register-wise max. Each sketch has two buffers; the low bit of the window
// epoch picks the one being written, so userspace can read and clear the
// other one.

volatile const __u32 sketch_enabled = 1;
// Count-Min row i hashes a source with multiply-add-shift,
// (cm_a[i] * src + cm_b[i]) >> (64 - CM_LOG_WIDTH), which is strongly
// universal for 32-bit keys when cm_a[i] and cm_b[i] are uniform random
// 64-bit values (Thorup, "High Speed Hashing for Integers and Strings",
// Theorem 3.5). The loader draws them at random.
volatile const __u64 cm_a[CM_DEPTH] = {};
volatile const __u64 cm_b[CM_DEPTH] = {};
volatile const __u64 hll_seed = 0;

struct sketch_config {
	__u32 epoch;      // window number; its low bit selects the buffer
	__u32 drop_heavy; // drop packets from sources in `heavy`
	__u32 phi_ppm;    // heavy-hitter threshold, parts per million of the window's packets
	__u32 pad;
	__u64 min_count; // and at least this many packets
};

struct heavy_entry {
	__u64 estimate;  // this CPU's Count-Min estimate when flagged
	__u32 epoch;     // window it was last flagged in
	__u32 confirmed; // set by userspace: heavy over a whole closed window
};

struct hll_registers {
	__u8 reg[HLL_REGISTERS];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sketch_config);
} sketch_cfg SEC(".maps");

// Two buffers of CM_DEPTH rows of CM_WIDTH counters, flattened:
// buffer * CM_DEPTH * CM_WIDTH + row * CM_WIDTH + column.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2 * CM_DEPTH * CM_WIDTH);
	__type(key, __u32);
	__type(value, __u64);
} cm SEC(".maps");

// Packets counted into each buffer (N in the Count-Min bound).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} cm_total SEC(".maps");

// Two buffers of one register set per VIP: buffer * MAX_VIPS + VIP index.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2 * MAX_VIPS);
	__type(key, __u32);
	__type(value, struct hll_registers);
} hll SEC(".maps");

// Sources whose Count-Min estimate crossed the threshold. Userspace checks
// each one against the merged sketch at the end of every window and removes
// it if it isn't heavy there.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, HEAVY_ENTRIES);
	__type(key, __be32);
	__type(value, struct heavy_entry);
} heavy SEC(".maps");

// Make the enums visible in BTF so bpf2go can generate Go constants.
const enum stat *unused_stat __attribute__((unused));
const enum sketch_params *unused_sketch_params __attribute__((unused));

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

// MurmurHash3's 64-bit finaliser: a bijection with good avalanche.
static __always_inline __u64 fmix64(__u64 k)
{
	k ^= k >> 33;
	k *= 0xff51afd7ed558ccdULL;
	k ^= k >> 33;
	k *= 0xc4ceb9fe1a85ec53ULL;
	k ^= k >> 33;
	return k;
}

// Count of leading zero bits; x must be non-zero.
static __always_inline __u32 clz64(__u64 x)
{
	__u32 n = 0;
	if (!(x & 0xffffffff00000000ULL)) { n += 32; x <<= 32; }
	if (!(x & 0xffff000000000000ULL)) { n += 16; x <<= 16; }
	if (!(x & 0xff00000000000000ULL)) { n += 8; x <<= 8; }
	if (!(x & 0xf000000000000000ULL)) { n += 4; x <<= 4; }
	if (!(x & 0xc000000000000000ULL)) { n += 2; x <<= 2; }
	if (!(x & 0x8000000000000000ULL)) { n += 1; }
	return n;
}

// observe updates the sketches for one VIP packet from src and returns
// XDP_DROP if the packet should be dropped as part of a flood.
static __always_inline int observe(const struct vip_info *vip, __be32 src)
{
	__u32 zero = 0;
	struct sketch_config *cfg = bpf_map_lookup_elem(&sketch_cfg, &zero);
	if (!cfg)
		return XDP_PASS;
	__u32 epoch = cfg->epoch;
	__u32 buf = epoch & 1;

	// Count-Min: add 1 to one counter per row; the estimate is the
	// smallest of them.
	__u64 est = ~0ULL;
#pragma unroll
	for (int i = 0; i < CM_DEPTH; i++) {
		__u32 col = (cm_a[i] * (__u64)src + cm_b[i]) >> (64 - CM_LOG_WIDTH);
		__u32 key = buf * CM_DEPTH * CM_WIDTH + i * CM_WIDTH + col;
		__u64 *c = bpf_map_lookup_elem(&cm, &key);
		if (!c)
			return XDP_PASS;
		*c += 1;
		if (*c < est)
			est = *c;
	}
	__u64 *total = bpf_map_lookup_elem(&cm_total, &buf);
	if (!total)
		return XDP_PASS;
	*total += 1;

	// HyperLogLog: the top HLL_P bits of the hash pick a register; the
	// register keeps the largest "position of the first 1 bit" seen in the
	// remaining bits. The sentinel bit caps that position at 64 - HLL_P + 1.
	__u32 hkey = buf * MAX_VIPS + vip->index;
	struct hll_registers *regs = bpf_map_lookup_elem(&hll, &hkey);
	if (regs) {
		__u64 h = fmix64((__u64)src ^ hll_seed);
		__u32 idx = h >> (64 - HLL_P);
		__u8 rho = clz64((h << HLL_P) | (1ULL << (HLL_P - 1))) + 1;
		if (rho > regs->reg[idx])
			regs->reg[idx] = rho;
	}

	// Heavy hitters: flag src once this CPU's estimate reaches both
	// min_count and phi of this CPU's packets in the window. A flag is only
	// a candidate; userspace confirms it against the merged sketch.
	if (est >= cfg->min_count && est * 1000000 >= (__u64)cfg->phi_ppm * *total) {
		struct heavy_entry *e = bpf_map_lookup_elem(&heavy, &src);
		if (!e) {
			struct heavy_entry fresh = {.estimate = est, .epoch = epoch};
			bpf_map_update_elem(&heavy, &src, &fresh, BPF_NOEXIST);
		} else if (e->epoch != epoch) {
			e->estimate = est;
			e->epoch = epoch;
		}
	}
	// Drop only confirmed sources, so a per-CPU false positive never
	// drops traffic. Packets are counted above before being dropped, so a
	// source stays confirmed for as long as it keeps flooding.
	if (cfg->drop_heavy) {
		struct heavy_entry *e = bpf_map_lookup_elem(&heavy, &src);
		if (e && e->confirmed)
			return XDP_DROP;
	}
	return XDP_PASS;
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

	if (sketch_enabled && observe(vip, iph->saddr) == XDP_DROP) {
		count(STAT_DROP_HEAVY);
		return XDP_DROP;
	}

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
