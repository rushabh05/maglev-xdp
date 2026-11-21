package maglev

// The paper derives each backend's permutation from two independent hashes of
// its name: offset = h1(name) mod M and skip = h2(name) mod (M-1) + 1. Here
// h1 and h2 are the same 64-bit hash with different seeds.
//
// These hashes are part of the table's contract: every load-balancer instance
// must compute the same table for the same backend set, so changing them (or
// the seeds) changes every table. TestGoldenTable pins the output.
const (
	seedOffset uint64 = 0x9e3779b97f4a7c15
	seedSkip   uint64 = 0xc2b2ae3d27d4eb4f
)

// hash64 is FNV-1a over the seed's 8 bytes and then s, followed by the
// MurmurHash3 64-bit finaliser. FNV-1a alone mixes its low bits poorly for
// short, similar names ("be-1", "be-2", ...); the finaliser fixes that.
// It is deterministic across processes and platforms, unlike hash/maphash.
func hash64(s string, seed uint64) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < 8; i++ {
		h ^= (seed >> (8 * i)) & 0xff
		h *= prime64
	}
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return fmix64(h)
}

func fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}
