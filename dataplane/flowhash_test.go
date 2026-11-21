package dataplane

import (
	"net/netip"
	"testing"
)

// Published MurmurHash3_x86_32 test vectors, so the Go side is checked
// against the reference algorithm and not just against itself.
func TestMurmur3Vectors(t *testing.T) {
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0, 0},
		{"", 1, 0x514e28b7},
		{"", 0xffffffff, 0x81f16f39},
		{"\x00\x00\x00\x00", 0, 0x2362f9de},
		{"aaaa", 0x9747b28c, 0x5a97808a},
		{"aaa", 0x9747b28c, 0x283e0130},
		{"aa", 0x9747b28c, 0x5d211726},
		{"a", 0x9747b28c, 0x7fa09ea6},
		{"Hello, world!", 0x9747b28c, 0x24884cba},
		{"The quick brown fox jumps over the lazy dog", 0x9747b28c, 0x2fa826cd},
	}
	for _, c := range cases {
		if got := murmur3([]byte(c.in), c.seed); got != c.want {
			t.Errorf("murmur3(%q, %#x) = %#x, want %#x", c.in, c.seed, got, c.want)
		}
	}
}

func TestFlowHashIsMurmurOfThePacketBytes(t *testing.T) {
	f := Flow{
		Src:     netip.MustParseAddr("192.0.2.1"),
		Dst:     netip.MustParseAddr("198.51.100.10"),
		SrcPort: 40000,
		DstPort: 443,
		Proto:   TCP,
	}
	key := []byte{
		192, 0, 2, 1, // src
		198, 51, 100, 10, // dst
		0x9c, 0x40, // 40000
		0x01, 0xbb, // 443
		6, 0, 0, 0, // proto, padding
	}
	if got, want := FlowHash(f), murmur3(key, flowHashSeed); got != want {
		t.Fatalf("FlowHash = %#x, want %#x", got, want)
	}

	// Every field must affect the hash.
	base := FlowHash(f)
	variants := []Flow{f, f, f, f, f}
	variants[0].Src = netip.MustParseAddr("192.0.2.2")
	variants[1].Dst = netip.MustParseAddr("198.51.100.11")
	variants[2].SrcPort++
	variants[3].DstPort++
	variants[4].Proto = UDP
	for i, v := range variants {
		if FlowHash(v) == base {
			t.Errorf("variant %d hashes the same as the base flow", i)
		}
	}
}
