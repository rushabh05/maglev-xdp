package dataplane

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"strconv"
)

// Proto is an IP protocol number.
type Proto uint8

// Protocols the data plane balances.
const (
	TCP Proto = 6
	UDP Proto = 17
)

func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "proto(" + strconv.Itoa(int(p)) + ")"
}

// Flow is the 5-tuple the data plane hashes to choose a backend.
type Flow struct {
	Src, Dst         netip.Addr // must be IPv4
	SrcPort, DstPort uint16
	Proto            Proto
}

const flowHashSeed = 0x4d474c56 // "MGLV"

// FlowHash returns the hash the XDP program computes for f:
// MurmurHash3_x86_32 with seed "MGLV" over the 16-byte key
//
//	src (4) | dst (4) | src port (2, big endian) | dst port (2, big endian) | proto (1) | 0 0 0
//
// which is how those fields appear in the packet. The data plane's slot for
// the flow is FlowHash(f) mod M, so Table.Lookup(uint64(FlowHash(f))) predicts
// its choice for a flow that isn't already in connection tracking.
//
// FlowHash panics if Src or Dst is not an IPv4 address.
func FlowHash(f Flow) uint32 {
	var key [16]byte
	src, dst := f.Src.As4(), f.Dst.As4()
	copy(key[0:4], src[:])
	copy(key[4:8], dst[:])
	binary.BigEndian.PutUint16(key[8:10], f.SrcPort)
	binary.BigEndian.PutUint16(key[10:12], f.DstPort)
	key[12] = byte(f.Proto)
	return murmur3(key[:], flowHashSeed)
}

// murmur3 is MurmurHash3_x86_32 (Austin Appleby, public domain).
func murmur3(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := binary.LittleEndian.Uint32(data[4*i:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}

	tail := data[4*n:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}

	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
