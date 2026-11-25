package sketch

import (
	"math"
	"math/bits"
)

// HLL is a HyperLogLog sketch (Flajolet, Fusy, Gandouet and Meunier, 2007)
// of distinct 32-bit keys with m = 2^p registers.
//
// A key is hashed to 64 bits with Hash64. The top p bits pick a register;
// the register keeps the largest ρ seen, where ρ is the position of the
// first 1 bit in the remaining 64-p bits (1-based, capped at 64-p+1).
type HLL struct {
	p    int
	seed uint64
	reg  []uint8
}

// NewHLL returns an empty sketch with 2^p registers (4 <= p <= 18).
func NewHLL(p int, seed uint64) *HLL {
	if p < 4 || p > 18 {
		panic("sketch: HyperLogLog precision out of range")
	}
	return &HLL{p: p, seed: seed, reg: make([]uint8, 1<<p)}
}

// Hash64 is the key hash shared with the XDP program: MurmurHash3's 64-bit
// finaliser applied to key XOR seed. It is a bijection, so distinct keys
// never collide in the full 64 bits.
func Hash64(seed uint64, key uint32) uint64 {
	k := uint64(key) ^ seed
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}

// Add records key.
func (h *HLL) Add(key uint32) {
	x := Hash64(h.seed, key)
	idx := x >> (64 - h.p)
	// The sentinel bit caps ρ at 64-p+1 when the remaining bits are zero.
	rho := uint8(bits.LeadingZeros64(x<<h.p|1<<(h.p-1))) + 1
	if rho > h.reg[idx] {
		h.reg[idx] = rho
	}
}

// M returns the number of registers.
func (h *HLL) M() int { return len(h.reg) }

// StdError is the asymptotic relative standard error 1.04/√m.
func (h *HLL) StdError() float64 { return 1.04 / math.Sqrt(float64(len(h.reg))) }

// Registers returns the registers. The caller must not modify them.
func (h *HLL) Registers() []uint8 { return h.reg }

// Load replaces the registers, e.g. with values read from the kernel.
func (h *HLL) Load(reg []uint8) error {
	if len(reg) != len(h.reg) {
		return ErrMismatch
	}
	copy(h.reg, reg)
	return nil
}

// Merge folds o into h with a register-wise max, which gives exactly the
// sketch of the union of both key sets. Seeds must match.
func (h *HLL) Merge(o *HLL) error {
	if h.p != o.p || h.seed != o.seed {
		return ErrMismatch
	}
	for i, r := range o.reg {
		h.reg[i] = max(h.reg[i], r)
	}
	return nil
}

// Estimate returns the estimated number of distinct keys: the raw
// HyperLogLog estimate α_m m² / Σ 2^-M[j], replaced by linear counting
// m ln(m/V) when the raw estimate is at most 5m/2 and V > 0 registers are
// still zero. With 64-bit hashes no large-range correction is needed.
func (h *HLL) Estimate() float64 {
	m := float64(len(h.reg))
	sum, zeros := 0.0, 0
	for _, r := range h.reg {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	raw := alpha(len(h.reg)) * m * m / sum
	if raw <= 2.5*m && zeros > 0 {
		return m * math.Log(m/float64(zeros))
	}
	return raw
}

func alpha(m int) float64 {
	switch m {
	case 16:
		return 0.673
	case 32:
		return 0.697
	case 64:
		return 0.709
	}
	return 0.7213 / (1 + 1.079/float64(m))
}
