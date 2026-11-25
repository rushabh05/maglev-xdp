package sketch

import (
	"errors"
	"math"
	"math/rand/v2"
	"slices"
	"testing"
)

func seeds(rng *rand.Rand, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = rng.Uint64()
	}
	return out
}

func newCM(rng *rand.Rand) *CountMin {
	return NewCountMin(12, seeds(rng, 5), seeds(rng, 5))
}

func TestCountMinParameters(t *testing.T) {
	c := newCM(rand.New(rand.NewPCG(1, 1)))
	if c.Width() != 4096 || c.Depth() != 5 {
		t.Fatalf("shape %dx%d", c.Depth(), c.Width())
	}
	// w = 4096 >= e/ε and d = 5 >= ln(1/δ) for ε = 0.001, δ = 0.01.
	if c.Width() < int(math.Ceil(math.E/0.001)) || float64(c.Depth()) < math.Log(1/0.01) {
		t.Error("shape does not meet ε = 0.001, δ = 0.01")
	}
	if got := c.Epsilon(); math.Abs(got-math.E/4096) > 1e-15 {
		t.Errorf("ε = %v", got)
	}
	if got := c.Delta(); math.Abs(got-math.Exp(-5)) > 1e-15 {
		t.Errorf("δ = %v", got)
	}
}

func TestCountMinNeverUnderestimates(t *testing.T) {
	rng := rand.New(rand.NewPCG(2, 2))
	c := newCM(rng)
	truth := map[uint32]uint64{}
	for range 200_000 {
		k := uint32(rng.IntN(20_000))
		truth[k]++
		if est := c.Add(k); est < truth[k] {
			t.Fatalf("Add returned %d for a key seen %d times", est, truth[k])
		}
	}
	for k, a := range truth {
		if est := c.Estimate(k); est < a {
			t.Fatalf("Estimate(%d) = %d < true count %d", k, est, a)
		}
	}
	if c.Total() != 200_000 {
		t.Errorf("Total = %d", c.Total())
	}
}

// Merging per-CPU sketches must give exactly the sketch of the whole stream.
func TestCountMinMergeIsExact(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 3))
	a, b := seeds(rng, 5), seeds(rng, 5)
	whole := NewCountMin(12, a, b)
	parts := []*CountMin{NewCountMin(12, a, b), NewCountMin(12, a, b), NewCountMin(12, a, b)}
	for range 100_000 {
		k := rng.Uint32()
		whole.Add(k)
		parts[rng.IntN(len(parts))].Add(k)
	}
	merged := NewCountMin(12, a, b)
	for _, p := range parts {
		if err := merged.Merge(p); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(merged.Counters(), whole.Counters()) || merged.Total() != whole.Total() {
		t.Fatal("merged sketch differs from the sketch of the whole stream")
	}
	if err := merged.Merge(newCM(rng)); !errors.Is(err, ErrMismatch) {
		t.Errorf("merging different seeds: err = %v", err)
	}
}

func TestHLLMergeIsExact(t *testing.T) {
	rng := rand.New(rand.NewPCG(4, 4))
	seed := rng.Uint64()
	whole := NewHLL(14, seed)
	parts := []*HLL{NewHLL(14, seed), NewHLL(14, seed), NewHLL(14, seed), NewHLL(14, seed)}
	for range 300_000 {
		k := rng.Uint32()
		whole.Add(k)
		// The same key may land on several "CPUs"; the union counts it once.
		parts[rng.IntN(len(parts))].Add(k)
		if rng.IntN(4) == 0 {
			parts[rng.IntN(len(parts))].Add(k)
		}
	}
	merged := NewHLL(14, seed)
	for _, p := range parts {
		if err := merged.Merge(p); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(merged.Registers(), whole.Registers()) {
		t.Fatal("merged registers differ from the sketch of the whole stream")
	}
	if err := merged.Merge(NewHLL(14, seed+1)); !errors.Is(err, ErrMismatch) {
		t.Errorf("merging different seeds: err = %v", err)
	}
}

func TestHLLBasics(t *testing.T) {
	h := NewHLL(14, 42)
	if got := h.Estimate(); got != 0 {
		t.Errorf("empty estimate = %v", got)
	}
	for k := range uint32(1000) {
		h.Add(k)
		h.Add(k) // duplicates don't count
	}
	if got := h.Estimate(); math.Abs(got-1000)/1000 > 0.02 {
		t.Errorf("estimate for 1000 keys = %.1f", got)
	}
	for _, r := range h.Registers() {
		if r > 64-14+1 {
			t.Fatalf("register value %d exceeds 64-p+1", r)
		}
	}
	if math.Abs(h.StdError()-1.04/128) > 1e-12 {
		t.Errorf("StdError = %v", h.StdError())
	}
}

func TestIsHeavy(t *testing.T) {
	cases := []struct {
		est, total, min uint64
		phi             uint32
		want            bool
	}{
		{999, 100_000, 1000, 10_000, false}, // below min
		{1000, 100_000, 1000, 10_000, true}, // exactly 1% and min
		{1000, 100_001, 1000, 10_000, false},
		{50, 100, 10, 500_000, true},
	}
	for _, c := range cases {
		if got := IsHeavy(c.est, c.total, c.min, c.phi); got != c.want {
			t.Errorf("IsHeavy(%+v) = %v", c, got)
		}
	}
}
