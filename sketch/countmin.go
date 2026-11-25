// Package sketch has reference implementations of the two streaming sketches
// the XDP program keeps: a Count-Min sketch of packets per source address and
// a HyperLogLog of distinct source addresses. Given the same seeds and the
// same packets they produce exactly the counters and registers the kernel
// does; the dataplane tests check that bit for bit.
//
// docs/MATH.md derives the error bounds quoted here.
package sketch

import (
	"errors"
	"math"
	"slices"
)

// ErrMismatch is returned when merging sketches with different shapes or seeds.
var ErrMismatch = errors.New("sketch: shapes or seeds differ")

// CountMin is a Count-Min sketch (Cormode and Muthukrishnan, 2005) over
// 32-bit keys: depth rows of width = 2^logWidth counters. Row i maps a key to
// column (a[i]*key + b[i]) >> (64 - logWidth), computed mod 2^64. With a[i],
// b[i] uniform random 64-bit values this hash is strongly universal (Thorup,
// "High Speed Hashing for Integers and Strings", Theorem 3.5), which is all
// the error bound needs.
//
// For a key with true count a among N updates, the estimate â satisfies
// a <= â always, and â <= a + εN with probability at least 1 - δ, where
// ε = e/width and δ = e^-depth.
type CountMin struct {
	logWidth int
	a, b     []uint64
	counts   []uint64 // row-major: row*width + column
	total    uint64
}

// NewCountMin returns an empty sketch with len(a) rows of 2^logWidth
// counters. a and b are the per-row hash seeds and must have equal length.
func NewCountMin(logWidth int, a, b []uint64) *CountMin {
	if len(a) != len(b) || len(a) == 0 || logWidth < 1 || logWidth > 32 {
		panic("sketch: bad Count-Min shape")
	}
	return &CountMin{
		logWidth: logWidth,
		a:        slices.Clone(a),
		b:        slices.Clone(b),
		counts:   make([]uint64, len(a)<<logWidth),
	}
}

// Depth is the number of rows, d.
func (c *CountMin) Depth() int { return len(c.a) }

// Width is the number of counters per row, w.
func (c *CountMin) Width() int { return 1 << c.logWidth }

// Epsilon is the additive error factor e/w.
func (c *CountMin) Epsilon() float64 { return math.E / float64(c.Width()) }

// Delta is the failure probability e^-d.
func (c *CountMin) Delta() float64 { return math.Exp(-float64(c.Depth())) }

// Column returns the counter that row i uses for key.
func (c *CountMin) Column(i int, key uint32) int {
	return int((c.a[i]*uint64(key) + c.b[i]) >> (64 - c.logWidth))
}

// Add counts one occurrence of key and returns the new estimate for it,
// exactly as the XDP program does.
func (c *CountMin) Add(key uint32) uint64 {
	est := uint64(math.MaxUint64)
	w := c.Width()
	for i := range c.a {
		j := i*w + c.Column(i, key)
		c.counts[j]++
		est = min(est, c.counts[j])
	}
	c.total++
	return est
}

// Estimate returns the smallest of key's counters.
func (c *CountMin) Estimate(key uint32) uint64 {
	est := uint64(math.MaxUint64)
	w := c.Width()
	for i := range c.a {
		est = min(est, c.counts[i*w+c.Column(i, key)])
	}
	return est
}

// Total is N, the number of updates.
func (c *CountMin) Total() uint64 { return c.total }

// Bound returns ⌊εN⌋: with probability at least 1-δ, a key's true count is
// within [Estimate - Bound, Estimate].
func (c *CountMin) Bound() uint64 { return uint64(c.Epsilon() * float64(c.total)) }

// Counters returns the counters, row-major. The caller must not modify them.
func (c *CountMin) Counters() []uint64 { return c.counts }

// Load replaces the counters and total, e.g. with values read from the
// kernel. counts must be row-major with Depth()*Width() entries.
func (c *CountMin) Load(counts []uint64, total uint64) error {
	if len(counts) != len(c.counts) {
		return ErrMismatch
	}
	copy(c.counts, counts)
	c.total = total
	return nil
}

// Merge adds o into c. A Count-Min sketch is linear, so the result is
// exactly the sketch of both streams together. Seeds must match.
func (c *CountMin) Merge(o *CountMin) error {
	if c.logWidth != o.logWidth || !slices.Equal(c.a, o.a) || !slices.Equal(c.b, o.b) {
		return ErrMismatch
	}
	for i, v := range o.counts {
		c.counts[i] += v
	}
	c.total += o.total
	return nil
}

// IsHeavy is the heavy-hitter rule the XDP program applies (per CPU) and
// userspace applies again on the merged sketch: an estimate is heavy if it is
// at least minCount and at least phiPPM parts per million of total.
func IsHeavy(estimate, total, minCount uint64, phiPPM uint32) bool {
	return estimate >= minCount && estimate*1_000_000 >= uint64(phiPPM)*total
}
