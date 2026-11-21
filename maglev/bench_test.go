package maglev

import (
	"fmt"
	"testing"
)

// The paper reports 1.8 ms (M=65537) and 22.9 ms (M=655373) to generate a
// table on its hardware. These benchmarks measure the same thing here.
func BenchmarkBuild(b *testing.B) {
	for _, c := range []struct{ size, n int }{
		{DefaultSize, 10}, {DefaultSize, 100}, {DefaultSize, 1000}, {655373, 100}, {655373, 1000},
	} {
		backends := names(c.n)
		b.Run(fmt.Sprintf("M=%d/N=%d", c.size, c.n), func(b *testing.B) {
			for range b.N {
				if _, err := Build(backends, c.size); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLookup(b *testing.B) {
	p, err := NewPool(DefaultSize, names(100)...)
	if err != nil {
		b.Fatal(err)
	}
	h := uint64(0)
	for range b.N {
		p.Lookup(h)
		h += 0x9e3779b97f4a7c15
	}
}
