package maglev

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"slices"
	"testing"
)

func names(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("be-%03d", i+1)
	}
	return out
}

func mustBuild(t testing.TB, backends []string, size int) *Table {
	t.Helper()
	tb, err := Build(backends, size)
	if err != nil {
		t.Fatalf("Build(%d backends, size %d): %v", len(backends), size, err)
	}
	return tb
}

// TestPaperExample reproduces Table 1 of the paper: M = 7 and three backends
// whose (offset, skip) pairs are (3, 4), (0, 2) and (3, 1). Removing B2
// changes B2's two slots plus exactly one other (the last row).
func TestPaperExample(t *testing.T) {
	const (
		b1 = 0
		b2 = 1
		b3 = 2
	)
	before := fill([]uint64{3, 0, 3}, []uint64{4, 2, 1}, 7)
	if want := []uint32{b2, b1, b2, b1, b3, b3, b1}; !slices.Equal(before, want) {
		t.Errorf("before = %v, want %v", before, want)
	}

	// Without B2, B1 is index 0 and B3 is index 1.
	after := fill([]uint64{3, 3}, []uint64{4, 1}, 7)
	if want := []uint32{0, 0, 0, 0, 1, 1, 1}; !slices.Equal(after, want) {
		t.Errorf("after = %v, want %v", after, want)
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	cases := []struct {
		name     string
		backends []string
		size     int
		want     error
	}{
		{"size 0", names(1), 0, ErrSizeNotPrime},
		{"size 1", names(1), 1, ErrSizeNotPrime},
		{"negative size", names(1), -7, ErrSizeNotPrime},
		{"power of two", names(1), 65536, ErrSizeNotPrime},
		{"odd composite", names(1), 65535, ErrSizeNotPrime},
		{"too large", names(1), MaxSize + 1, ErrSizeTooLarge},
		{"empty name", []string{"a", ""}, 13, ErrEmptyName},
		{"duplicate", []string{"a", "b", "a"}, 13, ErrDuplicate},
		{"more backends than slots", names(8), 7, ErrTooManyBackends},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Build(c.backends, c.size); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// Each backend takes one slot per round, so shares differ by at most one
// slot: every backend owns floor(M/N) or ceil(M/N) entries.
func TestEveryBackendGetsAnEqualShare(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 10, 100, 1000} {
		for _, size := range []int{7919, DefaultSize} {
			if n > size {
				continue
			}
			tb := mustBuild(t, names(n), size)
			lo, hi := size/n, (size+n-1)/n
			total := 0
			for i, c := range tb.Counts() {
				if c < lo || c > hi {
					t.Errorf("N=%d M=%d: %s owns %d slots, want %d..%d", n, size, tb.Backends()[i], c, lo, hi)
				}
				total += c
			}
			if total != size {
				t.Errorf("N=%d M=%d: slots owned = %d, want %d", n, size, total, size)
			}
		}
	}
}

// The table must depend only on the backend set, so separate load-balancer
// instances agree regardless of the order they learned about backends in.
func TestOrderDoesNotMatter(t *testing.T) {
	want := mustBuild(t, names(50), DefaultSize)
	rng := rand.New(rand.NewPCG(1, 2))
	for range 5 {
		shuffled := names(50)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := mustBuild(t, shuffled, DefaultSize)
		if !slices.Equal(got.Entries(), want.Entries()) || !slices.Equal(got.Backends(), want.Backends()) {
			t.Fatal("table changed when backends were given in a different order")
		}
	}
}

// TestGoldenTable pins the table for a fixed backend set. It is a regression
// guard, not a correctness proof: if it fails, the hashes or the population
// loop changed, and tables built by old and new binaries would disagree.
func TestGoldenTable(t *testing.T) {
	tb := mustBuild(t, names(5), DefaultSize)
	h := fnv.New64a()
	buf := make([]byte, 4)
	for _, e := range tb.Entries() {
		binary.LittleEndian.PutUint32(buf, e)
		h.Write(buf)
	}
	const want = 0x4c67e140e6519d80
	if got := h.Sum64(); got != want {
		t.Fatalf("table checksum = %#x, want %#x", got, uint64(want))
	}
}

func TestLookup(t *testing.T) {
	tb := mustBuild(t, names(5), 13)
	backends, entries := tb.Backends(), tb.Entries()
	for _, h := range []uint64{0, 1, 12, 13, 14, 1 << 32, ^uint64(0)} {
		got, ok := tb.Lookup(h)
		if want := backends[entries[h%13]]; !ok || got != want {
			t.Errorf("Lookup(%d) = %q, %v; want %q, true", h, got, ok, want)
		}
	}
}

func TestEmptyTable(t *testing.T) {
	tb := mustBuild(t, nil, 13)
	if _, ok := tb.Lookup(42); ok {
		t.Error("Lookup on an empty table reported a backend")
	}
	if tb.Len() != 0 || tb.Size() != 13 || tb.Entries() != nil || len(tb.Counts()) != 0 {
		t.Errorf("empty table: Len=%d Size=%d Entries=%v Counts=%v", tb.Len(), tb.Size(), tb.Entries(), tb.Counts())
	}
}

func TestCompare(t *testing.T) {
	a := mustBuild(t, names(5), 13)
	if d, _ := Compare(a, a); d.Changed != 0 {
		t.Errorf("table vs itself: %+v", d)
	}

	empty := mustBuild(t, nil, 13)
	for _, pair := range [][2]*Table{{a, empty}, {empty, a}} {
		d, err := Compare(pair[0], pair[1])
		if err != nil || d.Changed != 13 || d.Necessary != 13 || d.Extra != 0 {
			t.Errorf("to/from empty: %+v, %v", d, err)
		}
	}

	if _, err := Compare(a, mustBuild(t, names(5), 17)); !errors.Is(err, ErrSizeMismatch) {
		t.Errorf("different sizes: err = %v, want %v", err, ErrSizeMismatch)
	}

	// Swapping one backend for another: every slot of the old one changes,
	// and all of those changes are necessary.
	b := mustBuild(t, append(names(4), "replacement"), 13)
	d, err := Compare(a, b)
	if err != nil || d.Necessary < a.Counts()[4] || d.Changed != d.Necessary+d.Extra {
		t.Errorf("replace one backend: %+v, %v", d, err)
	}
}
