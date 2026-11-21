// Package maglev implements Maglev consistent hashing, as described in
// "Maglev: A Fast and Reliable Software Network Load Balancer"
// (Eisenbud et al., NSDI '16), section 3.4.
//
// A Table maps a flow hash to a backend with one modulo and one array read.
// Tables are immutable once built. Pool owns a backend set and swaps in a
// freshly built Table on every change, so a reader never sees a table that is
// half populated.
package maglev

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// DefaultSize is the lookup-table size used in the paper. It must be prime;
// 65537 (2^16 + 1) is.
const DefaultSize = 65537

// MaxSize bounds the table so slot and backend indexes always fit in a uint32
// (the key and value type of the BPF array map the data plane will read) and
// the table stays a reasonable size in memory (64 MiB at the limit).
const MaxSize = 1 << 24

var (
	// ErrSizeNotPrime is returned when the table size is not a prime.
	ErrSizeNotPrime = errors.New("maglev: table size must be prime")
	// ErrSizeTooLarge is returned when the table size exceeds MaxSize.
	ErrSizeTooLarge = errors.New("maglev: table size exceeds MaxSize")
	// ErrTooManyBackends is returned when there are more backends than slots.
	ErrTooManyBackends = errors.New("maglev: more backends than table slots")
	// ErrEmptyName is returned for a backend with an empty name.
	ErrEmptyName = errors.New("maglev: backend name is empty")
	// ErrDuplicate is returned when a backend name appears twice.
	ErrDuplicate = errors.New("maglev: duplicate backend")
	// ErrNotFound is returned when removing a backend that is not present.
	ErrNotFound = errors.New("maglev: backend not found")
	// ErrSizeMismatch is returned when comparing tables of different sizes.
	ErrSizeMismatch = errors.New("maglev: tables have different sizes")
)

// Table is a populated Maglev lookup table. It is safe for concurrent use
// because it is never modified after Build returns.
type Table struct {
	size     int
	backends []string // sorted; an entry's value is an index into this slice
	entries  []uint32 // slot -> backend index; nil when there are no backends
}

// Build populates a lookup table of the given prime size for the backends.
//
// Backends are identified by name. The result depends only on the set of
// names and the size, not on their order, so every load-balancer instance
// given the same backend set builds a byte-identical table.
func Build(backends []string, size int) (*Table, error) {
	if err := checkSize(size); err != nil {
		return nil, err
	}
	names := slices.Clone(backends)
	slices.Sort(names)
	for i, name := range names {
		if name == "" {
			return nil, ErrEmptyName
		}
		if i > 0 && name == names[i-1] {
			return nil, fmt.Errorf("%w: %q", ErrDuplicate, name)
		}
	}
	if len(names) > size {
		return nil, fmt.Errorf("%w: %d backends, %d slots", ErrTooManyBackends, len(names), size)
	}
	t := &Table{size: size, backends: names}
	if len(names) > 0 {
		t.entries = populate(names, size)
	}
	return t, nil
}

func checkSize(size int) error {
	if size > MaxSize {
		return fmt.Errorf("%w: %d > %d", ErrSizeTooLarge, size, MaxSize)
	}
	// ProbablyPrime is exact for inputs below 2^64.
	if size < 2 || !big.NewInt(int64(size)).ProbablyPrime(0) {
		return fmt.Errorf("%w: %d", ErrSizeNotPrime, size)
	}
	return nil
}

// populate is the algorithm from Pseudocode 1 of the paper. Backend i walks
// its own permutation of the slots, (offset_i + j*skip_i) mod M for
// j = 0, 1, 2, ..., and the backends take turns claiming the next slot in
// their permutation that is still free, until every slot is taken. Because M
// is prime and 1 <= skip_i < M, each permutation visits every slot, so a
// backend always finds a free slot while the table is not full.
//
// Rather than materialising the N x M permutation matrix, pos[i] holds the
// next candidate slot for backend i and advances by skip_i.
func populate(names []string, size int) []uint32 {
	m := uint64(size)
	offset := make([]uint64, len(names))
	skip := make([]uint64, len(names))
	for i, name := range names {
		offset[i] = hash64(name, seedOffset) % m
		skip[i] = hash64(name, seedSkip)%(m-1) + 1
	}
	return fill(offset, skip, size)
}

// fill runs the population loop for backends with the given offsets and
// skips. It takes ownership of offset, which it reuses as pos.
func fill(offset, skip []uint64, size int) []uint32 {
	m := uint64(size)
	n := len(offset)
	pos := offset

	const free = ^uint32(0)
	entries := make([]uint32, size)
	for i := range entries {
		entries[i] = free
	}

	filled := 0
	for {
		for i := 0; i < n; i++ {
			c := pos[i]
			for entries[c] != free {
				if c += skip[i]; c >= m {
					c -= m
				}
			}
			entries[c] = uint32(i)
			if c += skip[i]; c >= m {
				c -= m
			}
			pos[i] = c
			if filled++; filled == size {
				return entries
			}
		}
	}
}

// Size returns the number of slots in the table (M).
func (t *Table) Size() int { return t.size }

// Len returns the number of backends in the table (N).
func (t *Table) Len() int { return len(t.backends) }

// Backends returns the backend names in table order (sorted). The value
// stored in each slot is an index into this slice.
func (t *Table) Backends() []string { return slices.Clone(t.backends) }

// Entries returns a copy of the slot -> backend-index array, in the form the
// data plane's BPF array map will hold. It is nil when there are no backends.
func (t *Table) Entries() []uint32 { return slices.Clone(t.entries) }

// Lookup returns the backend for a flow hash, or false if the table has no
// backends. The slot is hash mod M.
func (t *Table) Lookup(hash uint64) (string, bool) {
	if len(t.entries) == 0 {
		return "", false
	}
	return t.backends[t.entries[hash%uint64(t.size)]], true
}

// Counts returns how many slots each backend owns, aligned with Backends().
func (t *Table) Counts() []int {
	counts := make([]int, len(t.backends))
	for _, b := range t.entries {
		counts[b]++
	}
	return counts
}

// Diff is the slot-level difference between two tables of the same size.
type Diff struct {
	Size int // slots compared (M)

	// Changed is the number of slots whose backend differs.
	Changed int

	// Necessary is the part of Changed that no consistent hash can avoid:
	// slots whose old backend was removed, or that moved to a newly added
	// backend.
	Necessary int

	// Extra is the part of Changed that moved between two backends present
	// in both tables. Maglev trades a small amount of this for near-perfect
	// balance. Without connection tracking, flows in these slots switch
	// backend mid-connection.
	Extra int
}

// ChangedFraction returns Changed / Size.
func (d Diff) ChangedFraction() float64 { return frac(d.Changed, d.Size) }

// ExtraFraction returns Extra / Size.
func (d Diff) ExtraFraction() float64 { return frac(d.Extra, d.Size) }

func frac(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// Compare reports which slots changed backend between old and new.
func Compare(old, new *Table) (Diff, error) {
	if old.size != new.size {
		return Diff{}, fmt.Errorf("%w: %d vs %d", ErrSizeMismatch, old.size, new.size)
	}
	d := Diff{Size: old.size}
	switch {
	case len(old.entries) == 0 && len(new.entries) == 0:
		return d, nil
	case len(old.entries) == 0 || len(new.entries) == 0:
		// Every slot gains or loses its backend outright.
		d.Changed, d.Necessary = d.Size, d.Size
		return d, nil
	}

	// Map each old backend index to its index in new (-1 if removed), and
	// mark which new backends did not exist before.
	const gone = -1
	oldToNew := make([]int, len(old.backends))
	added := make([]bool, len(new.backends))
	for i := range added {
		added[i] = true
	}
	for i, name := range old.backends {
		j, ok := slices.BinarySearch(new.backends, name)
		if !ok {
			oldToNew[i] = gone
			continue
		}
		oldToNew[i] = j
		added[j] = false
	}

	for s := range old.entries {
		o, n := oldToNew[old.entries[s]], new.entries[s]
		if o == int(n) {
			continue
		}
		d.Changed++
		if o == gone || added[n] {
			d.Necessary++
		} else {
			d.Extra++
		}
	}
	return d, nil
}
