package maglev

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
)

// Pool is a mutable backend set with a current lookup table. Changes rebuild
// the table off to the side and publish it with one atomic pointer swap, so
// Lookup and Table never block and never observe a partial table. This is
// the shape the control plane needs for hot reload: build the new table,
// then write it to the data plane.
type Pool struct {
	mu       sync.Mutex // serialises writers
	size     int
	backends map[string]struct{}
	table    atomic.Pointer[Table]
}

// NewPool returns a pool with a table of the given prime size and the given
// initial backends.
func NewPool(size int, backends ...string) (*Pool, error) {
	t, err := Build(backends, size)
	if err != nil {
		return nil, err
	}
	p := &Pool{size: size, backends: make(map[string]struct{}, len(backends))}
	for _, b := range backends {
		p.backends[b] = struct{}{}
	}
	p.table.Store(t)
	return p, nil
}

// Table returns the current table. The caller may keep it; it never changes.
func (p *Pool) Table() *Table { return p.table.Load() }

// Lookup returns the backend for a flow hash in the current table.
func (p *Pool) Lookup(hash uint64) (string, bool) { return p.Table().Lookup(hash) }

// Add adds a backend and returns how the table changed.
func (p *Pool) Add(name string) (Diff, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if name == "" {
		return Diff{}, ErrEmptyName
	}
	if _, ok := p.backends[name]; ok {
		return Diff{}, fmt.Errorf("%w: %q", ErrDuplicate, name)
	}
	next := append(p.namesLocked(), name)
	return p.swapLocked(next)
}

// Remove removes a backend and returns how the table changed. Removing the
// last backend leaves an empty table whose lookups report false.
func (p *Pool) Remove(name string) (Diff, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.backends[name]; !ok {
		return Diff{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	next := slices.DeleteFunc(p.namesLocked(), func(n string) bool { return n == name })
	return p.swapLocked(next)
}

// Set replaces the whole backend set with one rebuild and returns how the
// table changed.
func (p *Pool) Set(backends []string) (Diff, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.swapLocked(slices.Clone(backends))
}

func (p *Pool) namesLocked() []string {
	names := make([]string, 0, len(p.backends)+1)
	for n := range p.backends {
		names = append(names, n)
	}
	return names
}

func (p *Pool) swapLocked(names []string) (Diff, error) {
	next, err := Build(names, p.size)
	if err != nil {
		return Diff{}, err
	}
	d, err := Compare(p.table.Load(), next)
	if err != nil {
		return Diff{}, err
	}
	p.backends = make(map[string]struct{}, len(names))
	for _, n := range names {
		p.backends[n] = struct{}{}
	}
	p.table.Store(next)
	return d, nil
}
