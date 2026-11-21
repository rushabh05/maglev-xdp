package maglev

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPoolAddRemove(t *testing.T) {
	p, err := NewPool(DefaultSize, names(9)...)
	if err != nil {
		t.Fatal(err)
	}
	old := p.Table()

	d, err := p.Add("be-010")
	if err != nil {
		t.Fatal(err)
	}
	if p.Table().Len() != 10 || d.Necessary == 0 || d.Changed != d.Necessary+d.Extra {
		t.Errorf("after Add: Len=%d diff=%+v", p.Table().Len(), d)
	}
	if old.Len() != 9 {
		t.Error("Add modified a table a caller was holding")
	}
	// The pool's table must equal a fresh build of the same set.
	if !slices.Equal(p.Table().Entries(), mustBuild(t, names(10), DefaultSize).Entries()) {
		t.Error("table after Add differs from Build of the same backends")
	}

	if _, err := p.Add("be-010"); !errors.Is(err, ErrDuplicate) {
		t.Errorf("Add duplicate: err = %v, want %v", err, ErrDuplicate)
	}
	if _, err := p.Add(""); !errors.Is(err, ErrEmptyName) {
		t.Errorf("Add empty: err = %v, want %v", err, ErrEmptyName)
	}
	if _, err := p.Remove("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove missing: err = %v, want %v", err, ErrNotFound)
	}

	if _, err := p.Remove("be-010"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Table().Entries(), old.Entries()) {
		t.Error("Add then Remove did not restore the original table")
	}
}

func TestPoolSetAndEmpty(t *testing.T) {
	p, err := NewPool(13, "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Set([]string{"c"}); err != nil {
		t.Fatal(err)
	}
	if got, ok := p.Lookup(5); !ok || got != "c" {
		t.Errorf("after Set: Lookup = %q, %v", got, ok)
	}
	if _, err := p.Set([]string{"x", "x"}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("Set with duplicate: err = %v, want %v", err, ErrDuplicate)
	}
	if got, _ := p.Lookup(5); got != "c" {
		t.Error("a failed Set changed the table")
	}

	d, err := p.Remove("c")
	if err != nil || d.Changed != 13 {
		t.Fatalf("removing the last backend: %+v, %v", d, err)
	}
	if _, ok := p.Lookup(5); ok {
		t.Error("empty pool returned a backend")
	}
	if _, err := p.Add("d"); err != nil {
		t.Fatal(err)
	}
	if got, ok := p.Lookup(5); !ok || got != "d" {
		t.Errorf("after re-adding: Lookup = %q, %v", got, ok)
	}
}

// Readers must never block on, or race with, writers. Run with -race.
func TestPoolConcurrentLookups(t *testing.T) {
	p, err := NewPool(1009, names(8)...)
	if err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var misses atomic.Int64
	for r := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := uint64(r)
			for !stop.Load() {
				if _, ok := p.Lookup(h); !ok {
					misses.Add(1)
				}
				h += 0x9e3779b97f4a7c15
			}
		}()
	}
	for i := range 1000 {
		name := names(9)[8]
		if i%2 == 0 {
			_, err = p.Add(name)
		} else {
			_, err = p.Remove(name)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if misses.Load() != 0 {
		t.Errorf("%d lookups found no backend while the pool was never empty", misses.Load())
	}
}
