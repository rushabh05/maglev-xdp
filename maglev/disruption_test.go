package maglev

import (
	"math/rand/v2"
	"slices"
	"testing"
)

// When one of N backends fails, an ideal consistent hash moves exactly the
// failed backend's share of slots, 1/N. Maglev moves that share plus a little
// "extra" between surviving backends, the price of its near-perfect balance.
// The paper (section 5.3) notes the extra shrinks as the table grows.
//
// The bounds below were set from measured values with some headroom; run
// `go test -v -run Disruption ./maglev` to see the numbers. ratio is
// (share of slots remapped) / (1/N), so 1.00 is ideal.
func TestDisruptionOnBackendFailure(t *testing.T) {
	cases := []struct {
		size     int
		n        int
		maxRatio float64
		long     bool
	}{
		{DefaultSize, 3, 1.01, false},
		{DefaultSize, 5, 1.02, false},
		{DefaultSize, 10, 1.05, false},
		{DefaultSize, 20, 1.12, false},
		{DefaultSize, 50, 1.30, false},
		{DefaultSize, 100, 1.70, false},
		{655373, 10, 1.02, true},
		{655373, 100, 1.25, true},
	}
	t.Logf("%8s %5s %8s %10s %10s %10s %11s", "M", "N", "ideal", "mean", "max", "max ratio", "max extra")
	for _, c := range cases {
		if c.long && testing.Short() {
			continue
		}
		backends := names(c.n)
		before := mustBuild(t, backends, c.size)
		counts := before.Counts()

		// Fail every backend for small N, an even sample of 20 otherwise.
		step := max(1, c.n/20)
		var sum, worst, worstExtra float64
		failures := 0
		for f := 0; f < c.n; f += step {
			after := mustBuild(t, slices.Delete(slices.Clone(backends), f, f+1), c.size)
			d, err := Compare(before, after)
			if err != nil {
				t.Fatal(err)
			}
			// All of the failed backend's slots must move, and only those
			// count as necessary.
			if d.Necessary != counts[f] {
				t.Errorf("M=%d N=%d fail %s: necessary = %d, want its %d slots", c.size, c.n, backends[f], d.Necessary, counts[f])
			}
			share := d.ChangedFraction()
			sum += share
			worst = max(worst, share)
			worstExtra = max(worstExtra, d.ExtraFraction())
			failures++
		}
		ideal := 1 / float64(c.n)
		mean := sum / float64(failures)
		ratio := worst / ideal
		t.Logf("%8d %5d %7.2f%% %9.2f%% %9.2f%% %10.3f %10.3f%%", c.size, c.n, 100*ideal, 100*mean, 100*worst, ratio, 100*worstExtra)

		if ratio > c.maxRatio {
			t.Errorf("M=%d N=%d: worst failure remapped %.3f x 1/N, want <= %.2f", c.size, c.n, ratio, c.maxRatio)
		}
		if worstExtra > 0.01 {
			t.Errorf("M=%d N=%d: extra churn between survivors %.2f%% of the table, want <= 1%%", c.size, c.n, 100*worstExtra)
		}
	}
}

// Adding a backend to N should move about 1/(N+1) of the slots, all of them
// to the new backend except for a small extra.
func TestDisruptionOnBackendAdd(t *testing.T) {
	cases := []struct {
		n        int
		maxRatio float64
	}{{5, 1.02}, {10, 1.05}, {100, 1.70}}
	for _, c := range cases {
		before := mustBuild(t, names(c.n), DefaultSize)
		after := mustBuild(t, names(c.n+1), DefaultSize)
		d, err := Compare(before, after)
		if err != nil {
			t.Fatal(err)
		}
		ideal := 1 / float64(c.n+1)
		ratio := d.ChangedFraction() / ideal
		t.Logf("N=%d -> %d: remapped %.2f%% (ideal %.2f%%, ratio %.3f), extra %.3f%%",
			c.n, c.n+1, 100*d.ChangedFraction(), 100*ideal, ratio, 100*d.ExtraFraction())
		newOwned := after.Counts()[c.n] // names are zero padded, so the new one sorts last
		if d.Necessary != newOwned {
			t.Errorf("N=%d -> %d: necessary = %d, want the new backend's %d slots", c.n, c.n+1, d.Necessary, newOwned)
		}
		if ratio > c.maxRatio {
			t.Errorf("N=%d -> %d: remapped %.3f x 1/(N+1), want <= %.2f", c.n, c.n+1, ratio, c.maxRatio)
		}
	}
}

// Slots are a proxy; what matters is flows. Hash a million random flows
// through the table before and after a failure and count how many land on a
// different backend. For contrast, do the same with naive hash-mod-N
// selection, which remaps most flows.
func TestFlowDisruption(t *testing.T) {
	const (
		n     = 10
		flows = 1_000_000
	)
	backends := names(n)
	failed := 3
	survivors := slices.Delete(slices.Clone(backends), failed, failed+1)
	before := mustBuild(t, backends, DefaultSize)
	after := mustBuild(t, survivors, DefaultSize)
	d, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewPCG(7, 11))
	maglevMoved, naiveMoved, onSurvivorMoved := 0, 0, 0
	for range flows {
		h := rng.Uint64()
		b, _ := before.Lookup(h)
		a, _ := after.Lookup(h)
		if a != b {
			maglevMoved++
			if b != backends[failed] {
				onSurvivorMoved++
			}
		}
		if backends[h%n] != survivors[h%(n-1)] {
			naiveMoved++
		}
	}
	got := float64(maglevMoved) / flows
	naive := float64(naiveMoved) / flows
	broken := float64(onSurvivorMoved) / flows
	t.Logf("N=%d, fail %s, %d flows: Maglev remapped %.2f%% (slots: %.2f%%), hash mod N remapped %.2f%%",
		n, backends[failed], flows, 100*got, 100*d.ChangedFraction(), 100*naive)
	t.Logf("flows on a healthy backend that moved anyway: %.3f%% (these need connection tracking to survive)", 100*broken)

	// Flow hashes are uniform, so the flow share should track the slot share
	// to within sampling noise (stddev ~0.03% here).
	if diff := got - d.ChangedFraction(); diff > 0.002 || diff < -0.002 {
		t.Errorf("flows remapped %.3f%% but slots remapped %.3f%%", 100*got, 100*d.ChangedFraction())
	}
	if naive < 0.5 {
		t.Errorf("hash mod N remapped only %.2f%% of flows; expected most of them", 100*naive)
	}
}
