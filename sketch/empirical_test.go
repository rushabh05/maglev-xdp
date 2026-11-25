package sketch

import (
	"math"
	"math/rand/v2"
	"os"
	"slices"
	"testing"
)

// trials scales a full-run trial count: SKETCH_FULL=1 runs it as given (the
// numbers in README.md come from that run), the default runs a quarter, and
// the race detector a fortieth, so CI stays fast.
func trials(full int) int {
	switch {
	case os.Getenv("SKETCH_FULL") != "":
		return full
	case raceEnabled:
		return max(2, full/40)
	}
	return max(2, full/4)
}

// The tests in this file check the sketches against their theory on
// synthetic traffic and log the numbers that README.md and docs/MATH.md
// quote. Run them with `go test -v -run Empirical ./sketch`. The thresholds
// asserted are the theoretical guarantees, or (where the theory is only
// asymptotic) the measured values with headroom, as noted.

// distinctKeys returns n distinct pseudo-random 32-bit keys: i*K+c is a
// bijection on uint32 for odd K.
func distinctKeys(rng *rand.Rand, n int) []uint32 {
	k, c := rng.Uint32()|1, rng.Uint32()
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(i)*k + c
	}
	return out
}

// TestEmpiricalCountMinZipf feeds Zipf-distributed traffic through the
// production shape (w = 4096, d = 5) and checks the Count-Min guarantee
// Pr[â > a + εN] <= δ, plus the per-row Markov step Pr[row error >= εN] <= 1/e.
func TestEmpiricalCountMinZipf(t *testing.T) {
	const (
		packets  = 1_000_000
		universe = 100_000
	)
	nTrials := trials(40)
	t.Logf("%-10s %8s %10s %8s %10s %10s %12s %10s %14s",
		"traffic", "keys", "within εN", "1-δ", "mean err", "mean/εN", "max err", "max/εN", "rows >= εN")
	for _, s := range []float64{1.1, 1.5} {
		var keysQueried, within, rowsOver, rowsTotal int
		var sumErr float64
		var maxErr uint64
		var bound float64
		for trial := range nTrials {
			rng := rand.New(rand.NewPCG(uint64(trial), uint64(s*100)))
			c := newCM(rng)
			keys := distinctKeys(rng, universe)
			zipf := rand.NewZipf(rng, s, 1, universe-1)
			truth := make(map[uint32]uint64)
			for range packets {
				k := keys[zipf.Uint64()]
				truth[k]++
				c.Add(k)
			}
			bound = c.Epsilon() * float64(c.Total())
			w := c.Width()
			for k, a := range truth {
				est := c.Estimate(k)
				if est < a {
					t.Fatalf("underestimate: %d < %d", est, a)
				}
				err := est - a
				keysQueried++
				sumErr += float64(err)
				maxErr = max(maxErr, err)
				if float64(err) <= bound {
					within++
				}
				for i := range c.Depth() {
					rowsTotal++
					if float64(c.Counters()[i*w+c.Column(i, k)]-a) >= bound {
						rowsOver++
					}
				}
			}
		}
		share := float64(within) / float64(keysQueried)
		mean := sumErr / float64(keysQueried)
		rowShare := float64(rowsOver) / float64(rowsTotal)
		delta := math.Exp(-5)
		t.Logf("%-10s %8d %9.4f%% %7.2f%% %10.2f %10.4f %12d %10.3f %9.4f%% (<= %.1f%%)",
			"zipf "+trimFloat(s), keysQueried, 100*share, 100*(1-delta), mean, mean/bound, maxErr, float64(maxErr)/bound,
			100*rowShare, 100/math.E)
		if share < 1-delta {
			t.Errorf("zipf %.1f: only %.4f%% of estimates within εN, guarantee is %.2f%%", s, 100*share, 100*(1-delta))
		}
		if rowShare > 1/math.E {
			t.Errorf("zipf %.1f: %.2f%% of row errors >= εN, Markov bound is %.1f%%", s, 100*rowShare, 100/math.E)
		}
	}
	t.Logf("N = %d packets per trial, %d trials, εN = %.1f", packets, nTrials, math.E/4096*packets)
}

// TestEmpiricalHLLError measures HyperLogLog's relative error over many
// trials and cardinalities and compares it with 1.04/√m.
func TestEmpiricalHLLError(t *testing.T) {
	const p = 14
	sigma := 1.04 / math.Sqrt(1<<p)
	m := float64(int(1) << p)
	cases := []struct{ n, trials int }{
		{100, 2000}, {1_000, 2000}, {10_000, 1000}, {20_000, 1000}, {30_000, 1000},
		{35_000, 1000}, {40_000, 1000}, {45_000, 1000}, {50_000, 1000}, {60_000, 1000},
		{80_000, 1000}, {100_000, 1000}, {1_000_000, 400}, {10_000_000, 40},
	}
	for i := range cases {
		cases[i].trials = trials(cases[i].trials)
	}
	t.Logf("m = %d, 1.04/√m = %.3f%%, linear counting used while the raw estimate <= 5m/2 = %d", 1<<p, 100*sigma, int(2.5*m))
	t.Logf("%10s %6s %9s %9s %9s %10s %10s %10s", "n", "trials", "bias", "RMSE", "RMSE/σ", "within 1σ", "within 2σ", "max |err|")
	for _, c := range cases {
		var sum, sumSq, maxAbs float64
		in1, in2 := 0, 0
		for trial := range c.trials {
			rng := rand.New(rand.NewPCG(uint64(c.n), uint64(trial)))
			h := NewHLL(p, rng.Uint64())
			for _, k := range distinctKeys(rng, c.n) {
				h.Add(k)
			}
			rel := (h.Estimate() - float64(c.n)) / float64(c.n)
			sum += rel
			sumSq += rel * rel
			maxAbs = max(maxAbs, math.Abs(rel))
			if math.Abs(rel) <= sigma {
				in1++
			}
			if math.Abs(rel) <= 2*sigma {
				in2++
			}
		}
		k := float64(c.trials)
		rmse := math.Sqrt(sumSq / k)
		t.Logf("%10d %6d %8.3f%% %8.3f%% %9.2f %9.1f%% %9.1f%% %9.3f%%",
			c.n, c.trials, 100*sum/k, 100*rmse, rmse/sigma, 100*float64(in1)/k, 100*float64(in2)/k, 100*maxAbs)
		// 1.04/√m is an asymptotic standard error, not a bound. Outside the
		// band around the linear-counting switch, allow 1.5σ. Inside it
		// (2m < n < 3.5m) the standard estimator is known to be biased
		// (the reason HyperLogLog++ adds bias correction); there the
		// assertion only guards against regressions from the measured values.
		limit := 1.5 * sigma
		if float64(c.n) > 2*m && float64(c.n) < 3.5*m {
			limit = 4 * sigma
		}
		// An RMSE estimated from k trials has a relative standard error of
		// about 1/√(2k); allow three of them so short runs (the race
		// detector runs few trials) don't fail on sampling noise alone.
		limit *= 1 + 3/math.Sqrt(2*float64(c.trials))
		if rmse > limit {
			t.Errorf("n=%d: RMSE %.3f%% exceeds %.2fσ", c.n, 100*rmse, limit/sigma)
		}
	}
}

// TestEmpiricalHeavyHitters simulates the in-kernel detector on a mixed
// flood: per-CPU Count-Min sketches, the per-CPU flag rule (with the floor
// split across CPUs, ⌈min/C⌉, as the dataplane configures it), then the
// userspace confirmation on the merged sketch. Packets are spread over CPUs
// at random, the worst case for per-CPU detection.
//
// Truth is {a >= max(φN, min)}. The proven guarantee covers the slightly
// smaller set {a >= φN + min}: every such source is flagged and confirmed.
func TestEmpiricalHeavyHitters(t *testing.T) {
	const (
		normalPackets = 660_000
		normalSources = 50_000
		phiPPM        = 10_000 // 1%
		minCount      = 1_000
	)
	// Attackers' shares of the window, in parts per 10,000; several sit just
	// either side of φ = 1%.
	attackShares := []int{30, 60, 90, 95, 105, 120, 200, 400, 800, 1500}
	t.Logf("φ = 1%%, min = %d, ε = e/4096 = %.4f%%", minCount, 100*math.E/4096)
	t.Logf("%5s %8s %7s %18s %18s %16s %18s", "CPUs", "packets", "truth", "kernel P / R", "confirmed P / R", "guaranteed R", "lowest confirmed")
	for _, cpus := range []int{1, 4, 16, 64} {
		perCPUMin := uint64((minCount + cpus - 1) / cpus)
		rng := rand.New(rand.NewPCG(uint64(cpus), 77))
		a, b := seeds(rng, 5), seeds(rng, 5)
		keys := distinctKeys(rng, normalSources+len(attackShares))
		attackers := keys[normalSources:]

		total := normalPackets * 10_000 / (10_000 - sum(attackShares))
		var stream []uint32
		zipf := rand.NewZipf(rng, 1.1, 1, normalSources-1)
		for range normalPackets {
			stream = append(stream, keys[zipf.Uint64()])
		}
		for i, share := range attackShares {
			for range total * share / 10_000 {
				stream = append(stream, attackers[i])
			}
		}
		rng.Shuffle(len(stream), func(i, j int) { stream[i], stream[j] = stream[j], stream[i] })

		perCPU := make([]*CountMin, cpus)
		for i := range perCPU {
			perCPU[i] = NewCountMin(12, a, b)
		}
		truthCount := map[uint32]uint64{}
		flagged := map[uint32]bool{}
		for _, k := range stream {
			truthCount[k]++
			c := perCPU[rng.IntN(cpus)]
			if est := c.Add(k); IsHeavy(est, c.Total(), perCPUMin, phiPPM) {
				flagged[k] = true
			}
		}
		merged := NewCountMin(12, a, b)
		for _, c := range perCPU {
			merged.Merge(c)
		}
		n := merged.Total()
		truth, guaranteed := map[uint32]bool{}, map[uint32]bool{}
		for k, cnt := range truthCount {
			if IsHeavy(cnt, n, minCount, phiPPM) {
				truth[k] = true
			}
			if cnt*1_000_000 >= uint64(phiPPM)*n+minCount*1_000_000 {
				guaranteed[k] = true
			}
		}
		confirmed := map[uint32]bool{}
		lowest := 1.0
		for k := range flagged {
			if IsHeavy(merged.Estimate(k), n, minCount, phiPPM) {
				confirmed[k] = true
				lowest = min(lowest, float64(truthCount[k])/float64(n))
			}
		}
		attackersHeavy := 0
		for _, k := range attackers {
			if truth[k] {
				attackersHeavy++
			}
		}
		if cpus == 1 {
			t.Logf("truth: %d heavy sources (%d attackers, %d Zipf sources), %d with a >= φN + min",
				len(truth), attackersHeavy, len(truth)-attackersHeavy, len(guaranteed))
		}
		kp, kr := precisionRecall(flagged, truth)
		cp, cr := precisionRecall(confirmed, truth)
		_, gr := precisionRecall(confirmed, guaranteed)
		t.Logf("%5d %8d %7d %8.3f / %.3f %10.3f / %.3f %9.3f (%d) %9.3f%% (%d flagged)",
			cpus, n, len(truth), kp, kr, cp, cr, gr, len(guaranteed), 100*lowest, len(flagged))

		// Proven (docs/MATH.md): every source with a >= φN + min is flagged
		// by some CPU and then confirmed.
		if gr != 1 {
			t.Errorf("%d CPUs: recall on {a >= φN + min} is %.3f, want 1", cpus, gr)
		}
		// With probability >= 1-δ per source: confirmed => a >= (φ-ε)N.
		if lowest < 0.01-math.E/4096 {
			t.Errorf("%d CPUs: confirmed a source with share %.4f%% < φ-ε", cpus, 100*lowest)
		}
	}
}

func precisionRecall(got, truth map[uint32]bool) (precision, recall float64) {
	tp := 0
	for k := range got {
		if truth[k] {
			tp++
		}
	}
	precision, recall = 1, 1
	if len(got) > 0 {
		precision = float64(tp) / float64(len(got))
	}
	if len(truth) > 0 {
		recall = float64(tp) / float64(len(truth))
	}
	return precision, recall
}

func sum(xs []int) int {
	s := 0
	for _, x := range xs {
		s += x
	}
	return s
}

func trimFloat(f float64) string {
	b := []byte{}
	b = append(b, byte('0'+int(f)))
	b = append(b, '.')
	b = append(b, byte('0'+int(math.Round(f*10))%10))
	return string(slices.Clip(b))
}
