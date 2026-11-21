// Command maglev-stats builds a Maglev lookup table and prints how evenly it
// spreads slots across backends. Given -fail and/or -add, it applies that
// change and reports how many slots and simulated flows were remapped.
//
//	go run ./cmd/maglev-stats -n 10 -fail be-03
//	go run ./cmd/maglev-stats -backends 10.0.0.1:80,10.0.0.2:80,10.0.0.3:80 -add 10.0.0.4:80
//	go run ./cmd/maglev-stats -n 100 -size 655373 -fail be-042
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rushabh05/maglev-xdp/maglev"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "maglev-stats:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("maglev-stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		n        = fs.Int("n", 10, "number of synthetic backends (be-01, be-02, ...); ignored if -backends is set")
		list     = fs.String("backends", "", "comma-separated backend names, e.g. 10.0.0.1:80,10.0.0.2:80")
		size     = fs.Int("size", maglev.DefaultSize, "lookup table size M (must be prime)")
		failList = fs.String("fail", "", "comma-separated backends to remove")
		addList  = fs.String("add", "", "comma-separated backends to add")
		flows    = fs.Int("flows", 1_000_000, "random flows to simulate for -fail/-add (0 to skip)")
		seed     = fs.Uint64("seed", 1, "seed for the simulated flow hashes")
		rows     = fs.Int("rows", 20, "maximum per-backend rows to print")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *rows < 0 {
		return fmt.Errorf("-rows must not be negative")
	}

	backends := splitList(*list)
	if len(backends) == 0 {
		if *n < 1 {
			return fmt.Errorf("-n must be at least 1")
		}
		backends = synthetic(*n)
	}

	start := time.Now()
	pool, err := maglev.NewPool(*size, backends...)
	if err != nil {
		return err
	}
	built := time.Since(start)
	before := pool.Table()

	w := stdout
	fmt.Fprintf(w, "Maglev table: M=%s (prime), N=%d backends, built in %s\n\n", commas(before.Size()), before.Len(), ms(built))
	printShares(w, before, *rows)

	fail, add := splitList(*failList), splitList(*addList)
	if len(fail) == 0 && len(add) == 0 {
		return nil
	}

	next := before.Backends()
	for _, f := range fail {
		i := slices.Index(next, f)
		if i < 0 {
			return fmt.Errorf("-fail %q: %w", f, maglev.ErrNotFound)
		}
		next = slices.Delete(next, i, i+1)
	}
	next = append(next, add...)

	start = time.Now()
	d, err := pool.Set(next)
	if err != nil {
		return err
	}
	built = time.Since(start)
	after := pool.Table()

	var change []string
	if len(fail) > 0 {
		change = append(change, "fail "+strings.Join(fail, ","))
	}
	if len(add) > 0 {
		change = append(change, "add "+strings.Join(add, ","))
	}
	fmt.Fprintf(w, "\nChange: %s (N=%d -> %d, rebuilt in %s)\n\n", strings.Join(change, "; "), before.Len(), after.Len(), ms(built))
	row := func(label, count, share, note string) {
		fmt.Fprintln(w, strings.TrimRight(fmt.Sprintf("  %-16s %9s %8s  %s", label, count, share, note), " "))
	}
	row("slots remapped", commas(d.Changed), pct(d.ChangedFraction()), "")
	row("  necessary", commas(d.Necessary), pct(float64(d.Necessary)/float64(d.Size)),
		"slots of removed backends or taken by added ones: the minimum for any consistent hash")
	row("  extra", commas(d.Extra), pct(d.ExtraFraction()),
		"moved between backends that stayed: Maglev's price for even balance")
	if len(fail) == 1 && len(add) == 0 {
		row("ideal (1/N)", "", pct(1/float64(before.Len())), "")
	}

	if *flows > 0 && after.Len() > 0 {
		mag, naive := simulate(before, after, *flows, *seed)
		fmt.Fprintf(w, "\nFlows remapped (%s random flow hashes):\n", commas(*flows))
		row("Maglev", "", pct(mag), "")
		row("hash mod N", "", pct(naive), "for comparison")
	}
	return nil
}

func printShares(w io.Writer, t *maglev.Table, maxRows int) {
	backends, counts := t.Backends(), t.Counts()
	ideal := float64(t.Size()) / float64(t.Len())
	if maxRows > 0 {
		width := len("backend")
		for _, b := range backends[:min(maxRows, len(backends))] {
			width = max(width, len(b))
		}
		fmt.Fprintf(w, "  %-*s %9s %8s %10s\n", width, "backend", "slots", "share", "vs ideal")
		for i, b := range backends {
			if i == maxRows {
				fmt.Fprintf(w, "  ... %d more\n", len(backends)-maxRows)
				break
			}
			fmt.Fprintf(w, "  %-*s %9s %8s %+9.3f%%\n", width, b, commas(counts[i]),
				pct(float64(counts[i])/float64(t.Size())), 100*(float64(counts[i])-ideal)/ideal)
		}
		fmt.Fprintln(w)
	}

	lo, hi := slices.Min(counts), slices.Max(counts)
	fmt.Fprintf(w, "balance: %s..%s slots per backend, so the busiest backend gets %.3f%% more than the least busy\n",
		commas(lo), commas(hi), 100*float64(hi-lo)/float64(lo))
	if t.Size() < 100*t.Len() {
		fmt.Fprintf(w, "note: M < 100*N. The paper picks M > 100*N to keep that gap under 1%%; consider a larger -size.\n")
	}
}

// simulate hashes random flows through both tables and returns the share
// that changed backend, plus the same share for naive hash-mod-N selection
// over the sorted backend lists.
func simulate(before, after *maglev.Table, flows int, seed uint64) (maglevShare, naiveShare float64) {
	rng := rand.New(rand.NewPCG(seed, seed^0x5bd1e995))
	bl, al := before.Backends(), after.Backends()
	moved, naive := 0, 0
	for range flows {
		h := rng.Uint64()
		b, _ := before.Lookup(h)
		a, _ := after.Lookup(h)
		if a != b {
			moved++
		}
		if bl[h%uint64(len(bl))] != al[h%uint64(len(al))] {
			naive++
		}
	}
	return float64(moved) / float64(flows), float64(naive) / float64(flows)
}

func synthetic(n int) []string {
	width := len(fmt.Sprint(n))
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("be-%0*d", width, i+1)
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func pct(f float64) string { return fmt.Sprintf("%.2f%%", 100*f) }

func ms(d time.Duration) string { return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000) }

func commas(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
