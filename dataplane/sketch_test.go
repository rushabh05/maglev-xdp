package dataplane

import (
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/rushabh05/maglev-xdp/sketch"
)

// Kernel tests for the traffic sketches. Like the other dataplane tests they
// run the real XDP program with BPF_PROG_TEST_RUN and need Linux and root.

func fixedSeeds(n uint64) Seeds {
	rng := rand.New(rand.NewPCG(n, 0xabc))
	var s Seeds
	for i := range CMDepth {
		s.CMA[i], s.CMB[i] = rng.Uint64(), rng.Uint64()
	}
	s.HLL = rng.Uint64()
	return s
}

func randomAddrs(rng *rand.Rand, n int) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for len(out) < n {
		a := netip.AddrFrom4([4]byte{byte(1 + rng.IntN(223)), byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())})
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func vipPacket(rng *rand.Rand, vip VIP, src netip.Addr) []byte {
	return packet(Flow{Src: src, Dst: vip.Addr, SrcPort: uint16(1024 + rng.IntN(60000)), DstPort: vip.Port, Proto: vip.Proto}, pktOpts{})
}

// The kernel's counters and registers must equal the Go reference's, bit for
// bit, after the same packets.
func TestSketchesMatchGoBitForBit(t *testing.T) {
	seeds := fixedSeeds(1)
	d := load(t, Config{Sketch: SketchConfig{Seeds: &seeds}})
	vipA, vipB := webVIP, VIP{Addr: netip.MustParseAddr("10.0.0.101"), Port: 53, Proto: UDP}
	mustSetVIP(t, d, vipA, testBackends(3))
	mustSetVIP(t, d, vipB, testBackends(3))

	cm := sketch.NewCountMin(CMLogWidth, seeds.CMA[:], seeds.CMB[:])
	hll := map[VIP]*sketch.HLL{vipA: sketch.NewHLL(HLLPrecision, seeds.HLL), vipB: sketch.NewHLL(HLLPrecision, seeds.HLL)}
	distinct := map[VIP]map[netip.Addr]bool{vipA: {}, vipB: {}}

	rng := rand.New(rand.NewPCG(5, 5))
	sources := randomAddrs(rng, 5000)
	zipf := rand.NewZipf(rng, 1.2, 1, uint64(len(sources)-1))
	for i := range 30_000 {
		src := sources[zipf.Uint64()]
		vip := vipA
		if rng.IntN(3) == 0 {
			vip = vipB
		}
		if ret, _ := run(t, d, vipPacket(rng, vip, src)); ret != xdpTX {
			t.Fatalf("packet %d: verdict %d", i, ret)
		}
		cm.Add(sourceKey(src))
		hll[vip].Add(sourceKey(src))
		distinct[vip][src] = true
	}
	// Traffic that isn't for a VIP must not touch the sketches.
	for range 500 {
		other := Flow{Src: sources[0], Dst: netip.MustParseAddr("10.0.0.200"), SrcPort: 1, DstPort: 80, Proto: TCP}
		run(t, d, packet(other, pktOpts{}))
	}

	kcm, err := d.readCountMin(0)
	if err != nil {
		t.Fatal(err)
	}
	if kcm.Total() != cm.Total() || !slices.Equal(kcm.Counters(), cm.Counters()) {
		t.Fatalf("Count-Min differs: kernel N=%d, Go N=%d", kcm.Total(), cm.Total())
	}
	for _, vip := range []VIP{vipA, vipB} {
		kh, err := d.readHLL(0, d.vips[vip].index)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(kh.Registers(), hll[vip].Registers()) {
			t.Fatalf("%v: HyperLogLog registers differ", vip)
		}
		t.Logf("%v: %d distinct sources, estimate %.1f", vip, len(distinct[vip]), kh.Estimate())
	}
	t.Logf("kernel and Go agree on all %d Count-Min counters (N=%d) and 2 × %d HyperLogLog registers",
		len(cm.Counters()), cm.Total(), 1<<HLLPrecision)
}

func TestSketchWindowRotation(t *testing.T) {
	d := load(t, Config{})
	mustSetVIP(t, d, webVIP, testBackends(2))
	rng := rand.New(rand.NewPCG(6, 6))
	sources := randomAddrs(rng, 100)
	for i := range 1000 {
		run(t, d, vipPacket(rng, webVIP, sources[i%100]))
	}
	r, err := d.RotateWindow(0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Packets != 1000 || r.Epoch != 0 || len(r.Distinct) != 1 {
		t.Fatalf("report = %+v", r)
	}
	if e := r.Distinct[0].Estimate; math.Abs(e-100) > 3 {
		t.Errorf("distinct estimate %.1f for 100 sources", e)
	}
	// The closed buffer is cleared, and new packets land in the other one.
	if cm, _ := d.readCountMin(0); cm.Total() != 0 || slices.Max(cm.Counters()) != 0 {
		t.Error("closed buffer was not cleared")
	}
	for range 10 {
		run(t, d, vipPacket(rng, webVIP, sources[0]))
	}
	if cm, _ := d.readCountMin(1); cm.Total() != 10 || cm.Estimate(sourceKey(sources[0])) < 10 {
		t.Errorf("new window: N=%d", cm.Total())
	}
	r, _ = d.RotateWindow(0)
	if r.Epoch != 1 || r.Packets != 10 {
		t.Errorf("second report = %+v", r)
	}
}

// A mixed flood through the real program: Zipf-distributed normal sources
// plus attackers at shares either side of φ = 1%. Reports precision and
// recall of the kernel's flags and of the confirmed set.
func TestHeavyHittersInKernel(t *testing.T) {
	const (
		normalPackets = 132_000
		normalSources = 20_000
		phi           = 0.01
		minCount      = 200
	)
	attackShares := []int{30, 60, 90, 95, 105, 120, 200, 400, 800, 1500} // parts per 10,000
	seeds := fixedSeeds(7)
	d := load(t, Config{Sketch: SketchConfig{Seeds: &seeds, Phi: phi, MinCount: minCount}})
	mustSetVIP(t, d, webVIP, testBackends(4))

	rng := rand.New(rand.NewPCG(7, 7))
	addrs := randomAddrs(rng, normalSources+len(attackShares))
	total := normalPackets * 10_000 / (10_000 - 3_400)
	var stream []netip.Addr
	zipf := rand.NewZipf(rng, 1.1, 1, normalSources-1)
	for range normalPackets {
		stream = append(stream, addrs[zipf.Uint64()])
	}
	for i, share := range attackShares {
		for range total * share / 10_000 {
			stream = append(stream, addrs[normalSources+i])
		}
	}
	rng.Shuffle(len(stream), func(i, j int) { stream[i], stream[j] = stream[j], stream[i] })

	counts := map[netip.Addr]uint64{}
	for _, src := range stream {
		counts[src]++
		run(t, d, vipPacket(rng, webVIP, src))
	}
	n := uint64(len(stream))

	flagged := map[uint32]bool{}
	var key uint32
	var entry lbHeavyEntry
	for it := d.objs.Heavy.Iterate(); it.Next(&key, &entry); {
		flagged[key] = true
	}
	r, err := d.RotateWindow(0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Packets != n {
		t.Fatalf("window counted %d packets, sent %d", r.Packets, n)
	}
	confirmed := map[uint32]bool{}
	lowest := 1.0
	for _, h := range r.Heavy {
		k := sourceKey(h.Addr)
		confirmed[k] = true
		lowest = min(lowest, float64(counts[h.Addr])/float64(n))
		if a := counts[h.Addr]; a > h.Estimate || a < h.Lower {
			t.Errorf("%v: true count %d outside reported [%d, %d]", h.Addr, a, h.Lower, h.Estimate)
		}
	}

	truth, guaranteed := map[uint32]bool{}, map[uint32]bool{}
	phiPPM := uint32(phi * 1e6)
	for src, a := range counts {
		if sketch.IsHeavy(a, n, minCount, phiPPM) {
			truth[sourceKey(src)] = true
		}
		if a*1_000_000 >= uint64(phiPPM)*n+minCount*1_000_000 {
			guaranteed[sourceKey(src)] = true
		}
	}
	kp, kr := prf(flagged, truth)
	cp, cr := prf(confirmed, truth)
	_, kg := prf(flagged, guaranteed)
	_, cg := prf(confirmed, guaranteed)
	t.Logf("kernel, %d CPUs, N=%d, φ=1%%, min=%d (per CPU %d), εN=%d", d.sk.ncpu, n, minCount,
		(minCount+d.sk.ncpu-1)/d.sk.ncpu, r.Bound)
	t.Logf("truth %d sources; kernel flagged %d: precision %.3f recall %.3f; confirmed %d: precision %.3f recall %.3f; lowest confirmed share %.3f%%",
		len(truth), len(flagged), kp, kr, len(confirmed), cp, cr, 100*lowest)
	if kg != 1 || cg != 1 {
		t.Errorf("recall on {a >= φN + min} = %.3f (kernel) / %.3f (confirmed), want 1", kg, cg)
	}
}

func prf(got, truth map[uint32]bool) (precision, recall float64) {
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

func TestDropHeavy(t *testing.T) {
	d := load(t, Config{Sketch: SketchConfig{Phi: 0.5, MinCount: 50, DropHeavy: true}})
	mustSetVIP(t, d, webVIP, testBackends(2))
	rng := rand.New(rand.NewPCG(8, 8))
	normal := randomAddrs(rng, 101)
	flooder, normal := normal[100], normal[:100]

	// window sends 200 flood and 100 normal packets, interleaved, and
	// returns how many flood packets were dropped and normal ones forwarded.
	window := func() (dropped, normalTX int) {
		for i := range 300 {
			src := flooder
			if i%3 == 2 {
				src = normal[i/3]
			}
			ret, _ := run(t, d, vipPacket(rng, webVIP, src))
			switch {
			case src == flooder && ret == xdpDrop:
				dropped++
			case src != flooder && ret == xdpTX:
				normalTX++
			}
		}
		return dropped, normalTX
	}

	// Window 0: the flooder is flagged but not yet confirmed, so nothing
	// is dropped.
	if dropped, normalTX := window(); dropped != 0 || normalTX != 100 {
		t.Fatalf("first window: %d flood packets dropped, %d/100 normal forwarded", dropped, normalTX)
	}
	r, err := d.RotateWindow(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Heavy) != 1 || r.Heavy[0].Addr != flooder {
		t.Fatalf("heavy = %+v, want just the flooder", r.Heavy)
	}

	// Window 1: confirmed, so every flood packet is dropped and normal
	// traffic is untouched.
	dropped, normalTX := window()
	if dropped != 200 || normalTX != 100 {
		t.Errorf("second window: %d/200 flood packets dropped, %d/100 normal forwarded", dropped, normalTX)
	}
	if s, _ := d.Stats(); s.DropHeavy != uint64(dropped) {
		t.Errorf("DropHeavy = %d, dropped %d", s.DropHeavy, dropped)
	}
	t.Logf("after confirmation: %d of 200 flood packets dropped; %d of 100 normal forwarded", dropped, normalTX)

	// Dropped packets still count, so the flooder stays confirmed.
	if r, _ = d.RotateWindow(0); len(r.Heavy) != 1 {
		t.Fatalf("heavy after a dropped flood = %+v", r.Heavy)
	}
	// The flood stops: after a quiet window the source is unblocked.
	if r, _ = d.RotateWindow(0); len(r.Heavy) != 0 {
		t.Fatalf("heavy after a quiet window = %+v", r.Heavy)
	}
	if ret, _ := run(t, d, vipPacket(rng, webVIP, flooder)); ret != xdpTX {
		t.Errorf("former flooder still dropped (verdict %d)", ret)
	}
}

// Regression test for a race the veth e2e test found: a flood keeps arriving
// while userspace closes a window, so the kernel re-flags the source in the
// new window (updating its entry in place) before userspace reads the entry.
// The source must still be judged against the closed window and confirmed.
func TestHeavyConfirmedWhenReflaggedDuringRotation(t *testing.T) {
	d := load(t, Config{Sketch: SketchConfig{Phi: 0.5, MinCount: 20, DropHeavy: true}})
	mustSetVIP(t, d, webVIP, testBackends(2))
	rng := rand.New(rand.NewPCG(10, 10))
	srcs := randomAddrs(rng, 2)
	flooder, normal := srcs[0], srcs[1]
	send := func(src netip.Addr, n int) (dropped int) {
		for range n {
			if ret, _ := run(t, d, vipPacket(rng, webVIP, src)); ret == xdpDrop {
				dropped++
			}
		}
		return dropped
	}

	send(flooder, 300)
	send(normal, 10)
	// Between the epoch switch and the judging, the flood continues: enough
	// packets to cross the per-CPU threshold in the new window.
	d.afterFlip = func() { send(flooder, 100) }
	r, err := d.RotateWindow(0)
	d.afterFlip = nil
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Heavy) != 1 || r.Heavy[0].Addr != flooder {
		t.Fatalf("heavy = %+v (flagged %d, pending %d), want the flooder confirmed", r.Heavy, r.Flagged, r.Pending)
	}
	if dropped := send(flooder, 100); dropped != 100 {
		t.Errorf("after confirmation, %d of 100 flood packets dropped", dropped)
	}
	if dropped := send(normal, 10); dropped != 0 {
		t.Errorf("%d normal packets dropped", dropped)
	}

	// A source flagged in the new window but not heavy over the closed one
	// is kept, unconfirmed (not dropped), and judged next time.
	quiet := randomAddrs(rng, 3)[2]
	d.afterFlip = func() { send(quiet, 100) }
	r, err = d.RotateWindow(0) // closes the window with 200 flood + 10 normal packets
	d.afterFlip = nil
	if err != nil {
		t.Fatal(err)
	}
	if r.Pending != 1 {
		t.Fatalf("pending = %d, want 1 (the source first flagged in the new window)", r.Pending)
	}
	if dropped := send(quiet, 10); dropped != 0 {
		t.Errorf("an unconfirmed source had %d packets dropped", dropped)
	}
	if r, _ = d.RotateWindow(0); len(r.Heavy) != 1 || r.Heavy[0].Addr != quiet {
		t.Errorf("next window: heavy = %+v, want the newly flagged source", r.Heavy)
	}
}

func TestSketchesDisabled(t *testing.T) {
	d := load(t, Config{Sketch: SketchConfig{Disabled: true, DropHeavy: true, MinCount: 1}})
	mustSetVIP(t, d, webVIP, testBackends(2))
	rng := rand.New(rand.NewPCG(9, 9))
	src := randomAddrs(rng, 1)[0]
	for range 100 {
		if ret, _ := run(t, d, vipPacket(rng, webVIP, src)); ret != xdpTX {
			t.Fatalf("verdict %d with sketches disabled", ret)
		}
	}
	if cm, _ := d.readCountMin(0); cm.Total() != 0 {
		t.Errorf("disabled sketch counted %d packets", cm.Total())
	}
}

// TestPerPacketCost measures the program's average run time per packet with
// BPF_PROG_TEST_RUN, repeating one VIP packet. This is in-kernel program time
// only (no driver, NIC or cache-miss effects of real traffic), so it says
// what the sketches add, not what a NIC would sustain.
func TestPerPacketCost(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const repeat = 2_000_000
	pkt := packet(flow("192.0.2.1", 40000), pktOpts{})
	never := uint64(1) << 60 // a min count the repeated source never reaches
	variants := []struct {
		name string
		cfg  SketchConfig
	}{
		{"sketches off", SketchConfig{Disabled: true}},
		{"sketches on", SketchConfig{MinCount: never}},
		{"sketches on, drop check on", SketchConfig{MinCount: never, DropHeavy: true}},
	}
	var base float64
	for _, v := range variants {
		d := load(t, Config{Sketch: v.cfg})
		mustSetVIP(t, d, webVIP, testBackends(4))
		best := math.Inf(1)
		for range 5 {
			ret, per, err := d.Program().Benchmark(pkt, repeat, nil)
			if err != nil {
				t.Fatal(err)
			}
			if ret != xdpTX {
				t.Fatalf("%s: verdict %d", v.name, ret)
			}
			best = min(best, float64(per.Nanoseconds()))
		}
		if base == 0 {
			base = best
		}
		t.Logf("%-28s %4.0f ns/packet (best of 5 × %d runs), +%.0f ns", v.name, best, repeat, best-base)
	}
}
