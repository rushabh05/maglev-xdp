package dataplane

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/cilium/ebpf"

	"github.com/rushabh05/maglev-xdp/sketch"
)

// Sketch dimensions, from bpf/lb.c.
const (
	CMDepth      = int(lbSketchParamsCM_DEPTH)
	CMLogWidth   = int(lbSketchParamsCM_LOG_WIDTH)
	CMWidth      = int(lbSketchParamsCM_WIDTH)
	HLLPrecision = int(lbSketchParamsHLL_P)
)

// SketchConfig configures the Count-Min and HyperLogLog sketches the XDP
// program keeps over VIP traffic.
type SketchConfig struct {
	// Disabled leaves the sketches out of the packet path entirely.
	Disabled bool
	// Seeds for the sketch hashes; nil draws them from crypto/rand.
	Seeds *Seeds
	// Phi is the heavy-hitter threshold as a share of a window's packets.
	// Zero means 0.01.
	Phi float64
	// MinCount is the least number of packets in a window for a source to
	// count as heavy. Zero means 1000.
	MinCount uint64
	// DropHeavy drops packets from sources confirmed heavy over the last
	// closed window (flood mitigation). Mitigation starts at the first
	// RotateWindow after a flood begins and ends one window after it stops.
	DropHeavy bool
}

// Seeds are the random parameters of the sketch hashes.
type Seeds struct {
	CMA, CMB [CMDepth]uint64 // Count-Min row i: (CMA[i]*src + CMB[i]) >> (64 - CMLogWidth)
	HLL      uint64          // HyperLogLog: fmix64(src XOR HLL)
}

// RandomSeeds draws seeds from crypto/rand, so a sender can't pick source
// addresses that collide in the Count-Min rows.
func RandomSeeds() (Seeds, error) {
	var buf [8 * (2*CMDepth + 1)]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return Seeds{}, err
	}
	var s Seeds
	for i := range CMDepth {
		s.CMA[i] = binary.LittleEndian.Uint64(buf[16*i:])
		s.CMB[i] = binary.LittleEndian.Uint64(buf[16*i+8:])
	}
	s.HLL = binary.LittleEndian.Uint64(buf[16*CMDepth:])
	return s, nil
}

// SketchParams describes the sketches and their guarantees.
type SketchParams struct {
	Depth, Width int
	Epsilon      float64 // e/Width: estimates are within εN ...
	Delta        float64 // ... with probability at least 1-δ = 1 - e^-Depth
	HLLRegisters int
	HLLStdError  float64 // 1.04/√m
	BytesPerCPU  int     // map memory per CPU, both buffers
}

// Params returns the sketch parameters (fixed at compile time).
func Params() SketchParams {
	m := 1 << HLLPrecision
	return SketchParams{
		Depth:        CMDepth,
		Width:        CMWidth,
		Epsilon:      math.E / float64(CMWidth),
		Delta:        math.Exp(-float64(CMDepth)),
		HLLRegisters: m,
		HLLStdError:  1.04 / math.Sqrt(float64(m)),
		BytesPerCPU:  2*CMDepth*CMWidth*8 + 2*8 + 2*maxVIPsC*m,
	}
}

const maxVIPsC = 16 // MAX_VIPS in bpf/lb.c; Load checks it against the map

type sketchState struct {
	enabled  bool
	seeds    Seeds
	phiPPM   uint32
	minCount uint64
	drop     bool
	epoch    uint32
	ncpu     int
}

func newSketchState(cfg SketchConfig) (sketchState, error) {
	s := sketchState{enabled: !cfg.Disabled, phiPPM: 10_000, minCount: 1000, drop: cfg.DropHeavy}
	if cfg.Phi != 0 {
		if cfg.Phi < 0 || cfg.Phi > 1 {
			return s, fmt.Errorf("dataplane: heavy-hitter share %v outside (0, 1]", cfg.Phi)
		}
		s.phiPPM = uint32(math.Round(cfg.Phi * 1e6))
	}
	if cfg.MinCount != 0 {
		s.minCount = cfg.MinCount
	}
	if cfg.Seeds != nil {
		s.seeds = *cfg.Seeds
	} else {
		var err error
		if s.seeds, err = RandomSeeds(); err != nil {
			return s, err
		}
	}
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return s, err
	}
	s.ncpu = n
	return s, nil
}

// writeSketchConfig publishes the epoch and heavy-hitter policy. The kernel
// applies the count floor per CPU, so it gets ⌈min/C⌉ for C possible CPUs:
// summing over CPUs, any source with at least φN + min packets in a window
// then crosses the per-CPU rule on some CPU (docs/MATH.md, §3.3).
func (d *Dataplane) writeSketchConfig() error {
	s := &d.sk
	perCPU := (s.minCount + uint64(s.ncpu) - 1) / uint64(s.ncpu)
	return d.objs.SketchCfg.Put(uint32(0), lbSketchConfig{
		Epoch:     s.epoch,
		DropHeavy: boolToU32(s.drop),
		PhiPpm:    s.phiPPM,
		MinCount:  perCPU,
	})
}

// SetHeavyPolicy changes the heavy-hitter threshold and drop setting.
func (d *Dataplane) SetHeavyPolicy(phi float64, minCount uint64, drop bool) error {
	if phi <= 0 || phi > 1 || minCount == 0 {
		return fmt.Errorf("dataplane: bad heavy-hitter policy φ=%v min=%d", phi, minCount)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sk.phiPPM, d.sk.minCount, d.sk.drop = uint32(math.Round(phi*1e6)), minCount, drop
	return d.writeSketchConfig()
}

// HeavyHitter is a source confirmed heavy over a whole window.
type HeavyHitter struct {
	Addr     netip.Addr
	Estimate uint64 // Count-Min estimate â: never below the true count
	Lower    uint64 // â - εN: the true count is at least this with probability >= 1-δ
}

// Distinct is a VIP's estimated number of distinct sources in a window.
type Distinct struct {
	VIP      VIP
	Estimate float64
	StdError float64 // relative, 1.04/√m
}

// WindowReport summarises one closed window.
type WindowReport struct {
	Epoch    uint32
	Packets  uint64 // N: VIP packets counted
	Bound    uint64 // ⌊εN⌋
	Distinct []Distinct
	Heavy    []HeavyHitter // descending by estimate
	Flagged  int           // kernel candidates judged against this window
	Pending  int           // of those, not heavy here but flagged again in the new window: kept, not dropped
}

// RotateWindow closes the current window and returns its report. It
// switches the kernel to the other buffer, waits grace for programs already
// running on the old buffer to finish (they take microseconds), then merges
// the closed buffer across CPUs and judges every flagged source against it:
//
//   - heavy over the closed window: confirmed (dropped, with DropHeavy);
//   - not heavy, but flagged again in the new window: unconfirmed, and kept
//     to be judged at the end of the new window;
//   - otherwise: removed.
//
// Every candidate is judged whatever epoch its entry carries, because the
// kernel re-flags a source in place as soon as it crosses the threshold in
// the new window, which can happen before this code reads the entry. Finally
// the closed buffer is cleared for reuse.
func (d *Dataplane) RotateWindow(grace time.Duration) (WindowReport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	closed := d.sk.epoch
	d.sk.epoch++
	if err := d.writeSketchConfig(); err != nil {
		return WindowReport{}, err
	}
	if d.afterFlip != nil {
		d.afterFlip()
	}
	time.Sleep(grace)

	buf := closed & 1
	cm, err := d.readCountMin(buf)
	if err != nil {
		return WindowReport{}, err
	}
	r := WindowReport{Epoch: closed, Packets: cm.Total(), Bound: cm.Bound()}

	for vip, st := range d.vips {
		h, err := d.readHLL(buf, st.index)
		if err != nil {
			return WindowReport{}, err
		}
		r.Distinct = append(r.Distinct, Distinct{VIP: vip, Estimate: h.Estimate(), StdError: h.StdError()})
	}
	slices.SortFunc(r.Distinct, func(a, b Distinct) int { return a.VIP.Addr.Compare(b.VIP.Addr) })

	var key uint32
	var entry lbHeavyEntry
	var stale []uint32
	updates := map[uint32]lbHeavyEntry{}
	it := d.objs.Heavy.Iterate()
	for it.Next(&key, &entry) {
		r.Flagged++
		est := cm.Estimate(key)
		switch {
		case sketch.IsHeavy(est, cm.Total(), d.sk.minCount, d.sk.phiPPM):
			entry.Confirmed = 1
			updates[key] = entry
			r.Heavy = append(r.Heavy, HeavyHitter{Addr: addrFromKey(key), Estimate: est, Lower: est - min(est, r.Bound)})
		case entry.Epoch > closed:
			r.Pending++
			if entry.Confirmed != 0 {
				entry.Confirmed = 0
				updates[key] = entry
			}
		default:
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return WindowReport{}, err
	}
	// Deleting an entry unblocks its source; confirming one lets the
	// kernel drop it (when DropHeavy is on) until it stops being heavy over
	// a window. A kernel flag set between the read above and this delete
	// (microseconds) is lost; the kernel sets it again at the source's next
	// packet over the threshold.
	for _, k := range stale {
		if err := d.objs.Heavy.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return WindowReport{}, err
		}
	}
	for k, e := range updates {
		if err := d.objs.Heavy.Put(k, e); err != nil {
			return WindowReport{}, err
		}
	}
	slices.SortFunc(r.Heavy, func(a, b HeavyHitter) int {
		if a.Estimate != b.Estimate {
			if a.Estimate > b.Estimate {
				return -1
			}
			return 1
		}
		return a.Addr.Compare(b.Addr)
	})

	return r, d.clearBuffer(buf)
}

// readCountMin returns buffer buf of the Count-Min sketch, merged over CPUs.
func (d *Dataplane) readCountMin(buf uint32) (*sketch.CountMin, error) {
	n := CMDepth * CMWidth
	all, err := sumPerCPU(d.objs.Cm, 2*n, d.sk.ncpu)
	if err != nil {
		return nil, fmt.Errorf("dataplane: reading Count-Min: %w", err)
	}
	var totals []uint64
	if err := d.objs.CmTotal.Lookup(buf, &totals); err != nil {
		return nil, err
	}
	var total uint64
	for _, t := range totals {
		total += t
	}
	cm := sketch.NewCountMin(CMLogWidth, d.sk.seeds.CMA[:], d.sk.seeds.CMB[:])
	return cm, cm.Load(all[int(buf)*n:int(buf+1)*n], total)
}

// readHLL returns buffer buf of a VIP's HyperLogLog, merged over CPUs.
func (d *Dataplane) readHLL(buf, vipIndex uint32) (*sketch.HLL, error) {
	var perCPU []lbHllRegisters
	if err := d.objs.Hll.Lookup(buf*maxVIPsC+vipIndex, &perCPU); err != nil {
		return nil, fmt.Errorf("dataplane: reading HyperLogLog: %w", err)
	}
	merged := make([]uint8, 1<<HLLPrecision)
	for _, regs := range perCPU {
		for i, r := range regs.Reg {
			merged[i] = max(merged[i], r)
		}
	}
	h := sketch.NewHLL(HLLPrecision, d.sk.seeds.HLL)
	return h, h.Load(merged)
}

func (d *Dataplane) clearBuffer(buf uint32) error {
	n := CMDepth * CMWidth
	keys := make([]uint32, n)
	for i := range keys {
		keys[i] = buf*uint32(n) + uint32(i)
	}
	if err := putPerCPUZeros(d.objs.Cm, keys, d.sk.ncpu); err != nil {
		return fmt.Errorf("dataplane: clearing Count-Min: %w", err)
	}
	if err := d.objs.CmTotal.Put(buf, make([]uint64, d.sk.ncpu)); err != nil {
		return err
	}
	zero := make([]lbHllRegisters, d.sk.ncpu)
	for i := range uint32(maxVIPsC) {
		if err := d.objs.Hll.Put(buf*maxVIPsC+i, zero); err != nil {
			return fmt.Errorf("dataplane: clearing HyperLogLog: %w", err)
		}
	}
	return nil
}

// sumPerCPU reads a per-CPU array of uint64 and sums each entry over CPUs.
func sumPerCPU(m *ebpf.Map, entries, ncpu int) ([]uint64, error) {
	sums := make([]uint64, entries)
	keys := make([]uint32, entries)
	vals := make([]uint64, entries*ncpu)
	var cursor ebpf.MapBatchCursor
	got := 0
	for got < entries {
		n, err := m.BatchLookup(&cursor, keys[got:], vals[got*ncpu:], nil)
		for i := got; i < got+n; i++ {
			for c := range ncpu {
				sums[keys[i]] += vals[i*ncpu+c]
			}
		}
		got += n
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if errors.Is(err, ebpf.ErrNotSupported) {
			return sumPerCPUSlow(m, entries)
		}
		if err != nil {
			return nil, err
		}
	}
	if got != entries {
		return nil, fmt.Errorf("batch lookup returned %d of %d entries", got, entries)
	}
	return sums, nil
}

func sumPerCPUSlow(m *ebpf.Map, entries int) ([]uint64, error) {
	sums := make([]uint64, entries)
	var vals []uint64
	for k := range uint32(entries) {
		if err := m.Lookup(k, &vals); err != nil {
			return nil, err
		}
		for _, v := range vals {
			sums[k] += v
		}
	}
	return sums, nil
}

func putPerCPUZeros(m *ebpf.Map, keys []uint32, ncpu int) error {
	_, err := m.BatchUpdate(keys, make([]uint64, len(keys)*ncpu), nil)
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	zero := make([]uint64, ncpu)
	for _, k := range keys {
		if err := m.Put(k, zero); err != nil {
			return err
		}
	}
	return nil
}

// sourceKey is the 32-bit key the sketches use for an IPv4 source: the
// __be32 address as the program reads it from the packet.
func sourceKey(a netip.Addr) uint32 { return be32(a) }

func addrFromKey(k uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], k)
	return netip.AddrFrom4(b)
}
