// Package dataplane loads the XDP load balancer (bpf/lb.c) into the kernel
// and keeps its maps in step with the control plane's view of VIPs and
// backends. It needs Linux and CAP_BPF/CAP_NET_ADMIN (or root).
package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/rushabh05/maglev-xdp/maglev"
)

// Mode selects how packets are forwarded to a backend.
type Mode uint32

const (
	// ModeL2 rewrites the destination MAC to the backend's and sends the
	// frame back out. The backend must be on the same L2 segment and accept
	// traffic for the VIP (direct server return).
	ModeL2 Mode = 0
	// ModeIPIP wraps the packet in an outer IPv4 header from Config.LBAddr
	// to the backend. The backend decapsulates and replies to the client
	// directly.
	ModeIPIP Mode = 1
)

func (m Mode) String() string {
	switch m {
	case ModeL2:
		return "l2"
	case ModeIPIP:
		return "ipip"
	}
	return fmt.Sprintf("mode(%d)", uint32(m))
}

// Config is fixed for the lifetime of a loaded program.
type Config struct {
	// TableSize is the Maglev table size per VIP. It must be prime.
	// Zero means maglev.DefaultSize.
	TableSize int
	Mode      Mode
	// LBAddr is the outer source address in ModeIPIP.
	LBAddr netip.Addr
	// Sketch configures the traffic sketches; the zero value enables them
	// with default thresholds and random seeds.
	Sketch SketchConfig
}

// VIP is a virtual service: traffic to Addr:Port over Proto is balanced.
type VIP struct {
	Addr  netip.Addr
	Port  uint16
	Proto Proto
}

func (v VIP) String() string { return fmt.Sprintf("%s:%d/%s", v.Addr, v.Port, v.Proto) }

// Backend is a real server behind a VIP.
type Backend struct {
	Addr netip.Addr
	// MAC is the next hop for reaching Addr: the backend's own MAC when it
	// is on the same L2 segment, otherwise the gateway's.
	MAC net.HardwareAddr
}

// Stats are packet counters summed over all CPUs.
type Stats struct {
	RX, Pass, TX, DropNoBackend, DropError, ConntrackHit, ConntrackMiss, DropHeavy uint64
}

var (
	ErrTooManyVIPs = errors.New("dataplane: no free VIP slots")
	ErrUnknownVIP  = errors.New("dataplane: unknown VIP")
)

// Dataplane is a loaded XDP program and its maps.
type Dataplane struct {
	mu      sync.Mutex
	objs    lbObjects
	size    int
	maxVIPs int
	vips    map[VIP]*vipState
	nextID  uint32 // backend IDs are never reused; 0 means "none"
	sk      sketchState

	afterFlip func() // test hook: runs in RotateWindow right after the epoch switch
}

type vipState struct {
	index uint32
	ids   map[netip.Addr]uint32 // backend address -> backend ID
	table *maglev.Table
}

// Load verifies and loads the XDP program. It does not attach it to an
// interface; see Attach.
func Load(cfg Config) (*Dataplane, error) {
	size := cfg.TableSize
	if size == 0 {
		size = maglev.DefaultSize
	}
	if _, err := maglev.Build(nil, size); err != nil {
		return nil, err
	}
	if cfg.Mode != ModeL2 && cfg.Mode != ModeIPIP {
		return nil, fmt.Errorf("dataplane: unknown mode %d", cfg.Mode)
	}
	if cfg.Mode == ModeIPIP && !cfg.LBAddr.Is4() {
		return nil, fmt.Errorf("dataplane: IP-in-IP mode needs an IPv4 LBAddr, got %v", cfg.LBAddr)
	}
	sk, err := newSketchState(cfg.Sketch)
	if err != nil {
		return nil, err
	}
	// Only needed on kernels before 5.11, which charge BPF memory to
	// RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	spec, err := loadLb()
	if err != nil {
		return nil, err
	}
	maxVIPs := int(spec.Maps["vips"].MaxEntries)
	if maxVIPs != maxVIPsC || int(spec.Maps["hll"].MaxEntries) != 2*maxVIPsC {
		return nil, fmt.Errorf("dataplane: MAX_VIPS in bpf/lb.c changed; update maxVIPsC")
	}
	spec.Maps["tables"].MaxEntries = uint32(maxVIPs * size)
	var lbAddr [4]byte
	if cfg.Mode == ModeIPIP {
		lbAddr = cfg.LBAddr.As4()
	}
	for name, v := range map[string]any{
		"table_size":     uint32(size),
		"mode":           uint32(cfg.Mode),
		"lb_addr":        lbAddr,
		"sketch_enabled": boolToU32(!cfg.Sketch.Disabled),
		"cm_a":           sk.seeds.CMA,
		"cm_b":           sk.seeds.CMB,
		"hll_seed":       sk.seeds.HLL,
	} {
		if err := spec.Variables[name].Set(v); err != nil {
			return nil, fmt.Errorf("dataplane: setting %s: %w", name, err)
		}
	}

	d := &Dataplane{size: size, maxVIPs: maxVIPs, vips: make(map[VIP]*vipState), sk: sk}
	if err := spec.LoadAndAssign(&d.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("dataplane: verifier rejected the program: %+v", ve)
		}
		return nil, fmt.Errorf("dataplane: loading: %w", err)
	}
	if err := d.writeSketchConfig(); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// Close unloads the program and its maps. Links created by Attach must be
// closed separately.
func (d *Dataplane) Close() error { return d.objs.Close() }

// Program returns the XDP program, for attaching or test runs.
func (d *Dataplane) Program() *ebpf.Program { return d.objs.XdpLb }

// TableSize returns the Maglev table size per VIP.
func (d *Dataplane) TableSize() int { return d.size }

// Attach attaches the program to an interface. flags is 0 (let the kernel
// choose), link.XDPDriverMode or link.XDPGenericMode.
func (d *Dataplane) Attach(ifname string, flags link.XDPAttachFlags) (link.Link, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	return link.AttachXDP(link.XDPOptions{Program: d.objs.XdpLb, Interface: iface.Index, Flags: flags})
}

// SetVIP creates or updates a VIP with the given backends. It builds the
// VIP's Maglev table and writes the maps in an order that keeps every packet
// routable while the update is in progress:
//
//  1. add or update backends, so every ID the new table uses exists;
//  2. overwrite the table (packets meanwhile see a mix of old and new slots,
//     all pointing at live backends);
//  3. publish the VIP, if it is new;
//  4. delete backends that left. Flows pinned to them in connection tracking
//     fail their backend lookup and get a new one from the table.
//
// A backend that stays keeps its ID, so connection tracking keeps its flows
// on it even if its slots in the table move. An empty backend list keeps the
// VIP but drops its traffic. If SetVIP returns an error the maps may be
// partly updated; calling it again with the same arguments repairs them.
func (d *Dataplane) SetVIP(vip VIP, backends []Backend) error {
	if err := checkVIP(vip); err != nil {
		return err
	}
	names := make([]string, len(backends))
	byName := make(map[string]Backend, len(backends))
	for i, b := range backends {
		if !b.Addr.Is4() {
			return fmt.Errorf("dataplane: backend %v is not IPv4", b.Addr)
		}
		if len(b.MAC) != 6 {
			return fmt.Errorf("dataplane: backend %v: MAC %q is not 6 bytes", b.Addr, b.MAC)
		}
		names[i] = b.Addr.String()
		byName[names[i]] = b
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	table, err := maglev.Build(names, d.size) // also rejects duplicates
	if err != nil {
		return err
	}

	st, exists := d.vips[vip]
	if !exists {
		idx, ok := d.freeIndex()
		if !ok {
			return ErrTooManyVIPs
		}
		st = &vipState{index: idx, ids: map[netip.Addr]uint32{}}
	}

	// 1. Backends.
	ids := make(map[netip.Addr]uint32, len(backends))
	for _, b := range backends {
		id, ok := st.ids[b.Addr]
		if !ok {
			d.nextID++
			id = d.nextID
		}
		var val lbBackend
		val.Addr = be32(b.Addr)
		copy(val.Mac[:], b.MAC)
		if err := d.objs.Backends.Put(id, val); err != nil {
			return fmt.Errorf("dataplane: writing backend %v: %w", b.Addr, err)
		}
		ids[b.Addr] = id
	}

	// 2. Table.
	idOf := make([]uint32, table.Len())
	for i, name := range table.Backends() {
		idOf[i] = ids[byName[name].Addr]
	}
	keys := make([]uint32, d.size)
	values := make([]uint32, d.size) // all zero ("no backend") if the table is empty
	base := st.index * uint32(d.size)
	entries := table.Entries()
	for s := range keys {
		keys[s] = base + uint32(s)
		if entries != nil {
			values[s] = idOf[entries[s]]
		}
	}
	if err := d.writeTable(keys, values); err != nil {
		return fmt.Errorf("dataplane: writing table for %v: %w", vip, err)
	}

	// 3. VIP.
	if !exists {
		if err := d.objs.Vips.Put(vipKey(vip), lbVipInfo{Index: st.index}); err != nil {
			return fmt.Errorf("dataplane: publishing %v: %w", vip, err)
		}
	}

	// 4. Backends that left.
	for addr, id := range st.ids {
		if _, ok := ids[addr]; !ok {
			if err := d.objs.Backends.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("dataplane: removing backend %v: %w", addr, err)
			}
		}
	}

	st.ids, st.table = ids, table
	d.vips[vip] = st
	return nil
}

// DeleteVIP stops balancing a VIP; its traffic goes back to the kernel.
func (d *Dataplane) DeleteVIP(vip VIP) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.vips[vip]
	if !ok {
		return fmt.Errorf("%w: %v", ErrUnknownVIP, vip)
	}
	if err := d.objs.Vips.Delete(vipKey(vip)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	for _, id := range st.ids {
		if err := d.objs.Backends.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	// The table slice is left as is; SetVIP rewrites all of it before a new
	// VIP that reuses the index is published.
	delete(d.vips, vip)
	return nil
}

// Table returns the Maglev table currently installed for a VIP.
func (d *Dataplane) Table(vip VIP) (*maglev.Table, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.vips[vip]
	if !ok {
		return nil, false
	}
	return st.table, true
}

// Stats returns the program's packet counters.
func (d *Dataplane) Stats() (Stats, error) {
	var s Stats
	for stat, dst := range map[lbStat]*uint64{
		lbStatSTAT_RX:              &s.RX,
		lbStatSTAT_PASS:            &s.Pass,
		lbStatSTAT_TX:              &s.TX,
		lbStatSTAT_DROP_NO_BACKEND: &s.DropNoBackend,
		lbStatSTAT_DROP_ERROR:      &s.DropError,
		lbStatSTAT_CT_HIT:          &s.ConntrackHit,
		lbStatSTAT_CT_MISS:         &s.ConntrackMiss,
		lbStatSTAT_DROP_HEAVY:      &s.DropHeavy,
	} {
		var perCPU []uint64
		if err := d.objs.Stats.Lookup(uint32(stat), &perCPU); err != nil {
			return Stats{}, err
		}
		for _, v := range perCPU {
			*dst += v
		}
	}
	return s, nil
}

func (d *Dataplane) freeIndex() (uint32, bool) {
	used := make([]bool, d.maxVIPs)
	for _, st := range d.vips {
		used[st.index] = true
	}
	i := slices.Index(used, false)
	return uint32(i), i >= 0
}

// writeTable writes the slots with one batch syscall where the kernel
// supports it (5.6+), falling back to one update per slot.
func (d *Dataplane) writeTable(keys, values []uint32) error {
	_, err := d.objs.Tables.BatchUpdate(keys, values, nil)
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	for i := range keys {
		if err := d.objs.Tables.Put(keys[i], values[i]); err != nil {
			return err
		}
	}
	return nil
}

func checkVIP(v VIP) error {
	if !v.Addr.Is4() {
		return fmt.Errorf("dataplane: VIP %v is not IPv4", v.Addr)
	}
	if v.Proto != TCP && v.Proto != UDP {
		return fmt.Errorf("dataplane: VIP %v: protocol must be TCP or UDP", v)
	}
	return nil
}

func vipKey(v VIP) lbVipKey {
	return lbVipKey{Addr: be32(v.Addr), Port: be16(v.Port), Proto: uint8(v.Proto)}
}

// be32 returns the uint32 whose in-memory bytes are the address in network
// order, matching a __be32 field read by the BPF program.
func be32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.NativeEndian.Uint32(b[:])
}

// be16 is the __be16 equivalent for ports.
func be16(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}
