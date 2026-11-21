package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/rushabh05/maglev-xdp/maglev"
)

// These tests load the real XDP program into the kernel and run packets
// through it with BPF_PROG_TEST_RUN. They need Linux and root (or CAP_BPF
// plus CAP_NET_ADMIN); elsewhere they skip. `make docker-test` runs them in
// a privileged container.

// XDP verdicts.
const (
	xdpDrop = 1
	xdpPass = 2
	xdpTX   = 3
)

var (
	lbMAC     = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xfe}
	clientMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xc1}
	vipAddr   = netip.MustParseAddr("10.0.0.100")
	webVIP    = VIP{Addr: vipAddr, Port: 80, Proto: TCP}
)

func load(t *testing.T, cfg Config) *Dataplane {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("XDP needs Linux; run `make docker-test`")
	}
	d, err := Load(cfg)
	if errors.Is(err, os.ErrPermission) {
		t.Skip("loading BPF programs needs root or CAP_BPF; run `make docker-test`")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// testBackends returns n backends 10.0.1.1, 10.0.1.2, ... whose MACs end in
// their index + 1, so a forwarded frame's MAC identifies its backend.
func testBackends(n int) []Backend {
	out := make([]Backend, n)
	for i := range out {
		out[i] = Backend{
			Addr: netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)}),
			MAC:  net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x01, byte(i + 1)},
		}
	}
	return out
}

func backendByMAC(t *testing.T, backends []Backend, mac []byte) Backend {
	t.Helper()
	for _, b := range backends {
		if bytes.Equal(b.MAC, mac) {
			return b
		}
	}
	t.Fatalf("frame sent to unknown MAC %s", net.HardwareAddr(mac))
	return Backend{}
}

// predict is the backend the Go control plane expects the data plane to pick
// for a flow that isn't in connection tracking.
func predict(t *testing.T, d *Dataplane, vip VIP, f Flow) netip.Addr {
	t.Helper()
	table, ok := d.Table(vip)
	if !ok {
		t.Fatalf("no table for %v", vip)
	}
	name, ok := table.Lookup(uint64(FlowHash(f)))
	if !ok {
		t.Fatalf("empty table for %v", vip)
	}
	return netip.MustParseAddr(name)
}

type pktOpts struct {
	etherType uint16 // default IPv4
	ihl       int    // default 5
	fragOff   uint16 // flags and offset, host order
	truncate  int    // bytes to cut from the end
}

// packet builds an Ethernet + IPv4 + TCP/UDP frame for a flow.
func packet(f Flow, o pktOpts) []byte {
	if o.etherType == 0 {
		o.etherType = 0x0800
	}
	if o.ihl == 0 {
		o.ihl = 5
	}
	payload := []byte("hello, backend")
	l4 := make([]byte, 20) // TCP header
	if f.Proto == UDP {
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[4:], uint16(8+len(payload)))
	} else {
		l4[12] = 5 << 4 // data offset
		l4[13] = 0x02   // SYN
	}
	binary.BigEndian.PutUint16(l4[0:], f.SrcPort)
	binary.BigEndian.PutUint16(l4[2:], f.DstPort)

	ip := make([]byte, 4*o.ihl)
	ip[0] = 0x40 | byte(o.ihl)
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(l4)+len(payload)))
	binary.BigEndian.PutUint16(ip[4:], 0x1234)
	binary.BigEndian.PutUint16(ip[6:], o.fragOff)
	ip[8] = 64
	ip[9] = byte(f.Proto)
	src, dst := f.Src.As4(), f.Dst.As4()
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))

	frame := append([]byte{}, lbMAC...)
	frame = append(frame, clientMAC...)
	frame = binary.BigEndian.AppendUint16(frame, o.etherType)
	frame = append(frame, ip...)
	frame = append(frame, l4...)
	frame = append(frame, payload...)
	return frame[:len(frame)-o.truncate]
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func run(t *testing.T, d *Dataplane, in []byte) (uint32, []byte) {
	t.Helper()
	ret, out, err := d.Program().Test(in)
	if err != nil {
		t.Fatal(err)
	}
	return ret, out
}

func flow(src string, sport uint16) Flow {
	return Flow{Src: netip.MustParseAddr(src), Dst: vipAddr, SrcPort: sport, DstPort: 80, Proto: TCP}
}

func randomFlow(rng *rand.Rand, vip VIP) Flow {
	return Flow{
		Src:     netip.AddrFrom4([4]byte{byte(1 + rng.IntN(223)), byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())}),
		Dst:     vip.Addr,
		SrcPort: uint16(1024 + rng.IntN(64511)),
		DstPort: vip.Port,
		Proto:   vip.Proto,
	}
}

func mustSetVIP(t *testing.T, d *Dataplane, vip VIP, backends []Backend) {
	t.Helper()
	if err := d.SetVIP(vip, backends); err != nil {
		t.Fatal(err)
	}
}

func TestPassesTrafficThatIsNotForAVIP(t *testing.T) {
	d := load(t, Config{})
	mustSetVIP(t, d, webVIP, testBackends(3))

	other := flow("192.0.2.1", 40000)
	other.Dst = netip.MustParseAddr("10.0.0.200")
	wrongPort := flow("192.0.2.1", 40000)
	wrongPort.DstPort = 8080
	udpToTCPVIP := flow("192.0.2.1", 40000)
	udpToTCPVIP.Proto = UDP
	icmp := flow("192.0.2.1", 40000)
	icmp.Proto = 1

	cases := map[string][]byte{
		"ARP":                     packet(flow("192.0.2.1", 1), pktOpts{etherType: 0x0806}),
		"IPv6 ethertype":          packet(flow("192.0.2.1", 1), pktOpts{etherType: 0x86dd}),
		"other destination":       packet(other, pktOpts{}),
		"VIP address, other port": packet(wrongPort, pktOpts{}),
		"UDP to a TCP VIP":        packet(udpToTCPVIP, pktOpts{}),
		"ICMP to the VIP address": packet(icmp, pktOpts{}),
		"IP options":              packet(flow("192.0.2.1", 1), pktOpts{ihl: 6}),
		"first fragment (MF set)": packet(flow("192.0.2.1", 1), pktOpts{fragOff: 0x2000}),
		"later fragment":          packet(flow("192.0.2.1", 1), pktOpts{fragOff: 0x0010}),
		"truncated in TCP header": packet(flow("192.0.2.1", 1), pktOpts{truncate: 14 + 20 + 1}),
		"truncated in IP header":  packet(flow("192.0.2.1", 1), pktOpts{truncate: 14 + 20 + 10}),
		"Ethernet header only":    packet(flow("192.0.2.1", 1), pktOpts{})[:14],
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			ret, out := run(t, d, in)
			if ret != xdpPass {
				t.Fatalf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
			}
			if !bytes.Equal(out, in) {
				t.Fatal("packet was modified")
			}
		})
	}
}

func TestL2Forwarding(t *testing.T) {
	d := load(t, Config{Mode: ModeL2})
	backends := testBackends(3)
	mustSetVIP(t, d, webVIP, backends)

	f := flow("192.0.2.1", 40000)
	in := packet(f, pktOpts{})
	ret, out := run(t, d, in)
	if ret != xdpTX {
		t.Fatalf("verdict = %d, want XDP_TX (%d)", ret, xdpTX)
	}
	if len(out) != len(in) {
		t.Fatalf("length = %d, want %d", len(out), len(in))
	}
	got := backendByMAC(t, backends, out[0:6])
	if want := predict(t, d, webVIP, f); got.Addr != want {
		t.Errorf("sent to %v, Go predicted %v", got.Addr, want)
	}
	if !bytes.Equal(out[6:12], lbMAC) {
		t.Errorf("source MAC = %s, want the load balancer's %s", net.HardwareAddr(out[6:12]), lbMAC)
	}
	if !bytes.Equal(out[12:], in[12:]) {
		t.Error("L2 mode changed bytes after the MAC addresses")
	}
}

func TestIPIPForwarding(t *testing.T) {
	lb := netip.MustParseAddr("10.0.0.1")
	d := load(t, Config{Mode: ModeIPIP, LBAddr: lb})
	backends := testBackends(3)
	mustSetVIP(t, d, webVIP, backends)

	for _, proto := range []Proto{TCP, UDP} {
		vip := webVIP
		vip.Proto = proto
		mustSetVIP(t, d, vip, backends)
		f := flow("192.0.2.1", 40000)
		f.Proto = proto

		in := packet(f, pktOpts{})
		ret, out := run(t, d, in)
		if ret != xdpTX {
			t.Fatalf("%v: verdict = %d, want XDP_TX (%d)", proto, ret, xdpTX)
		}
		if len(out) != len(in)+20 {
			t.Fatalf("%v: length = %d, want %d (input + 20-byte outer header)", proto, len(out), len(in)+20)
		}
		want := predict(t, d, vip, f)
		be := backendByMAC(t, backends, out[0:6])
		if be.Addr != want {
			t.Errorf("%v: sent to MAC of %v, Go predicted %v", proto, be.Addr, want)
		}
		if !bytes.Equal(out[6:12], lbMAC) || binary.BigEndian.Uint16(out[12:]) != 0x0800 {
			t.Errorf("%v: bad Ethernet header % x", proto, out[0:14])
		}

		outer := out[14:34]
		innerLen := binary.BigEndian.Uint16(in[16:])
		checks := []struct {
			what      string
			got, want any
		}{
			{"version/IHL", outer[0], byte(0x45)},
			{"total length", binary.BigEndian.Uint16(outer[2:]), innerLen + 20},
			{"TTL", outer[8], byte(64)},
			{"protocol", outer[9], byte(4)},
			{"source", netip.AddrFrom4([4]byte(outer[12:16])), lb},
			{"destination", netip.AddrFrom4([4]byte(outer[16:20])), want},
			{"checksum", checksum(outer), uint16(0)},
			{"inner packet unchanged", bytes.Equal(out[34:], in[14:]), true},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Errorf("%v: outer header %s = %v, want %v", proto, c.what, c.got, c.want)
			}
		}
	}
}

// The core cross-check: for thousands of random flows, the kernel picks the
// backend the Go Maglev table predicts. This only holds if the C and Go flow
// hashes, the slot arithmetic and the map layout all agree.
func TestDataplaneMatchesGo(t *testing.T) {
	d := load(t, Config{})
	backends := testBackends(10)
	udpVIP := VIP{Addr: vipAddr, Port: 53, Proto: UDP}
	mustSetVIP(t, d, webVIP, backends)
	mustSetVIP(t, d, udpVIP, backends)

	rng := rand.New(rand.NewPCG(3, 5))
	const flows = 5000
	perBackend := map[netip.Addr]int{}
	for i := range flows {
		vip := webVIP
		if i%2 == 1 {
			vip = udpVIP
		}
		f := randomFlow(rng, vip)
		ret, out := run(t, d, packet(f, pktOpts{}))
		if ret != xdpTX {
			t.Fatalf("flow %d: verdict = %d, want XDP_TX", i, ret)
		}
		got := backendByMAC(t, backends, out[0:6]).Addr
		if want := predict(t, d, vip, f); got != want {
			t.Fatalf("flow %+v: kernel chose %v, Go predicted %v", f, got, want)
		}
		perBackend[got]++
	}
	t.Logf("%d flows, all matched Go; per backend: %v", flows, perBackend)
	for _, b := range backends {
		if n := perBackend[b.Addr]; n < flows/10/2 || n > flows/10*2 {
			t.Errorf("%v got %d of %d flows; expected about %d", b.Addr, n, flows, flows/10)
		}
	}
}

// Connection tracking is what makes a backend change safe for established
// flows: Maglev alone moves a few flows between healthy backends.
func TestConntrackKeepsFlowsOnTheirBackend(t *testing.T) {
	d := load(t, Config{})
	backends := testBackends(6)
	five, six := backends[:5], backends
	mustSetVIP(t, d, webVIP, five)

	rng := rand.New(rand.NewPCG(9, 9))
	const n = 3000
	flows := make([]Flow, n)
	first := make([]netip.Addr, n)
	for i := range flows {
		flows[i] = randomFlow(rng, webVIP)
		_, out := run(t, d, packet(flows[i], pktOpts{}))
		first[i] = backendByMAC(t, backends, out[0:6]).Addr
	}
	before, _ := d.Table(webVIP)

	// Add a sixth backend. The table moves about 1/6 of slots; established
	// flows must not move.
	mustSetVIP(t, d, webVIP, six)
	after, _ := d.Table(webVIP)
	wouldMove, moved := 0, 0
	for i, f := range flows {
		b, _ := before.Lookup(uint64(FlowHash(f)))
		a, _ := after.Lookup(uint64(FlowHash(f)))
		if a != b {
			wouldMove++
		}
		_, out := run(t, d, packet(f, pktOpts{}))
		if backendByMAC(t, backends, out[0:6]).Addr != first[i] {
			moved++
		}
	}
	t.Logf("add backend: table alone would move %d of %d established flows; with conntrack %d moved", wouldMove, n, moved)
	if wouldMove == 0 {
		t.Fatal("test is vacuous: no flow's slot changed")
	}
	if moved != 0 {
		t.Errorf("%d established flows changed backend after a backend was added", moved)
	}

	// New flows follow the new table, including onto the new backend.
	onNew := 0
	for range 1000 {
		f := randomFlow(rng, webVIP)
		_, out := run(t, d, packet(f, pktOpts{}))
		got := backendByMAC(t, backends, out[0:6]).Addr
		if want := predict(t, d, webVIP, f); got != want {
			t.Fatalf("new flow went to %v, table says %v", got, want)
		}
		if got == six[5].Addr {
			onNew++
		}
	}
	if onNew == 0 {
		t.Error("no new flow reached the added backend")
	}

	// Remove backend 0. Its flows must move (to whatever the new table
	// says); everyone else's must stay.
	removed := six[0].Addr
	mustSetVIP(t, d, webVIP, six[1:])
	stayedWrongly, movedWrongly := 0, 0
	for i, f := range flows {
		_, out := run(t, d, packet(f, pktOpts{}))
		got := backendByMAC(t, backends, out[0:6]).Addr
		switch {
		case first[i] == removed && got == removed:
			stayedWrongly++
		case first[i] == removed && got != predict(t, d, webVIP, f):
			t.Fatalf("flow from removed backend went to %v, table says %v", got, predict(t, d, webVIP, f))
		case first[i] != removed && got != first[i]:
			movedWrongly++
		}
	}
	if stayedWrongly != 0 || movedWrongly != 0 {
		t.Errorf("remove backend: %d flows still sent to the removed backend, %d healthy flows moved", stayedWrongly, movedWrongly)
	}

	s, err := d.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.ConntrackHit == 0 || s.ConntrackMiss == 0 {
		t.Errorf("stats = %+v, want both conntrack hits and misses", s)
	}
}

func TestVIPWithoutBackendsDrops(t *testing.T) {
	d := load(t, Config{})
	mustSetVIP(t, d, webVIP, nil)
	if ret, _ := run(t, d, packet(flow("192.0.2.1", 1), pktOpts{})); ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	s, err := d.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.DropNoBackend != 1 {
		t.Errorf("DropNoBackend = %d, want 1", s.DropNoBackend)
	}
}

func TestDeleteVIP(t *testing.T) {
	d := load(t, Config{})
	mustSetVIP(t, d, webVIP, testBackends(2))
	if err := d.DeleteVIP(webVIP); err != nil {
		t.Fatal(err)
	}
	if ret, _ := run(t, d, packet(flow("192.0.2.1", 1), pktOpts{})); ret != xdpPass {
		t.Fatalf("verdict after DeleteVIP = %d, want XDP_PASS", ret)
	}
	if err := d.DeleteVIP(webVIP); !errors.Is(err, ErrUnknownVIP) {
		t.Errorf("second DeleteVIP: err = %v, want %v", err, ErrUnknownVIP)
	}
}

func TestVIPsHaveSeparateTables(t *testing.T) {
	d := load(t, Config{})
	all := testBackends(4)
	other := VIP{Addr: netip.MustParseAddr("10.0.0.101"), Port: 443, Proto: TCP}
	mustSetVIP(t, d, webVIP, all[:2])
	mustSetVIP(t, d, other, all[2:])

	rng := rand.New(rand.NewPCG(1, 1))
	for range 200 {
		for _, c := range []struct {
			vip  VIP
			pool []Backend
		}{{webVIP, all[:2]}, {other, all[2:]}} {
			_, out := run(t, d, packet(randomFlow(rng, c.vip), pktOpts{}))
			backendByMAC(t, c.pool, out[0:6]) // fails if outside the VIP's pool
		}
	}
}

func TestSetVIPRejectsBadInput(t *testing.T) {
	d := load(t, Config{TableSize: 1009})
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	v4 := netip.MustParseAddr("10.0.1.1")
	cases := []struct {
		name     string
		vip      VIP
		backends []Backend
		want     error
	}{
		{"duplicate backend", webVIP, []Backend{{v4, mac}, {v4, mac}}, maglev.ErrDuplicate},
		{"IPv6 VIP", VIP{netip.MustParseAddr("2001:db8::1"), 80, TCP}, nil, nil},
		{"ICMP VIP", VIP{vipAddr, 0, 1}, nil, nil},
		{"IPv6 backend", webVIP, []Backend{{netip.MustParseAddr("2001:db8::2"), mac}}, nil},
		{"short MAC", webVIP, []Backend{{v4, mac[:4]}}, nil},
	}
	for _, c := range cases {
		err := d.SetVIP(c.vip, c.backends)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: err = %v, want an error (%v)", c.name, err, c.want)
		}
	}

	for i := range d.maxVIPs {
		vip := VIP{Addr: netip.AddrFrom4([4]byte{10, 9, 0, byte(i)}), Port: 80, Proto: TCP}
		mustSetVIP(t, d, vip, nil)
	}
	extra := VIP{Addr: netip.MustParseAddr("10.9.1.0"), Port: 80, Proto: TCP}
	if err := d.SetVIP(extra, nil); !errors.Is(err, ErrTooManyVIPs) {
		t.Errorf("VIP %d: err = %v, want %v", d.maxVIPs+1, err, ErrTooManyVIPs)
	}
}

func TestLoadRejectsBadConfig(t *testing.T) {
	for _, cfg := range []Config{
		{TableSize: 100},
		{Mode: 7},
		{Mode: ModeIPIP}, // no LBAddr
	} {
		if d, err := Load(cfg); err == nil {
			d.Close()
			t.Errorf("Load(%+v) succeeded, want an error", cfg)
		}
	}
}
