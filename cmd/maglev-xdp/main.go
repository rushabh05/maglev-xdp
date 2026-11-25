// Command maglev-xdp runs the XDP load balancer on one interface for one VIP.
//
//	maglev-xdp -iface eth0 -vip 10.0.0.100:80/tcp -backends backends.txt
//	maglev-xdp -iface eth0 -vip 10.0.0.100:80/tcp -backends backends.txt -mode ipip -lb-addr 10.0.0.1
//
// The backends file has one backend per line, "<IPv4 address> <next-hop MAC>";
// blank lines and lines starting with # are ignored. Send SIGHUP to reload it:
// the Maglev table is rebuilt and swapped in, and connection tracking keeps
// established flows on their backend. Needs Linux and root.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/rushabh05/maglev-xdp/dataplane"
	"github.com/rushabh05/maglev-xdp/maglev"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		iface    = flag.String("iface", "", "interface to attach to (required)")
		vipFlag  = flag.String("vip", "", "virtual service, e.g. 10.0.0.100:80/tcp (required)")
		file     = flag.String("backends", "", "backends file (required)")
		modeFlag = flag.String("mode", "l2", "forwarding mode: l2 (MAC rewrite) or ipip (IP-in-IP)")
		lbAddr   = flag.String("lb-addr", "", "outer source address for -mode ipip")
		size     = flag.Int("size", maglev.DefaultSize, "Maglev table size (prime)")
		xdpMode  = flag.String("xdp-mode", "auto", "attach mode: auto, driver or generic")
		every    = flag.Duration("stats", 5*time.Second, "how often to log counters (0 to disable)")
		window   = flag.Duration("window", 5*time.Second, "traffic-sketch window: report distinct sources and heavy hitters this often")
		noSketch = flag.Bool("no-sketch", false, "leave the traffic sketches out of the packet path")
		hhPhi    = flag.Float64("hh-phi", 0.01, "heavy hitter: share of a window's VIP packets from one source")
		hhMin    = flag.Uint64("hh-min", 1000, "heavy hitter: and at least this many packets in the window")
		hhDrop   = flag.Bool("drop-heavy", false, "drop packets from heavy hitters (flood mitigation)")
		topN     = flag.Int("top", 5, "heavy hitters to log per window")
	)
	flag.Parse()
	if *iface == "" || *vipFlag == "" || *file == "" {
		flag.Usage()
		return errors.New("-iface, -vip and -backends are required")
	}

	vip, err := parseVIP(*vipFlag)
	if err != nil {
		return err
	}
	cfg := dataplane.Config{TableSize: *size, Sketch: dataplane.SketchConfig{
		Disabled: *noSketch, Phi: *hhPhi, MinCount: *hhMin, DropHeavy: *hhDrop,
	}}
	if *window <= 0 {
		return errors.New("-window must be positive")
	}
	switch *modeFlag {
	case "l2":
		cfg.Mode = dataplane.ModeL2
	case "ipip":
		cfg.Mode = dataplane.ModeIPIP
		if cfg.LBAddr, err = netip.ParseAddr(*lbAddr); err != nil {
			return fmt.Errorf("-lb-addr: %w", err)
		}
	default:
		return fmt.Errorf("-mode %q: want l2 or ipip", *modeFlag)
	}
	var flags link.XDPAttachFlags
	switch *xdpMode {
	case "auto":
	case "driver":
		flags = link.XDPDriverMode
	case "generic":
		flags = link.XDPGenericMode
	default:
		return fmt.Errorf("-xdp-mode %q: want auto, driver or generic", *xdpMode)
	}

	backends, err := readBackends(*file)
	if err != nil {
		return err
	}
	dp, err := dataplane.Load(cfg)
	if err != nil {
		return err
	}
	defer dp.Close()
	if err := dp.SetVIP(vip, backends); err != nil {
		return err
	}
	l, err := dp.Attach(*iface, flags)
	if err != nil {
		return fmt.Errorf("attaching to %s: %w", *iface, err)
	}
	defer l.Close()
	log.Printf("balancing %v across %d backends on %s (mode %v, xdp %s, table %d)",
		vip, len(backends), *iface, cfg.Mode, *xdpMode, dp.TableSize())
	var windows <-chan time.Time
	if !*noSketch {
		p := dataplane.Params()
		log.Printf("sketch: count-min %d x %d (ε=%.2e, δ=%.4f), hyperloglog m=%d (±%.2f%%), %d KiB per CPU; heavy = ≥%.2f%% and ≥%d packets per %v window, drop %v",
			p.Depth, p.Width, p.Epsilon, p.Delta, p.HLLRegisters, 100*p.HLLStdError, p.BytesPerCPU/1024,
			100**hhPhi, *hhMin, *window, *hhDrop)
		t := time.NewTicker(*window)
		defer t.Stop()
		windows = t.C
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	var tick <-chan time.Time
	if *every > 0 {
		t := time.NewTicker(*every)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-tick:
			if s, err := dp.Stats(); err == nil {
				log.Printf("rx=%d tx=%d pass=%d drop_no_backend=%d drop_error=%d drop_heavy=%d ct_hit=%d ct_miss=%d",
					s.RX, s.TX, s.Pass, s.DropNoBackend, s.DropError, s.DropHeavy, s.ConntrackHit, s.ConntrackMiss)
			}
		case <-windows:
			r, err := dp.RotateWindow(10 * time.Millisecond)
			if err != nil {
				log.Printf("sketch: %v", err)
				continue
			}
			logWindow(r, *topN)
		case sig := <-sigs:
			if sig != syscall.SIGHUP {
				log.Printf("%v: detaching", sig)
				return nil
			}
			reload(dp, vip, *file)
		}
	}
}

// logWindow prints one line per window, for example
//
//	sketch: window 12: 48210 packets, 10.0.0.100:80/tcp ≈1532 sources (±0.81%); heavy: 192.0.2.7 ≈20113 [20081, 20113]
//
// where [lower, estimate] holds the true count with probability >= 1-δ.
func logWindow(r dataplane.WindowReport, top int) {
	var b strings.Builder
	fmt.Fprintf(&b, "sketch: window %d: %d packets", r.Epoch, r.Packets)
	for _, d := range r.Distinct {
		fmt.Fprintf(&b, ", %v ≈%.0f sources (±%.2f%%)", d.VIP, d.Estimate, 100*d.StdError)
	}
	b.WriteString("; heavy:")
	if len(r.Heavy) == 0 {
		b.WriteString(" none")
	}
	for i, h := range r.Heavy {
		if i == top {
			fmt.Fprintf(&b, " (+%d more)", len(r.Heavy)-top)
			break
		}
		fmt.Fprintf(&b, " %v ≈%d [%d, %d]", h.Addr, h.Estimate, h.Lower, h.Estimate)
	}
	log.Print(b.String())
}

func reload(dp *dataplane.Dataplane, vip dataplane.VIP, file string) {
	backends, err := readBackends(file)
	if err != nil {
		log.Printf("reload: %v (keeping the current backends)", err)
		return
	}
	old, _ := dp.Table(vip)
	start := time.Now()
	if err := dp.SetVIP(vip, backends); err != nil {
		log.Printf("reload: %v", err)
		return
	}
	cur, _ := dp.Table(vip)
	if d, err := maglev.Compare(old, cur); err == nil {
		log.Printf("reload: %d backends in %v; %.2f%% of slots moved (new flows only: connection tracking keeps established ones)",
			len(backends), time.Since(start).Round(time.Microsecond), 100*d.ChangedFraction())
	}
}

func parseVIP(s string) (dataplane.VIP, error) {
	hostPort, protoName, ok := strings.Cut(s, "/")
	if !ok {
		protoName = "tcp"
	}
	ap, err := netip.ParseAddrPort(hostPort)
	if err != nil {
		return dataplane.VIP{}, fmt.Errorf("-vip %q: %w", s, err)
	}
	vip := dataplane.VIP{Addr: ap.Addr(), Port: ap.Port()}
	switch strings.ToLower(protoName) {
	case "tcp":
		vip.Proto = dataplane.TCP
	case "udp":
		vip.Proto = dataplane.UDP
	default:
		return dataplane.VIP{}, fmt.Errorf("-vip %q: protocol must be tcp or udp", s)
	}
	return vip, nil
}

func readBackends(path string) ([]dataplane.Backend, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []dataplane.Backend
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"<address> <mac>\"", path, n)
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		mac, err := net.ParseMAC(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		out = append(out, dataplane.Backend{Addr: addr, MAC: mac})
	}
	return out, sc.Err()
}
