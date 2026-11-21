//go:build ignore

// Helper for scripts/e2e.sh.
//
//	udp listen  -addr 10.0.0.100:5353                 print the source port of each datagram
//	udp send    -to 10.0.0.100:5353 -ports 40000-40099 one datagram from each source port
//	udp predict -vip 10.0.0.100:5353 -src 10.0.0.2 -ports 40000-40099 -backends file
//	                                                  print "<port> <backend>" as Go expects the data plane to choose
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/rushabh05/maglev-xdp/dataplane"
	"github.com/rushabh05/maglev-xdp/maglev"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: udp listen|send|predict [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "", "listen address")
	to := fs.String("to", "", "destination")
	vip := fs.String("vip", "", "VIP address:port")
	src := fs.String("src", "", "client source address")
	ports := fs.String("ports", "", "source port range, e.g. 40000-40099")
	backends := fs.String("backends", "", "backends file")
	size := fs.Int("size", maglev.DefaultSize, "Maglev table size")
	fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "listen":
		conn, err := net.ListenPacket("udp4", *addr)
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, 2048)
		for {
			_, from, err := conn.ReadFrom(buf)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(from.(*net.UDPAddr).Port)
		}
	case "send":
		dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(*to))
		lo, hi := portRange(*ports)
		for p := lo; p <= hi; p++ {
			conn, err := net.DialUDP("udp4", &net.UDPAddr{Port: p}, dst)
			if err != nil {
				log.Fatal(err)
			}
			if _, err := conn.Write([]byte("hello from port " + strconv.Itoa(p))); err != nil {
				log.Fatal(err)
			}
			conn.Close()
		}
	case "predict":
		ap := netip.MustParseAddrPort(*vip)
		names := readBackends(*backends)
		table, err := maglev.Build(names, *size)
		if err != nil {
			log.Fatal(err)
		}
		lo, hi := portRange(*ports)
		for p := lo; p <= hi; p++ {
			f := dataplane.Flow{Src: netip.MustParseAddr(*src), Dst: ap.Addr(), SrcPort: uint16(p), DstPort: ap.Port(), Proto: dataplane.UDP}
			be, _ := table.Lookup(uint64(dataplane.FlowHash(f)))
			fmt.Println(p, be)
		}
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func portRange(s string) (int, int) {
	a, b, _ := strings.Cut(s, "-")
	lo, err1 := strconv.Atoi(a)
	hi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || lo > hi {
		log.Fatalf("bad port range %q", s)
	}
	return lo, hi
}

func readBackends(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) == 2 && !strings.HasPrefix(fields[0], "#") {
			names = append(names, fields[0])
		}
	}
	return names
}
