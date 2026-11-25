# maglev-xdp

An L4 load balancer: Maglev consistent hashing ([Eisenbud et al., NSDI '16](https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/eisenbud)) in a Go control plane, with an eBPF/XDP data plane that forwards packets inside the network driver. The data plane also keeps streaming sketches of its traffic:

- a **Count-Min** sketch of packets per source, for heavy-hitter detection and optional flood dropping;
- a **HyperLogLog** of distinct sources per VIP.

Both come with error bounds that are proved in [docs/MATH.md](docs/MATH.md) and checked against measurements.

> **Status: phases 1 and 2 of 3 are done, plus the traffic sketches.**
>
> - **Tested in the kernel:** the XDP program forwards IPv4 TCP and UDP to backends chosen by the Maglev table, in L2 (MAC rewrite) or IP-in-IP mode. Connection tracking keeps established flows on their backend across a hot reload.
> - **Sketches:** the kernel's sketches equal a Go reference implementation bit for bit, and a flooding source is detected and dropped while normal traffic gets through.
> - **Where it ran:** kernel unit tests plus an end-to-end run with real packets over virtual interfaces, on arm64 in Docker and on x86-64 in CI ([what was run](#what-was-run-and-what-wasnt)).
> - **Not yet:** it has **not** run on a physical NIC or in native driver mode, and **nothing has been benchmarked for throughput**. The 10M+ packets/s per core figure is a target for phase 3, not a measurement.

## What works and what doesn't

| Piece | State |
|---|---|
| Maglev table population (Go), prime table size, 65537 by default | ✅ Works, tested, including the paper's worked example |
| Backend add, remove and replace-all, with an atomic table swap | ✅ Works, tested under `-race` |
| Disruption measurement (slots and simulated flows) | ✅ Works, [numbers below](#measured-disruption) |
| XDP data plane in C (parse Ethernet/IPv4/TCP/UDP, hash, look up, forward) | ✅ Works in kernel tests and on veth interfaces |
| Forwarding: L2 MAC rewrite (`XDP_TX`) and IP-in-IP encapsulation | ✅ Both modes, tested |
| Go loader with cilium/ebpf: config, VIPs, backends, table writes, stats | ✅ Works |
| Go and C pick the same backend | ✅ Checked over 5,000 random flows in the kernel |
| Connection tracking (LRU map) | ✅ Established flows don't move when a backend is added; flows on a removed backend move |
| `maglev-xdp` daemon with hot reload on SIGHUP | ✅ Works on veth (reload took about 2 ms for 4 backends) |
| Count-Min sketch of packets per source (5 × 4096, ε ≈ 6.6×10⁻⁴, δ ≈ 0.0067) | ✅ Kernel equals the Go reference bit for bit; bound held for 100% of 3.06M estimates |
| HyperLogLog of distinct sources per VIP (m = 16384, ±0.81%) | ✅ Kernel equals Go bit for bit; measured error matches 1.04/√m except near 2.5m ([details](docs/MATH.md#3-hyperloglog-distinct-sources)) |
| Heavy-hitter detection, per-CPU flags plus userspace confirmation | ✅ Precision 1.0 and recall 1.0 in the kernel on a mixed flood; recall on sources ≥ φN + min is proved |
| `-drop-heavy`: drop confirmed flooders in XDP | ✅ Off by default. 200/200 flood packets dropped after confirmation, 100/100 normal forwarded |
| [docs/MATH.md](docs/MATH.md): derivations for the table, the sketches and per-CPU merging | ✅ |
| `maglev-stats` CLI | ✅ Works |
| Native (driver) XDP on a physical NIC | ⏳ Not run. Only generic mode on veth (see below) |
| Benchmarks against IPVS and HAProxy | ⏳ Phase 3. Nothing measured yet |
| Health checks | ⏳ Not started. Backends only change when the file changes |
| Weighted backends | ❌ Not implemented |
| IPv6, IP options, IP fragments | ❌ Passed to the kernel untouched |

## Quick start

Requires Go 1.25 or newer (cilium/ebpf v0.22 needs it). CI tests Go 1.25 and the current release. Anything that touches XDP needs Linux and root. On macOS those targets run in Docker.

```bash
make test           # Go tests that run anywhere; the kernel tests skip off Linux
make docker-test    # every test, including the XDP program in the kernel (privileged container)
make e2e            # real packets over veth interfaces, in both forwarding modes
make generate       # recompile bpf/lb.c and regenerate the Go bindings (needs clang; runs in Docker)
```

Running the load balancer on Linux, as root:

```bash
cat > backends.txt <<'EOF'
# <backend IPv4> <next-hop MAC>
10.0.0.11 02:00:00:00:00:11
10.0.0.12 02:00:00:00:00:12
EOF
go run ./cmd/maglev-xdp -iface eth0 -vip 10.0.0.100:80/tcp -backends backends.txt               # L2 mode
go run ./cmd/maglev-xdp -iface eth0 -vip 10.0.0.100:80/tcp -backends backends.txt \
    -mode ipip -lb-addr 10.0.0.1                                                                 # IP-in-IP mode
kill -HUP <pid>     # after editing backends.txt: rebuild the table and swap it in
```

Traffic-sketch flags:

| flag | default | meaning |
|---|---|---|
| `-window` | `5s` | window length for the sketch reports |
| `-hh-phi` | `0.01` | heavy-hitter share of the window's packets |
| `-hh-min` | `1000` | heavy-hitter packet floor per window |
| `-drop-heavy` | off | drop confirmed heavy hitters |
| `-no-sketch` | off | take the sketches off the packet path |

Each window the daemon logs one line:

```text
sketch: window 1: 1210 packets, 10.0.0.100:5353/udp ≈31 sources (±0.81%); heavy: 10.0.0.250 ≈1000 [1000, 1000]
```

Each heavy hitter is reported as `≈estimate [lower, estimate]`. The true count lies in that interval with probability at least 1−δ.

Backends reply to clients directly (direct server return), so each backend needs the VIP configured locally: on its loopback interface in L2 mode, plus an IP-in-IP tunnel device in IP-in-IP mode. [`scripts/e2e.sh`](scripts/e2e.sh) sets up both.

The table-only CLI from phase 1 still works anywhere:

```bash
go run ./cmd/maglev-stats -n 10 -fail be-03       # 10 backends, then fail one
```

## How it works

### The Maglev table (Go, `maglev/`)

Each backend gets a pseudo-random preference order over the `M` table slots, `(offset + j·skip) mod M`. Its `offset` and `skip` come from two hashes of the backend's name. The backends take turns claiming their most-preferred slot that is still free until the table is full. So every backend ends up with ⌊M/N⌋ or ⌈M/N⌉ slots, and a packet's backend is `table[hash(5-tuple) mod M]`.

- **Same input, same table.** Backends are sorted before the build, and the name hash is fixed (FNV-1a plus a MurmurHash3 finaliser), so separate load-balancer instances with the same backends build identical tables. `TestGoldenTable` pins the output.
- **Immutable tables.** `Build` returns a `Table` that never changes. `Pool` rebuilds on every change and swaps the new table in atomically.
- **No permutation matrix.** The build keeps one cursor per backend, so extra memory is O(N), not O(N·M).

### The data plane (C/eBPF, `bpf/lb.c`; Go loader, `dataplane/`)

For each packet:

1. **Skip what isn't ours.** Anything that isn't IPv4 TCP/UDP for a configured VIP (address, port, protocol) gets `XDP_PASS`, untouched. So do packets with IP options, fragments and truncated packets.
2. **Pick a backend.** If the flow is in the connection-tracking map and its backend still exists, use that backend. Otherwise hash the 5-tuple with MurmurHash3 and read slot `hash mod M` of the VIP's table, giving a backend ID. Look up the backend and record the choice in connection tracking.
3. **Forward with `XDP_TX`.**
   - **L2 mode:** set the destination MAC to the backend's next hop, and the source MAC to the load balancer's.
   - **IP-in-IP mode:** grow the packet by 20 bytes and write an outer IPv4 header (load balancer → backend, protocol 4, with checksum) in front of the original packet.

| Map | Type | Contents |
|---|---|---|
| `vips` | hash, 16 entries | VIP → index of its table |
| `tables` | array, 16 × M | the Maglev tables back to back; values are backend IDs (0 = none) |
| `backends` | hash, 4096 entries | backend ID → address and next-hop MAC |
| `conntrack` | LRU hash, 65536 entries | 5-tuple → backend ID |
| `stats` | per-CPU array | rx, tx, pass, drops, conntrack hits and misses |

**Hot reload.** The table size, mode and outer source address are constants set at load time. Everything else changes live. `Dataplane.SetVIP` writes the maps in an order that keeps every packet routable:

1. Add the new backends.
2. Overwrite the table. While this runs, packets see a mix of old and new slots, but every slot points at a live backend.
3. Publish the VIP, if it's new.
4. Delete the backends that left.

Backend IDs are stable and never reused. So a backend that stays keeps its connection-tracking entries, and an entry pointing at a removed backend misses and gets a new backend.

**Keeping Go and C in step.** `dataplane.FlowHash` is the Go version of the C hash. It is checked against published MurmurHash3 test vectors, and `TestDataplaneMatchesGo` checks in the kernel that both sides choose the same backend.

### Traffic sketches (`bpf/lb.c` `observe`; Go reference in `sketch/`)

[docs/MATH.md](docs/MATH.md) has the proofs. In short, for each VIP packet the program updates two sketches.

**Count-Min of packets per source.** It has 5 rows of 4,096 counters.

- **Hashing:** each row uses multiply-add-shift hashing, `(a·src + b) >> 52`, with random 64-bit `a, b`. That hash is provably strongly universal for 32-bit keys.
- **Guarantee:** the estimate never undercounts, and overcounts by more than εN, with ε = e/4096 ≈ 6.6×10⁻⁴, with probability at most δ = e⁻⁵ ≈ 0.0067.
- **Measured:** 40 trials of 10⁶ Zipf-distributed packets (3.06M estimates in all). Every estimate was within εN. The mean overcount was 0.055 εN and the worst 0.52 εN.

**HyperLogLog of distinct sources per VIP.** It has 16,384 one-byte registers and uses the standard estimator with linear counting for small counts.

- **Measured relative error:** 0.68–1.07 × 1.04/√m (0.81%) across 1,000 to 10,000,000 distinct sources.
- **Exception:** between about 2.4m and 3m (40k–50k sources) it shows a known bias of up to +1.75%. HyperLogLog++ fixes that; this project doesn't yet.

**Per CPU, merged exactly.** Both sketches are per CPU, so the packet path has no atomic operations. Userspace merges the CPUs exactly: Count-Min by summing, HyperLogLog by a register-wise max. Each window has two buffers, so the kernel fills one while userspace reads and clears the other.

**Heavy hitters.** Detection has two stages:

1. **Kernel flag:** a CPU flags a source once its own estimate reaches φ of that CPU's packets and ⌈min/C⌉, where C is the number of CPUs.
2. **Userspace confirmation:** at each window's end, a flagged source is kept only if the merged sketch shows it at ≥ φN and ≥ min.

This catches every source with ≥ φN + min packets, which is proved. Each confirmed source's true share is at least φ − ε with probability ≥ 1 − δ, also proved.

With `-drop-heavy` the program drops only **confirmed** sources, so a per-CPU false flag never drops traffic. The cost of that safety is that mitigation starts up to one window late.

**Cost:** the sketches add about 7 ns per packet in `BPF_PROG_TEST_RUN` (57 → 64 ns, one repeated packet, so counters stay in cache). They use 832 KiB per CPU.

## What was run and what wasn't

Run, all passing:

- **On macOS (Go 1.26.3):** `go test -race ./...`. This covers the Maglev table, the CLI, the flow hash, and the Go sketches with their empirical checks. The kernel tests skip here. `SKETCH_FULL=1 go test -v -run Empirical ./sketch` produces the full-size sketch tables quoted in [docs/MATH.md](docs/MATH.md).
- **In Docker Desktop's Linux VM** (kernel 6.12.65-linuxkit, arm64, privileged container): `make docker-test`, every test under `-race`. That includes the XDP program running inside the kernel on hand-built packets (`BPF_PROG_TEST_RUN`), which checks:
  - pass-through for non-VIP, ARP, IPv6, ICMP, IP options, fragments and truncated packets;
  - exact output bytes in both forwarding modes, including the outer IPv4 checksum;
  - 5,000 random flows choosing the backend Go predicts;
  - connection tracking: when a 6th backend is added, the table alone would move 511 of 3,000 established flows, and with connection tracking 0 moved;
  - dropping traffic for a VIP with no backends, deleting a VIP, and keeping separate VIP tables apart;
  - the sketches, bit for bit: after 30,000 packets to two VIPs, all 20,480 merged Count-Min counters and both VIPs' 16,384 HyperLogLog registers equal the Go reference;
  - a 200,000-packet mixed flood across 14 CPUs: the kernel flagged 20 sources (precision 0.65, recall 1.0), and confirmation kept 13 (**precision 1.0, recall 1.0**). Every reported `[â − εN, â]` contained the true count;
  - drop mode: nothing is dropped before confirmation; after it, 200/200 flood packets are dropped and 100/100 normal ones forwarded. The source is unblocked one quiet window later;
  - per-packet cost: 57 ns with sketches off, 64 ns on, 65 ns on with the drop check.
- **`make e2e` in the same VM.** The client, load balancer and three backends each sit in their own network namespace on a Linux bridge, with `maglev-xdp` attached to the load balancer's veth in **generic** XDP mode. The client sends 300 UDP flows, then the backends file gets a fourth backend and the daemon gets a SIGHUP. Then it re-sends the 300 flows, followed by 300 new ones. Results, for both L2 and IP-in-IP:
  - all 900 datagrams arrived in a backend's socket, each on the backend Go predicted;
  - the XDP counters read `tx=900`;
  - the new table alone would have moved 65 of the 300 established flows, and none moved;
  - be4 got 73 of the 300 new flows;
  - in IP-in-IP mode, the backends' tunnel devices decapsulated all 900 packets.

  Then a flood: 30 normal sources (20 datagrams each) and one flooder (3,000 datagrams at 1,000/s) send at once, with heavy = ≥10% and ≥300 packets per 1 s window. Results, in both modes:
  - the daemon reported the flooder as heavy every window, with the exact count, and never reported a normal source;
  - the distinct-source estimate was ≈31, the true number;
  - all 600 normal datagrams arrived;
  - restarted with `-drop-heavy`, the flood was cut to between 925 and 1,949 of 3,000 delivered over four runs, the rest dropped in XDP, while all 600 normal datagrams still arrived. The spread comes from how the flood lines up with the 1 s windows: a flood that starts late in a window stays under the floor there, so confirmation waits for the next full window.
- **GitHub Actions** (`ubuntu-latest`, x86-64), on every push:
  - gofmt, vet and `go test -race` on Go 1.25 and the current release;
  - the XDP program rebuilt with Ubuntu's clang, with a check that the generated Go bindings match the committed ones;
  - the kernel tests and both end-to-end modes as root.

  The first run gave the same results as on arm64: all 5,000 flows matched Go, 0 of 511 established flows moved, and `tx=900` in both modes, with 900 packets decapsulated in IP-in-IP mode.

Not run:

- **Native (driver-mode) XDP and physical NICs.** The end-to-end test uses generic XDP on veth, which runs the same program but in the kernel's slower generic path. Real performance needs real NICs.
- **TCP end to end.** The kernel unit tests cover TCP; the veth test only sends UDP.
- **Any throughput or latency measurement.** That's phase 3. The +7 ns sketch cost is program time with hot caches, not a throughput number.
- **Sketches on real traffic.** The accuracy numbers come from synthetic Zipf traffic and test floods.

## Known limitations

- IPv4 only. IP options and fragments go to the kernel, as does ICMP for a VIP, including "fragmentation needed" messages.
- IP-in-IP adds 20 bytes, so the path from the load balancer to the backends needs an MTU 20 bytes larger than the client side.
- The connection-tracking map is one shared LRU hash. It has no idle timeout and is shared by all CPUs. Katran uses per-CPU maps to avoid contention; phase 3 will show whether this matters.
- Capacity is fixed at compile time: 16 VIPs, 4,096 backends and 65,536 tracked flows.
- If `SetVIP` fails halfway (say, a full map), the maps can be partly updated. Calling it again with the same arguments repairs them.
- Connection tracking is per instance. Several load balancers behind ECMP wouldn't share it; the paper's answer is the consistent hash itself.
- **Count-Min bound:** it holds per query, assuming the traffic doesn't depend on the hash seeds. The seeds are random per load and stay on the host.
- **HyperLogLog bias:** the standard estimator is biased up to +1.75% between about 2.4m and 3m distinct sources (40k–50k); there's no HyperLogLog++ correction.
- **Window switch:** userspace waits a 10 ms grace period before reading the closed buffer. That's a practical bound, not a synchronisation guarantee.
- **Mitigation lag and capacity:** dropping starts up to one window after a flood becomes heavy. The heavy-hitter map holds 1,024 sources.

## Measured disruption

When one of `N` backends fails, an ideal consistent hash moves only that backend's slots, a share of `1/N`. Maglev also moves a few slots between backends that stayed up (*extra*). That is the price of its near-perfect balance.

From `go test -v -run Disruption ./maglev`. Each row fails every backend in turn, or an even sample of 20 when N > 20. *Ratio* is the worst share remapped divided by `1/N`, so 1.00 is ideal.

| M (table size) | N | ideal 1/N | mean remapped | worst remapped | worst ratio | worst extra |
|---:|---:|---:|---:|---:|---:|---:|
| 65,537 | 3 | 33.33% | 33.35% | 33.35% | 1.001 | 0.02% |
| 65,537 | 5 | 20.00% | 20.09% | 20.11% | 1.006 | 0.11% |
| 65,537 | 10 | 10.00% | 10.24% | 10.31% | 1.031 | 0.31% |
| 65,537 | 20 | 5.00% | 5.31% | 5.36% | 1.071 | 0.36% |
| 65,537 | 50 | 2.00% | 2.45% | 2.50% | 1.251 | 0.50% |
| 65,537 | 100 | 1.00% | 1.57% | 1.61% | 1.610 | 0.61% |
| 655,373 | 10 | 10.00% | 10.05% | 10.06% | 1.006 | 0.06% |
| 655,373 | 100 | 1.00% | 1.14% | 1.15% | 1.146 | 0.15% |

With a million random flow hashes, N=10 and one backend failing, 10.19% of flows changed backend, against 10.20% of slots. Naive `hash mod N` selection moved 89.97% of them.

- **"About 1/N of flows remapped" holds for small pools.** With 10 backends, a failure moves 10.2–10.3% of flows instead of 10%.
- **For large pools it holds less tightly.** The extra churn stays under 1% of the table, but `1/N` shrinks as N grows. At N=100 a failure remaps 1.6% of flows instead of 1%, and a 10× larger table (655,373) brings that down to 1.15%. This matches the paper (§5.3).
- **Connection tracking is what protects established flows.** Without it, the extra flows (0.2% at N=10) would switch backend mid-connection. The paper uses connection tracking as "the primary means of protection" for the same reason. In this project, the kernel tests and the end-to-end run both show established flows staying on their backend when the table changes.

## Table build speed

From `go test -run '^$' -bench . ./maglev` on an Apple M4 Pro, Go 1.26:

| M | N | build time |
|---:|---:|---:|
| 65,537 | 10 | 0.98 ms |
| 65,537 | 100 | 1.43 ms |
| 65,537 | 1,000 | 1.60 ms |
| 655,373 | 100 | 16.9 ms |
| 655,373 | 1,000 | 19.6 ms |

A Go-side lookup takes about 1.1 ns. The paper reports 1.8 ms and 22.9 ms to generate the two table sizes on its own hardware, so the numbers aren't directly comparable.

## Layout

```text
maglev/              Maglev table, Pool (add/remove/swap), hashing, disruption tests, benchmarks
bpf/lb.c             the XDP program (forwarding, connection tracking, Count-Min, HyperLogLog)
bpf/include/bpf/     libbpf helper headers (vendored, LGPL-2.1 OR BSD-2-Clause)
dataplane/           Go loader (cilium/ebpf), flow hash, window rotation and merging, kernel tests
sketch/              Go reference Count-Min and HyperLogLog, with empirical checks against the theory
docs/MATH.md         derivations: Maglev table, Count-Min and HyperLogLog bounds, per-CPU merging, cost
  lb_bpfel.go/.o     generated by bpf2go from bpf/lb.c (committed; `make generate` rebuilds)
cmd/maglev-xdp/      the load-balancer daemon (attach, hot reload on SIGHUP, stats, sketch reports)
cmd/maglev-stats/    table statistics CLI
scripts/e2e.sh       namespace/veth/bridge end-to-end test (+ scripts/e2e/udp.go helper)
docker/Dockerfile    Linux build/test image: clang 19 + Go 1.26 + iproute2
.github/workflows/   CI: Go tests on 1.25 and stable; clang build, kernel tests and e2e as root
```

## Roadmap

1. **Control plane and Maglev table (Go).** ✅
2. **XDP data plane (C/eBPF), loader, connection tracking, hot reload.** ✅
   - **Traffic sketches:** in-kernel Count-Min and HyperLogLog, heavy-hitter detection and optional flood dropping, with [docs/MATH.md](docs/MATH.md). ✅
3. **Benchmarks.** Packets per second and latency against IPVS and HAProxy on the same hardware, with pktgen or TRex, on real NICs in native XDP mode. Also measure the sketches' cost with many distinct sources (cache misses). Likely follow-ups depending on results: per-CPU connection tracking, health checks, HyperLogLog++ bias correction.

## License

None chosen yet. The kernel requires a license string in the BPF object, so `bpf/lb.c` declares `Dual MIT/GPL` as a placeholder. Change it when you pick a license. The vendored libbpf headers keep their own license (LGPL-2.1 OR BSD-2-Clause, with `bpf/include/bpf/LICENSE.BSD-2-Clause`).
