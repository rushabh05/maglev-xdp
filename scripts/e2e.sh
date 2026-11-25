#!/usr/bin/env bash
# End-to-end check of the XDP load balancer on real (virtual) interfaces.
#
# Builds this topology with network namespaces, all on one Linux bridge:
#
#   client 10.0.0.2 ─┐
#   lb     10.0.0.1 ─┼─ br0      maglev-xdp attached to lb's interface
#   be1..3 10.0.0.1x ┘           VIP 10.0.0.100:5353/udp on each backend's lo
#
# The client sends UDP datagrams to the VIP. The XDP program on lb forwards
# each one (XDP_TX) to a backend, whose socket receives it. The script checks
# that every datagram reached the backend the Go Maglev table predicts, then
# hot-reloads a fourth backend (SIGHUP) and checks that established flows stay
# put while new flows follow the new table.
#
# Then a flood: 30 normal sources and one flooder send at the same time. With
# the traffic sketches the daemon must report the flooder as a heavy hitter
# and no normal source; restarted with -drop-heavy it must drop the flood once
# confirmed while every normal datagram still reaches a backend.
#
# Usage (as root on Linux, or via `make e2e`): scripts/e2e.sh [l2|ipip]
#
# Limits: veth interfaces only support generic (SKB) XDP for XDP_TX here, so
# this exercises the program's logic, not native-driver performance.
set -euo pipefail

MODE=${1:-l2}
VIP=10.0.0.100
PORT=5353
LB_IP=10.0.0.1
LB_MAC=02:00:00:00:00:01
CLIENT_IP=10.0.0.2
BACKENDS=("be1 10.0.0.11 02:00:00:00:00:11" "be2 10.0.0.12 02:00:00:00:00:12" "be3 10.0.0.13 02:00:00:00:00:13")
NEW_BACKEND="be4 10.0.0.14 02:00:00:00:00:14"
OLD_PORTS=40000-40299
NEW_PORTS=41000-41299

cd "$(dirname "$0")/.."
WORK=$(mktemp -d)
PIDS=()
NETNS=(lb client)

cleanup() {
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
	wait 2>/dev/null || true
	for ns in "${NETNS[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
	ip link del br0 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; [ -f "$WORK/lb.log" ] && sed 's/^/  lb: /' "$WORK/lb.log"; exit 1; }

step "build"
go build -o "$WORK/maglev-xdp" ./cmd/maglev-xdp
go build -o "$WORK/udp" ./scripts/e2e/udp.go

step "topology ($MODE mode)"
ip link add br0 type bridge
ip link set br0 up

# host <netns> <ip> <mac>: a namespace with one veth on br0.
host() {
	local ns=$1 ip=$2 mac=$3
	ip netns add "$ns"
	ip link add "$ns-v" type veth peer name "$ns-br"
	ip link set "$ns-v" netns "$ns"
	ip link set "$ns-br" master br0 up
	ip -n "$ns" link set lo up
	ip -n "$ns" link set "$ns-v" address "$mac"
	ip -n "$ns" addr add "$ip/24" dev "$ns-v"
	ip -n "$ns" link set "$ns-v" up
}

# backend <netns> <ip> <mac>: a host that accepts traffic for the VIP and
# replies to the client directly (direct server return).
backend() {
	local ns=$1
	NETNS+=("$ns")
	host "$@"
	ip -n "$ns" addr add "$VIP/32" dev lo
	# Don't answer ARP for the VIP; only the load balancer should.
	ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2
	if [ "$MODE" = ipip ]; then
		ip -n "$ns" link add ipip0 type ipip external 2>/dev/null ||
			ip -n "$ns" link show tunl0 >/dev/null ||
			fail "no IP-in-IP support in this kernel"
		ip -n "$ns" link set ipip0 up 2>/dev/null || ip -n "$ns" link set tunl0 up
		ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
		for dev in ipip0 tunl0; do
			ip netns exec "$ns" sysctl -qw "net.ipv4.conf.$dev.rp_filter=0" 2>/dev/null || true
		done
	fi
	ip netns exec "$ns" "$WORK/udp" listen -addr "$VIP:$PORT" >>"$WORK/$ns.ports" &
	PIDS+=($!)
}

host lb "$LB_IP" "$LB_MAC"
host client "$CLIENT_IP" 02:00:00:00:00:02
# The client reaches the VIP through the load balancer's MAC.
ip -n client neigh add "$VIP" lladdr "$LB_MAC" dev client-v
for b in "${BACKENDS[@]}"; do
	backend $b
	set -- $b
	echo "$2 $3" >>"$WORK/backends.txt"
done
backend $NEW_BACKEND # up from the start, but not in the pool yet

# Heavy hitter here: at least 10% of a 1 s window's packets and at least 300.
LB_ARGS=(-iface lb-v -vip "$VIP:$PORT/udp" -backends "$WORK/backends.txt" -mode "$MODE" -lb-addr "$LB_IP"
	-xdp-mode generic -stats 200ms -window 1s -hh-phi 0.1 -hh-min 300)

# start_lb [extra flags]: run maglev-xdp in the lb namespace.
start_lb() {
	ip netns exec lb "$WORK/maglev-xdp" "${LB_ARGS[@]}" "$@" >"$WORK/lb.log" 2>&1 &
	LB_PID=$!
	PIDS+=("$LB_PID")
	for _ in $(seq 50); do grep -q balancing "$WORK/lb.log" 2>/dev/null && break; sleep 0.1; done
	grep -q balancing "$WORK/lb.log" || fail "maglev-xdp did not start"
	grep -E 'balancing|sketch: count-min' "$WORK/lb.log" | sed 's/^/  /'
}

step "start maglev-xdp on lb-v"
start_lb

# received: "<port> <backend ip>" for every datagram the backends received
# from the main client, sorted.
received() {
	for b in "${BACKENDS[@]}" "$NEW_BACKEND"; do
		set -- $b
		if [ -s "$WORK/$1.ports" ]; then
			awk -v ip="$CLIENT_IP" -v be="$2" '$1 == ip { print $2, be }' "$WORK/$1.ports"
		fi
	done | sort -n
}

# check <label> <expected file>: compare what arrived with what was expected.
check() {
	local label=$1 expected=$2
	local got="$WORK/got.$label"
	received >"$got"
	local want_n got_n
	want_n=$(wc -l <"$expected")
	got_n=$(wc -l <"$got")
	echo "  $label: $got_n of $want_n datagrams received"
	for b in "${BACKENDS[@]}" "$NEW_BACKEND"; do
		set -- $b
		printf '    %s %s: %s\n' "$1" "$2" "$(grep -c " $2\$" "$got" || true)"
	done
	if ! diff -q "$expected" "$got" >/dev/null; then
		diff "$expected" "$got" | head -20
		fail "$label: datagrams did not reach the predicted backends"
	fi
	echo "  $label: every datagram reached the backend Go predicted"
}

clear_received() { for ns in "${NETNS[@]:2}"; do : >"$WORK/$ns.ports"; done; }

wait_for() { # wait_for <count>: until the backends have received <count> datagrams
	for _ in $(seq 50); do [ "$(received | wc -l)" -ge "$1" ] && return; sleep 0.1; done
}

step "send 300 flows"
"$WORK/udp" predict -vip "$VIP:$PORT" -src "$CLIENT_IP" -ports "$OLD_PORTS" -backends "$WORK/backends.txt" >"$WORK/want.initial"
ip netns exec client "$WORK/udp" send -to "$VIP:$PORT" -ports "$OLD_PORTS"
wait_for 300
check initial "$WORK/want.initial"

step "hot reload: add be4, SIGHUP"
set -- $NEW_BACKEND
echo "$2 $3" >>"$WORK/backends.txt"
kill -HUP "$LB_PID"
for _ in $(seq 50); do grep -q 'reload:' "$WORK/lb.log" && break; sleep 0.1; done
grep 'reload:' "$WORK/lb.log" | sed 's/^/  /' || fail "no reload logged"
clear_received

step "same 300 flows again: connection tracking should keep each on its backend"
ip netns exec client "$WORK/udp" send -to "$VIP:$PORT" -ports "$OLD_PORTS"
wait_for 300
"$WORK/udp" predict -vip "$VIP:$PORT" -src "$CLIENT_IP" -ports "$OLD_PORTS" -backends "$WORK/backends.txt" >"$WORK/want.table"
moved=$(diff <(cut -d' ' -f2 "$WORK/want.initial") <(cut -d' ' -f2 "$WORK/want.table") | grep -c '^>' || true)
echo "  the new table alone would move $moved of 300 of these flows"
check established "$WORK/want.initial"
clear_received

step "300 new flows: should follow the new table, including be4"
"$WORK/udp" predict -vip "$VIP:$PORT" -src "$CLIENT_IP" -ports "$NEW_PORTS" -backends "$WORK/backends.txt" >"$WORK/want.new"
ip netns exec client "$WORK/udp" send -to "$VIP:$PORT" -ports "$NEW_PORTS"
wait_for 300
check new "$WORK/want.new"
grep -q ' 10.0.0.14$' "$WORK/got.new" || fail "no new flow reached be4"

step "the packets really went through XDP"
# The load balancer's namespace has no route or address for the VIP and
# doesn't forward, so without XDP_TX nothing would reach a backend. Check the
# program's own counter anyway.
before=$(grep -c 'rx=' "$WORK/lb.log" || true)
for _ in $(seq 20); do [ "$(grep -c 'rx=' "$WORK/lb.log" || true)" -gt "$before" ] && break; sleep 0.1; done
counters=$(grep 'rx=' "$WORK/lb.log" | tail -1 | sed 's/^.* rx=/rx=/')
echo "  XDP counters: $counters"
tx=$(sed 's/.* tx=\([0-9]*\).*/\1/' <<<"$counters")
[ "$tx" -ge 900 ] || fail "XDP forwarded $tx packets, want at least 900"
if [ "$MODE" = ipip ]; then
	decap=0
	for ns in "${NETNS[@]:2}"; do
		for dev in ipip0 tunl0; do
			n=$(ip netns exec "$ns" cat "/sys/class/net/$dev/statistics/rx_packets" 2>/dev/null || echo 0)
			decap=$((decap + n))
		done
	done
	echo "  packets decapsulated by the backends' IP-in-IP devices: $decap"
	[ "$decap" -ge 900 ] || fail "backends decapsulated $decap packets, want at least 900"
fi

step "flood setup: 30 normal sources, one flooder"
FLOODER=10.0.0.250
NORMAL_IPS=()
for i in $(seq 50 79); do NORMAL_IPS+=("10.0.0.$i"); done
for ip in "${NORMAL_IPS[@]}" "$FLOODER"; do ip -n client addr add "$ip/24" dev client-v; done

# from <ip>: datagrams the backends received from ip.
from() { cat "$WORK"/be*.ports | awk -v ip="$1" '$1 == ip' | wc -l; }

# flood_round: over about 3 s, the flooder sends 3000 datagrams and each
# normal source 20, all at once.
flood_round() {
	clear_received
	local pids=()
	ip netns exec client "$WORK/udp" send -to "$VIP:$PORT" -from "$FLOODER" -ports 20000-22999 -rate 1000 &
	pids+=($!)
	for ip in "${NORMAL_IPS[@]}"; do
		ip netns exec client "$WORK/udp" send -to "$VIP:$PORT" -from "$ip" -ports 50000-50019 -rate 7 &
		pids+=($!)
	done
	wait "${pids[@]}"
	sleep 0.5 # let the last datagrams arrive
}

# heavy_lines: the daemon's per-window sketch reports that list a heavy hitter.
heavy_lines() { grep 'sketch: window' "$WORK/lb.log" | grep -v 'heavy: none' || true; }

check_normal() {
	local got=0
	for ip in "${NORMAL_IPS[@]}"; do got=$((got + $(from "$ip"))); done
	echo "  normal sources: $got of 600 datagrams reached a backend"
	[ "$got" -eq 600 ] || fail "normal traffic lost: $got of 600"
	if heavy_lines | grep -Eq ' 10\.0\.0\.(5[0-9]|6[0-9]|7[0-9]) ≈'; then
		heavy_lines | sed 's/^/  /'
		fail "a normal source was reported as a heavy hitter"
	fi
}

wait_for_flooder_report() {
	for _ in $(seq 30); do heavy_lines | grep -q " $FLOODER ≈" && break; sleep 0.1; done
	heavy_lines | grep " $FLOODER ≈" | tail -2 | sed 's/^.*sketch: /  sketch: /'
	heavy_lines | grep -q " $FLOODER ≈" || fail "flooder never reported as a heavy hitter"
}

step "flood, detection only"
flood_round
echo "  flooder: $(from "$FLOODER") of 3000 datagrams reached a backend"
wait_for_flooder_report
check_normal

step "flood, with -drop-heavy"
kill -TERM "$LB_PID"
wait "$LB_PID" 2>/dev/null || true
start_lb -drop-heavy
flood_round
wait_for_flooder_report
check_normal
got=$(from "$FLOODER")
dropped=$(grep 'rx=' "$WORK/lb.log" | tail -1 | sed 's/.*drop_heavy=\([0-9]*\).*/\1/')
echo "  flooder: $got of 3000 datagrams reached a backend; XDP dropped $dropped (drop_heavy)"
[ "$dropped" -ge 500 ] || fail "only $dropped flood packets dropped"
[ "$got" -le 2500 ] || fail "$got of 3000 flood packets got through"

step "PASS ($MODE mode)"
