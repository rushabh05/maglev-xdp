# The maths behind maglev-xdp

This note derives the guarantees behind the code and sets each one beside what the tests measured.

**What counts as a claim.** Each statement here is one of three kinds:

- **proved here**, with a short proof;
- **cited**: a published result, used as stated, under the assumptions its authors state;
- **measured**: a number from a named test, with the command that reproduces it.

Nothing else is claimed.

Contents:

1. [The Maglev table](#1-the-maglev-table): the build terminates, the balance, and what removing or adding a backend must and does change.
2. [Count-Min](#2-count-min-packets-per-source): the error bound and how the parameters follow from it.
3. [HyperLogLog](#3-hyperloglog-distinct-sources): the estimator, its standard error, and the small-range correction.
4. [Per-CPU sketches merge exactly](#4-per-cpu-sketches-merge-exactly).
5. [Heavy hitters from per-CPU sketches](#5-heavy-hitters-from-per-cpu-sketches): what is and isn't guaranteed.
6. [Memory and cost per packet](#6-memory-and-cost-per-packet).

---

## 1. The Maglev table

The setup follows Eisenbud et al., *Maglev* (NSDI '16), §3.4:

- **Table:** a prime $M$ slots and $N \le M$ backends.
- **Hashes:** backend $i$ has $\mathrm{offset}_i \in [0, M)$ and $\mathrm{skip}_i \in [1, M-1]$, both from hashes of its name.
- **Preference list:** $\mathrm{perm}_i(j) = (\mathrm{offset}_i + j\cdot \mathrm{skip}_i) \bmod M$, for $j = 0, 1, \dots$
- **Build:** backends take turns in a fixed order. In its turn, backend $i$ scans its list from a cursor $\mathrm{next}_i$ and claims the first free slot.

The implementation is `populate` in [`maglev/maglev.go`](../maglev/maglev.go). `TestPaperExample` checks it against the paper's worked example.

### 1.1 Every preference list is a permutation (proved)

Since $M$ is prime and $0 < \mathrm{skip}_i < M$, $\gcd(\mathrm{skip}_i, M) = 1$. Suppose $\mathrm{perm}_i(j) = \mathrm{perm}_i(j')$ with $0 \le j < j' < M$. Then $M \mid (j'-j)\,\mathrm{skip}_i$. Because $M$ is prime and doesn't divide $\mathrm{skip}_i$, it must divide $j' - j$, which is impossible for $0 < j'-j < M$. So $j \mapsto \mathrm{perm}_i(j)$ is a bijection on $[0, M)$: each backend's list visits every slot exactly once.

### 1.2 The build terminates after exactly $M$ turns and $O(NM)$ probes (proved)

**Invariant:** every slot at positions $< \mathrm{next}_i$ in backend $i$'s list is filled. The cursor only advances past a slot that is already filled, or that $i$ fills itself, and filled slots stay filled.

While fewer than $M$ slots are filled, some slot is free. By 1.1 it appears in $i$'s list, and by the invariant it appears at a position $\ge \mathrm{next}_i$. So every turn fills exactly one slot, and every cursor stays $\le M$.

The build therefore stops after exactly $M$ turns. Each probe either fills a slot ($M$ in total) or advances a cursor (at most $M$ per backend), so there are at most $(N+1)M$ probes in total.

The paper's $O(M \log M)$ expected bound assumes random preference lists; that one is **cited, not proved here**. **Measured:** building a table of $M = 65{,}537$ takes 1.0–1.6 ms for $N = 10$–$1000$ (`go test -bench Build ./maglev`, Apple M4 Pro).

### 1.3 Balance: every backend owns $\lfloor M/N \rfloor$ or $\lceil M/N \rceil$ slots (proved)

Turns go round-robin and each fills one slot. Write $M = qN + r$ with $0 \le r < N$. After $q$ full rounds every backend owns $q$ slots, and the remaining $r$ turns give the first $r$ backends one more each. So

```math
\max_i |\text{slots}_i| - \min_i |\text{slots}_i| \le 1,
\qquad
\frac{\max - \min}{\min} \le \frac{1}{\lfloor M/N\rfloor} \approx \frac{N}{M}.
```

With $M > 100N$ the busiest backend gets less than 1% more than the least busy one; this is the paper's rule of thumb. **Measured:** `TestEveryBackendGetsAnEqualShare` checks the bound for $N$ up to 1000.

### 1.4 What removing or adding a backend must change, and what Maglev changes

**Definitions.** For two tables of the same size:

- **changed** slots are those whose owner differs;
- **necessary** changes are slots whose old owner was removed or whose new owner was added;
- **extra** changes are the rest: slots that move between backends present in both tables.

**Lower bound (proved).** Removing backend $k$ must reassign every one of $k$'s slots, because $k$ is absent from the new table. By 1.3 that is at least $\lfloor M/N\rfloor$ slots, a share of about $1/N$, and no assignment of any kind can do better. Adding a backend likewise forces at least $\lfloor M/(N+1) \rfloor$ changes, since the new backend must end up with that many slots.

**Maglev's extra churn (measured, not proved).** Maglev doesn't achieve the lower bound exactly. Removing $k$ changes the order in which survivors meet free slots. Wherever $k$ used to claim a slot first, a survivor now takes it earlier, and that survivor's later choices shift with it. The paper gives no closed-form bound for this cascade, and none is proved here. The measured worst case over failures is shown below; the full table is in the README's [Measured disruption](../README.md#measured-disruption) section (`go test -v -run Disruption ./maglev`).

| $M$ | $N$ | ideal $1/N$ | worst changed | worst extra |
|---:|---:|---:|---:|---:|
| 65,537 | 10 | 10.00% | 10.31% | 0.31% |
| 65,537 | 100 | 1.00% | 1.61% | 0.61% |
| 655,373 | 100 | 1.00% | 1.15% | 0.15% |

The paper reports the same direction: larger tables are more resilient (§5.3).

**Connection tracking (proved by construction, tested).** The data plane consults the connection-tracking map before the table. So a flow keeps its backend across any table change unless that backend is removed. `TestConntrackKeepsFlowsOnTheirBackend` and `scripts/e2e.sh` check this: 0 of 511, and 0 of 65, flows that the table alone would have moved actually moved.

---

## 2. Count-Min: packets per source

The stream is a window's $N$ VIP packets. Each packet has a key $x$, its 32-bit IPv4 source, and $a_x$ is the true number of packets from $x$.

The sketch has $d$ rows of $w = 2^\ell$ counters. Row $i$ hashes with

```math
h_i(x) = \left\lfloor \frac{(a_i x + b_i) \bmod 2^{64}}{2^{64-\ell}} \right\rfloor ,
```

each packet adds 1 to $C[i][h_i(x)]$ in every row, and the estimate is $\hat a_x = \min_i C[i][h_i(x)]$. This is `observe` in [`bpf/lb.c`](../bpf/lb.c) and `CountMin` in [`sketch/countmin.go`](../sketch/countmin.go). The sketch is due to Cormode and Muthukrishnan (2005).

### 2.1 The hash family is strongly universal (cited)

> **Theorem** (Thorup, *High Speed Hashing for Integers and Strings*, 2015, Theorem 3.5; due to Dietzfelbinger 1996). Let keys have $w_k$ bits and outputs $\ell$ bits, and let $\bar w \ge w_k + \ell - 1$. If $a, b$ are independent and uniform on $[0, 2^{\bar w})$, then $h_{a,b}(x) = \lfloor ((ax+b) \bmod 2^{\bar w}) / 2^{\bar w - \ell}\rfloor$ is strongly universal: for $x \ne y$ and any outputs $q, r$, $\Pr[h(x) = q \wedge h(y) = r] = 2^{-2\ell}$.

Here $\bar w = 64$, $w_k = 32$ and $\ell = 12$, and $64 \ge 43$. Summing over $q = r$ gives what the bound below needs:

```math
\Pr[h_i(x) = h_i(y)] = 2^{\ell}\cdot 2^{-2\ell} = \frac{1}{w} \qquad (x \ne y).
```

The loader draws $a_i, b_i$ from `crypto/rand`, independently for each row and freshly at each load. The analysis assumes the traffic doesn't depend on the seeds. The seeds never leave the host, but a sender who learned them could choose colliding addresses; that case isn't covered.

### 2.2 The error bound (proved)

**Theorem.** For every key $x$, $\hat a_x \ge a_x$, and

```math
\Pr\big[\hat a_x > a_x + \varepsilon N\big] \le \delta
\qquad\text{for}\qquad \varepsilon = \frac{e}{w},\quad \delta = e^{-d}.
```

*Proof.*

1. Write $C[i][h_i(x)] = a_x + X_i$, where $X_i = \sum_{y \ne x} a_y\, \mathbf 1[h_i(y) = h_i(x)] \ge 0$. Hence $\hat a_x = a_x + \min_i X_i \ge a_x$.
2. By 2.1, $\mathbb E[X_i] = \sum_{y\ne x} a_y / w = (N - a_x)/w \le N/w$.
3. By Markov's inequality, $\Pr[X_i \ge \varepsilon N] \le \mathbb E[X_i]/(\varepsilon N) \le 1/(\varepsilon w) = 1/e$.
4. The rows use independent $(a_i, b_i)$, so $X_1, \dots, X_d$ are independent, and

```math
\Pr[\min_i X_i > \varepsilon N] = \prod_{i=1}^d \Pr[X_i > \varepsilon N] \le e^{-d} = \delta. \qquad\blacksquare
```

The guarantee holds **per query**. Across $q$ queries the expected number of estimates outside the bound is at most $q\delta$; no simultaneous guarantee is claimed.

### 2.3 Choosing the parameters

The targets are $\varepsilon_0 = 10^{-3}$ and $\delta_0 = 10^{-2}$:

- $w \ge \lceil e/\varepsilon_0\rceil = 2719$. Rounding up to a power of two (the shift needs one) gives $w = 4096$, so $\varepsilon = e/4096 \approx 6.64\times 10^{-4}$.
- $d \ge \lceil \ln(1/\delta_0)\rceil = 5$, so $\delta = e^{-5} \approx 6.74\times 10^{-3}$.

One buffer is $5 \times 4096$ 8-byte counters, 160 KiB per CPU. The values are `CM_DEPTH` and `CM_LOG_WIDTH` in `bpf/lb.c`.

### 2.4 Measured against the bound

From `SKETCH_FULL=1 go test -v -run EmpiricalCountMin ./sketch`: 40 trials per row, each with $N = 10^6$ packets drawn from a Zipf distribution over $10^5$ sources, with fresh seeds per trial. $\varepsilon N = 663.6$.

| traffic | estimates checked | within $\varepsilon N$ | guarantee $1-\delta$ | mean error | max error | rows with error $\ge \varepsilon N$ (bound $1/e$) |
|---|---:|---:|---:|---:|---:|---:|
| Zipf $s=1.1$ | 2,587,757 | **100%** | 99.33% | 36.6 ($0.055\,\varepsilon N$) | 345 ($0.52\,\varepsilon N$) | 3.66% (36.8%) |
| Zipf $s=1.5$ | 468,490 | **100%** | 99.33% | 1.7 ($0.003\,\varepsilon N$) | 63 ($0.09\,\varepsilon N$) | 1.63% (36.8%) |

The bound holds everywhere, with room to spare. The slack sits in step 3: Markov's inequality is distribution-free. On skewed traffic most packets come from a few sources, and a single row's collision mass is usually far below its mean of $N/w$.

---

## 3. HyperLogLog: distinct sources

There are $m = 2^p$ registers ($p = 14$, so $m = 16384$), one set per VIP. A source $x$ is processed as follows:

- **Hash:** $h(x) = \mathrm{fmix64}(x \oplus s)$, the MurmurHash3 64-bit finaliser applied to $x$ XOR a random seed $s$.
- **Register:** the top $p$ bits of $h(x)$ pick register $j$.
- **Value:** $\rho$ is the position of the leftmost 1 bit in the remaining $64-p$ bits, counting from 1. A sentinel bit caps it at $65 - p$.
- **Update:** $M[j] \leftarrow \max(M[j], \rho)$.

This is `observe` in `bpf/lb.c` and `HLL` in [`sketch/hll.go`](../sketch/hll.go).

### 3.1 The estimator and its standard error (cited)

```math
E = \alpha_m\, m^2 \Big(\sum_{j=1}^{m} 2^{-M[j]}\Big)^{-1}, \qquad \alpha_m = \frac{0.7213}{1 + 1.079/m}.
```

The intuition: a register that receives $k$ distinct keys has $\Pr[M \ge r] = 1-(1-2^{-(r-1)})^k$, so $2^{M[j]}$ is of the order of the number of keys that land in register $j$. The harmonic mean over registers, scaled by $m$, estimates $n$, and $\alpha_m$ removes the systematic bias.

> **Theorem** (Flajolet, Fusy, Gandouet and Meunier, 2007, Theorem 1). If $h$ is a truly random function, then as $n \to \infty$, $E$ is asymptotically unbiased with relative standard error $\beta_m/\sqrt m$, where $\beta_m \to \sqrt{3\ln 2 - 1} \approx 1.03896$.

For $m = 16384$ that gives $1.04/\sqrt m \approx 0.81\%$. The proof (poissonisation and Mellin transforms) isn't reproduced here.

Two caveats apply. $\mathrm{fmix64}$ isn't a truly random function, so the theorem's hypothesis is only approximated, and the numbers below are the evidence that the approximation is good. And the result is asymptotic.

### 3.2 Small-range correction: linear counting (proved for the expectation)

For small $n$ many registers are still zero and $E$ is biased upward. The fix is the linear-counting estimator of Whang, Vander-Zanden and Taylor (1990).

**Derivation.** Assume $n$ distinct keys hashed uniformly to $m$ registers, and let $V$ be the number of registers still zero. By linearity of expectation,

```math
\mathbb E[V] = m\Big(1-\frac1m\Big)^{n} = m\, e^{\,n\ln(1-1/m)} \approx m\,e^{-n/m}.
```

Solving $V = m e^{-n/m}$ for $n$ gives the method-of-moments estimate $\hat n = m \ln(m/V)$. Following Flajolet et al., the code uses $\hat n$ when $E \le \tfrac52 m$ and $V > 0$, and $E$ otherwise.

**No large-range correction.** The original paper corrects for hash collisions as $n$ nears $2^{32}$ with 32-bit hashes. Here $x \mapsto \mathrm{fmix64}(x \oplus s)$ is a composition of bijections on 64-bit words, so distinct sources never collide at all.

### 3.3 Measured against $1.04/\sqrt m$

From `SKETCH_FULL=1 go test -v -run EmpiricalHLL ./sketch`, with a fresh seed and distinct keys in every trial. $\sigma = 1.04/\sqrt m = 0.812\%$.

| $n$ | trials | bias | RMSE | RMSE / $\sigma$ | within $\pm 2\sigma$ |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 2000 | 0.00% | 0.56% | 0.68 | 99.8% |
| 10,000 | 1000 | −0.02% | 0.64% | 0.78 | 99.3% |
| 35,000 | 1000 | +0.06% | 0.84% | 1.04 | 94.6% |
| **40,000** | 1000 | **+1.75%** | **2.55%** | **3.14** | 30.0% |
| **45,000** | 1000 | **+1.58%** | **1.71%** | **2.10** | 52.2% |
| 50,000 | 1000 | +0.96% | 1.18% | 1.45 | 84.3% |
| 100,000 | 1000 | 0.00% | 0.75% | 0.92 | 96.3% |
| 1,000,000 | 400 | −0.02% | 0.83% | 1.02 | 95.0% |
| 10,000,000 | 40 | −0.02% | 0.87% | 1.07 | 100.0% |

How the error behaves across $n$:

- **Small $n$:** linear counting does better than $\sigma$.
- **Large $n$:** the error matches $1.04/\sqrt m$ to within sampling noise. A separate run with 1,000 trials at $n = 10^5$ gave 0.92σ, and with 400 trials at $10^6$ gave 1.00σ.
- **Between about $2.4m$ and $3m$ (40k–50k):** the standard estimator is biased by up to +1.75%. Its switch from linear counting at $\tfrac52 m$ lands where the raw estimate still has a bias. This is the known weakness that HyperLogLog++ (Heule, Nunkesser and Hall, 2013) fixes with empirical bias correction. It isn't fixed here; the task called for the standard estimator. The kernel stores registers, not estimates, so a better estimator can replace this one in userspace without touching the data plane.

---

## 4. Per-CPU sketches merge exactly

Each CPU updates its own copy of each sketch, so the packet path needs no atomic operations. The copies come from `BPF_MAP_TYPE_PERCPU_ARRAY`. An XDP program runs to completion on one CPU without being interleaved with another instance of itself there, so the per-CPU increments don't race. Userspace merges the copies at the end of a window.

**Count-Min: sum (proved).** Every CPU uses the same $(a_i, b_i)$, because they are load-time constants shared by all CPUs, and each packet is processed by exactly one CPU. So for every row $i$ and column $j$,

```math
\sum_{c} C_c[i][j] \;=\; \sum_c \#\{\text{packets on } c \text{ with } h_i(x)=j\} \;=\; C[i][j],
```

the counter of a single sketch over the whole window. Likewise $\sum_c N_c = N$. The merged sketch is the sketch of the window, exactly, so §2.2 applies to it with the window's $N$.

**HyperLogLog: register-wise max (proved).** $M_c[j]$ is the maximum $\rho$ over keys seen on CPU $c$ that hash to $j$. Then $\max_c M_c[j]$ is the maximum over all keys in the window that hash to $j$, which is exactly the register of a single sketch of the union. A source seen on several CPUs counts once, because max is idempotent. Summing per-CPU *estimates* would count it several times.

**Tested.** `TestCountMinMergeIsExact` and `TestHLLMergeIsExact` check this in Go. `TestSketchesMatchGoBitForBit` checks it in the kernel. After 30,000 packets, all 20,480 merged Count-Min counters and all 2 × 16,384 merged registers equal a single Go sketch fed the same packets.

**Windows.** Each sketch has two buffers. The low bit of the window number picks the one the kernel writes. At the end of a window, userspace does three things:

1. switches the window number;
2. waits a grace period (10 ms in the daemon) for programs already running on the old buffer;
3. reads the old buffer, then clears it.

The grace period is a practical bound, not a synchronisation guarantee. A program that started before the switch and is still running after 10 ms would leak a few counts into a later window. XDP programs run for well under a microsecond (§6).

---

## 5. Heavy hitters from per-CPU sketches

**Definitions.** There are $C$ CPUs. $a_{x,c}$ and $N_c$ are source $x$'s and all packets on CPU $c$ in a window, so $a_x = \sum_c a_{x,c}$ and $N = \sum_c N_c$. The thresholds are a share $\varphi$ and a floor $m_0$; a source is **heavy** if $a_x \ge \max(\varphi N, m_0)$. Detection has two stages:

- **Kernel flag**, per CPU, on each packet from $x$: flag $x$ if $\hat a_{x,c} \ge \max(\varphi N_c, \lceil m_0/C\rceil)$, using CPU $c$'s own sketch and counts so far.
- **Userspace confirmation**, at the end of each window, on that window's merged sketch. Every flagged $x$ is judged:
  - confirmed if $\hat a_x \ge \max(\varphi N, m_0)$;
  - otherwise kept, but unconfirmed, if the kernel has already flagged it again in the new window;
  - otherwise removed.

### 5.1 Recall: everything clearly heavy is caught (proved)

**Theorem.** If $a_x \ge \varphi N + m_0$, then $x$ is flagged during the window and confirmed at its end.

*Proof.* Suppose $x$ is never flagged. Take a CPU $c$ with $a_{x,c} > 0$, and the moment $t_c$ of $x$'s last packet there. At $t_c$ all of $x$'s packets on $c$ have been counted, and Count-Min never underestimates, so $\hat a_{x,c}(t_c) \ge a_{x,c}$. Since $x$ wasn't flagged,

```math
a_{x,c} \le \hat a_{x,c}(t_c) < \max\big(\varphi N_c(t_c),\, \lceil m_0/C\rceil\big).
```

Both $N_c(t_c) \le N_c$ and the integrality of $a_{x,c}$ (so $a_{x,c} < \lceil m_0/C\rceil$ implies $a_{x,c} < m_0/C$) then give $a_{x,c} < \varphi N_c + m_0/C$. The same inequality holds trivially on CPUs with $a_{x,c} = 0$. Summing over all $C$ CPUs gives $a_x < \varphi N + m_0$, a contradiction. So $x$ is flagged. It is then confirmed, because $\hat a_x \ge a_x \ge \varphi N + m_0 \ge \max(\varphi N, m_0)$. $\blacksquare$

The per-CPU floor is $\lceil m_0/C\rceil$ rather than $m_0$ for exactly this reason. With $m_0$ on every CPU, a source spread over many CPUs never reaches the floor on any one of them. An earlier version did that, and its measured recall at 16 CPUs was 0.69. Sources with $\max(\varphi N, m_0) \le a_x < \varphi N + m_0$ are heavy but not guaranteed to be caught. The tables below report measured recall on them.

**Implementation notes.** Two points about the implementation, both of which the proof relies on:

- *Every candidate is judged, whatever epoch its entry carries.* The kernel re-flags a source in place as soon as it crosses the threshold in a new window. Under a sustained flood that happens within milliseconds of the switch, before userspace reads the entry. An earlier version judged only entries whose epoch matched the closed window, so a continuous flood was never confirmed. The veth end-to-end test caught it, and `TestHeavyConfirmedWhenReflaggedDuringRotation` now reproduces it deterministically.
- *There is one race left.* A flag the kernel sets between userspace reading an entry and deleting it, a window of microseconds, is lost. The kernel sets it again at the source's next packet over the threshold, so this only matters if that was the source's last such packet in the window.

### 5.2 Precision: confirmed sources are nearly heavy (proved)

**Theorem.** For any source $x$, $\Pr[x \text{ confirmed and } a_x < \max(\varphi N, m_0) - \varepsilon N] \le \delta$.

*Proof.* Confirmation means $\hat a_x \ge \max(\varphi N, m_0)$, and by §2.2 (applied to the merged sketch, by §4) $a_x \ge \hat a_x - \varepsilon N$ except with probability $\delta$. $\blacksquare$

With $\varphi = 1\%$ and $\varepsilon = 0.066\%$, a confirmed source has share above $0.93\%$ (per source, with probability $\ge 0.9933$). The daemon reports each one as $[\hat a_x - \lfloor\varepsilon N\rfloor,\ \hat a_x]$, which contains $a_x$ with the same probability.

### 5.3 Dropping

With `-drop-heavy`, the kernel drops packets only from **confirmed** sources. So a source is dropped only if 5.2's guarantee covers it. The kernel's per-CPU flags, which over-flag by design, never cause a drop on their own.

Dropped packets are still counted, so a source that keeps flooding stays confirmed. It is unblocked at the end of the first window in which it is no longer heavy.

If a source sends at least $\varphi N + m_0$ packets in a window, §5.1 says it is confirmed when that window closes, and its packets are dropped from then on. So drops begin within one window length plus the grace period of the start of that window. Until then, its packets are forwarded.

### 5.4 Measured

**Simulation.** From `SKETCH_FULL=1 go test -v -run EmpiricalHeavy ./sketch`:

- **Traffic:** a window of $N = 10^6$ packets. 66% come from 50,000 Zipf($s=1.1$) sources. Ten attackers make up the rest, at shares of 0.3, 0.6, 0.9, 0.95, 1.05, 1.2, 2, 4, 8 and 15%.
- **Thresholds:** $\varphi = 1\%$, $m_0 = 1000$.
- **CPU spread:** packets go to CPUs uniformly at random, the worst case for per-CPU detection.
- **Truth:** 13 heavy sources: the 6 attackers at 1.05% and above, and the 7 largest Zipf sources. 11 of them are in the guaranteed set $a \ge \varphi N + m_0$.

| CPUs | kernel flags: precision / recall | confirmed: precision / recall | recall on the guaranteed set | lowest confirmed share |
|---:|---:|---:|---:|---:|
| 1 | 0.929 / 1.000 | **1.000 / 1.000** | 1.000 | 1.050% |
| 4 | 0.929 / 1.000 | **1.000 / 1.000** | 1.000 | 1.050% |
| 16 | 0.765 / 1.000 | **1.000 / 1.000** | 1.000 | 1.050% |
| 64 | 0.565 / 1.000 | **1.000 / 1.000** | 1.000 | 1.050% |

**Kernel.** `TestHeavyHittersInKernel` ran the real XDP program (`BPF_PROG_TEST_RUN`, 14 CPUs) on $N = 200{,}000$ packets. 66% came from 20,000 Zipf($s=1.1$) sources and the rest from the same ten attackers. It used $m_0 = 200$ (15 per CPU), and $\varepsilon N = 132$:

- the kernel flagged 20–21 sources over several runs, for precision 0.62–0.65 and recall 1.0. Which CPU runs each test packet varies, so the per-CPU flags vary too; the 4-CPU CI runner flagged 17, for precision 0.77;
- confirmation kept 13, for **precision 1.0 and recall 1.0**, in every run;
- every reported interval $[\hat a - \lfloor\varepsilon N\rfloor, \hat a]$ contained the true count.

**Drop mode.** `TestDropHeavy` passed 0 of 200 flood packets in the window before confirmation, then dropped **200 of 200** while forwarding **100 of 100** normal packets. The end-to-end test ran 30 normal sources plus one flooder at 1000 packets/s for 3 s over veth. Across ten runs (both forwarding modes), the backends received **600 of 600** normal datagrams every time. The flooder was confirmed at the end of its first window in every run, and the flood was cut to 931–1,134 of 3,000 delivered, with the rest dropped in XDP. That matches §5.3: what gets through is the flood's first window, before confirmation.

Before the re-flag fix in §5.1, some runs let 1,920–2,936 through, because a continuous flood could stay unconfirmed for several windows.

---

## 6. Memory and cost per packet

**Memory per CPU** (both buffers):

| structure | size |
|---|---:|
| Count-Min: 2 buffers × 5 × 4096 × 8 B | 320 KiB |
| Count-Min totals: 2 × 8 B | 16 B |
| HyperLogLog: 2 buffers × 16 VIPs × 16,384 × 1 B | 512 KiB |
| **total** | **832 KiB** |

The heavy-hitter map is shared across CPUs: 1,024 entries of 16 B.

**Work per VIP packet:**

- **Count-Min:** five rows, each one multiply-add-shift, one map lookup and an increment, plus the running minimum.
- **HyperLogLog:** one $\mathrm{fmix64}$ (two multiplies, three xor-shifts), a count of leading zeros (at most six shift-and-test steps), one lookup and a compare.
- **Fixed:** one lookup of the configuration and one increment of the total.
- **Heavy-hitter map:** a lookup only when a source crosses the per-CPU threshold or when drop mode is on.

There are no atomic operations and no loops beyond the five unrolled rows.

**Measured.** `TestPerPacketCost` repeats one VIP packet $2\times10^6$ times through `BPF_PROG_TEST_RUN` and reports the best of 5 repetitions. It ran three times on two machines; each column is one test run:

| configuration | Docker VM, Apple M4 Pro (arm64), run 1 | same, run 2 | GitHub Actions runner (x86-64) |
|---|---:|---:|---:|
| sketches off | 57 ns | 62 ns | 59 ns |
| sketches on | 64 ns (+7) | 64 ns (+2) | 71 ns (+12) |
| sketches on, drop check on | 65 ns (+8) | 65 ns (+3) | 76 ns (+17) |

So the sketches added **2–12 ns per packet** in these runs, and 3–17 ns with the drop check. On arm64 the run-to-run spread of the baseline is as large as the effect, so read this as "a few to about a dozen nanoseconds", not a precise figure.

This is in-kernel program time with the counters hot in cache, because the same packet repeats. It leaves out driver and NIC costs and the cache misses that many distinct sources would cause. So it bounds what the sketches add in the best case. It is not a throughput figure.

---

## References

- D. E. Eisenbud et al. Maglev: A Fast and Reliable Software Network Load Balancer. NSDI 2016.
- G. Cormode and S. Muthukrishnan. An improved data stream summary: the count-min sketch and its applications. *J. Algorithms* 55(1), 2005.
- M. Thorup. High Speed Hashing for Integers and Strings. arXiv:1504.06804, 2015 (Theorem 3.5).
- M. Dietzfelbinger. Universal hashing and k-wise independent random variables via integer arithmetic without primes. STACS 1996.
- P. Flajolet, É. Fusy, O. Gandouet and F. Meunier. HyperLogLog: the analysis of a near-optimal cardinality estimation algorithm. AofA 2007.
- K.-Y. Whang, B. T. Vander-Zanden and H. M. Taylor. A linear-time probabilistic counting algorithm for database applications. *ACM TODS* 15(2), 1990.
- S. Heule, M. Nunkesser and A. Hall. HyperLogLog in practice: algorithmic engineering of a state of the art cardinality estimation algorithm. EDBT 2013.
