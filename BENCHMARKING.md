# Benchmarking weave

How to measure weave against a baseline on real machines. The goal is
reproducible numbers: same hardware, same duration, same payload sizes, warmup
plus 5–10 runs, median and p95 reported. Never compare against a single run.

Two layers of measurement:

1. **Loopback micro-benchmarks** (`cargo bench --bench baseline`) — pure
   hot paths (wire encode/decode, noise, routing) plus loopback end-to-end
   paths. Fast, deterministic, but not a real network. CI runs these.
2. **Real-network benchmarks** (`weave-netbench` through the TUN overlay) —
   application-level RTT, throughput, and loss across an actual (or emulated)
   link. This document covers that layer.

## Reproducibility checklist

Record these with every result:

- machine: CPU model, cores, RAM; OS and kernel version
- `rustc -V` and the commit SHA of weave under test
- underlay: physical or virtual, interface type, link speed, MTU
- encryption: control-plane only (`--identity` set or not); data plane is
  unencrypted in the current version
- payload sizes and per-run duration
- background load on both machines

Run each size 5–10 times after warmup runs; report median and p95, not the
best run.

## weave-netbench

`weave-netbench` is an application-level echo benchmark. It measures what a
real application would see, not synthetic goodput:

- **RTT**: sequential probes (no pipelining), echo round trip through the
  overlay.
- **Throughput**: pipelined sends with a sliding window, echo goodput in
  packets/s and Mbps.
- **Loss**: application-level — a probe counts as lost if no matching reply
  arrives within `--timeout-ms`, in either direction.

Both processes bind UDP sockets. When run through the overlay, the echo
server binds an overlay address and probes traverse the TUN data plane
end-to-end (root required).

```sh
cargo build --release --bins
```

### Through the overlay (root)

Terminal 1 — echo server, listening on its overlay address (10.77.0.1):

```sh
sudo ./target/release/weave echo \
  --bind 0.0.0.0:4000 \
  --tun --address 10.77.0.1 --peer-address 10.77.0.2 \
  --mtu 1430
```

Terminal 2 — probe, sending into the overlay from 10.77.0.2 (also root, also
needs `--mtu 1430` if using a 1400 B payload — the default overlay MTU of 1420
cannot carry 1400 B of UDP payload plus headers):

```sh
sudo ./target/release/weave echo \
  --bind 0.0.0.0:4001 \
  --tun --address 10.77.0.2 --peer-address 10.77.0.1 \
  --mtu 1430
```

Terminal 3 — probe (no root needed; it sends plain UDP to the local overlay
address, or run it on a third machine to a routed overlay address):

```sh
./target/release/weave-netbench probe \
  --target 10.77.0.1:4000 \
  --sizes 64,512,1200,1400 \
  --runs 5 --warmup 1 \
  --probes 200 --duration-ms 2000 \
  --timeout-ms 200 --label veth-A
```

Options:

```text
--target <ADDR:PORT>   echo server address (overlay or underlay)
--label <NAME>         label for the results table and CSV
--sizes <LIST>         comma-separated UDP payload sizes in bytes
--runs <N>             measured runs per size (after warmup)
--warmup <N>           unrecorded runs per size
--probes <N>           sequential RTT probes per run
--duration-ms <N>      throughput phase duration per run
--window <N>           max in-flight probes during throughput (default 128)
--pps <N>              cap on send rate (default: unbounded)
--timeout-ms <N>       per-probe reply deadline
--bind <ADDR:PORT>     local source address
--csv <PATH>           also write raw per-run rows to a CSV
--verbose              per-run lines in addition to the summary
```

Two-hop and relay scenarios work the same way: point `--target` at the
far-side overlay address and let routing do the rest; use `--label` to keep
results distinguishable (e.g. `direct`, `2-hop`, `relay`).

## Stage A — two machines, direct link

- Two identical (or at least comparable) machines, either on the same LAN or
  with a known-good route between them.
- Baselines, on the same machines, same sizes, same duration, same order:
  - `iperf3 -s` / `iperf3 -c <peer> -l <size> -t 30` for UDP goodput.
  - `ping -i 0.2 -c 500 <peer>` for ICMP RTT distribution.
- Then the weave overlay with `weave-netbench` as above.
- Compare: overlay goodput vs iperf3 goodput (expect overhead from UDP
  encapsulation), overlay RTT vs ping RTT (expect one extra copy + frame
  overhead per direction).

## Stage B — three machines, multi-hop

- Three machines: A—B—C, where A and C are not on the same link.
- Direct: run A↔C through a static route or single-hop neighbour.
- Two-hop: run A↔C through B with `--neighbor` on both segments; compare
  against Stage A numbers to quantify the per-hop cost.
- If two-hop throughput *exceeds* direct throughput on loopback (a known
  artifact of scheduling under a saturated single path in the micro-bench),
  re-run over the real multi-hop topology before drawing conclusions — the
  effect does not reproduce off-loopback in practice.

## Stage C — different networks, NAT, relay

- Machines behind home/office NAT or across the public internet.
- Direct attempt first; if UDP is blocked or NAT breaks the path, verify
  relay fallback (`--relay` on a reachable third host, `--serve-relay` on it).
- Report direct vs relay numbers separately; relay adds at least one extra
  network leg per direction.

## Self-healing under impairment (tc netem)

On Linux, impair the underlay link (not the overlay) and verify behaviour.
`tc` requires root.

```sh
# 1% loss both directions
sudo tc qdisc add dev eth0 root netem loss 1%

# 50 ms added delay
sudo tc qdisc add dev eth0 root netem delay 50ms

# change after the fact (drop the qdisc)
sudo tc qdisc del dev eth0 root
```

Scenarios, each with a long-running `weave-netbench probe` (or continuous
ping through the overlay) observing the effect:

| Scenario | How | What to verify |
| -------- | --- | -------------- |
| 1% loss | `netem loss 1%` | RTT stable; loss stays near 1% at app level; no lifecycle flapping |
| 5% loss | `netem loss 5%` | peers stay connected (lifecycle threshold not tripped); higher loss visible in netbench only |
| 50 ms delay | `netem delay 50ms` | RTT increases by ~2× one-way; failover timers must not fire spuriously |
| 100 ms delay | `netem delay 100ms` | same, with `--link-timeout-ms` raised if needed |
| relay down | kill the relay process | sessions on the direct path unaffected; relay-fallback peers blackhole until direct recovers |
| endpoint change | restart a peer on a new `--bind` port | authenticated endpoint migration; probes resume with a brief RTT spike |
| partition and heal | `tc qdisc add ... netem loss 100%`, then delete | peers go Disconnected, probe with backoff, reconnect and restore routes within the expected window |

For each scenario record: the impairment, the observed RTT/loss before,
during, and after, and the recovery time. Deterministic no-sleep simulations
of failover and partition-heal also live in `tests/topology.rs`.

## Interpreting results

- **RTT** is round-trip and includes echo processing; on loopback the echo
  cost is small but not zero.
- **Throughput** is application payload goodput (echoed bytes), not wire
  rate — encapsulation headers are not counted.
- **Loss** is app-level (both directions); a single lost reply marks the
  whole probe lost.
- Overlay MTU defaults to 1420; payload sizes ≥ ~1200 B need a matching
  `--mtu` on the weave nodes or they will be dropped at the TUN.
