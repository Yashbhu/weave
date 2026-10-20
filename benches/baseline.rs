//! reproducible micro- and end-to-end benchmarks for weave.
//!
//! run with `cargo bench --bench baseline`. this uses the built-in test harness
//! (no external benchmarking crate) so the numbers are easy to reproduce. each
//! benchmark prints its own result line; there are no assertions to make it
//! flaky under load.
//!
//! what is measured:
//!   - wire encode/decode over several payload sizes
//!   - ip packet validation and hop-limit decrement
//!   - routing-table lookup
//!   - control-message authentication (noise record seal/open)
//!   - dijkstra route calculation over a 128-node chain
//!   - end-to-end overlay forwarding over loopback udp: one-way latency
//!     distribution (median/p95) and throughput, for several packet sizes
//!
//! the end-to-end numbers are loopback on one machine. they show the cost of the
//! pipeline, not a real network, and are not comparable to another overlay
//! without matching hardware, mtu and topology.

use std::future::Future;
use std::hint::black_box;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use weave::noise::{Handshake, Identity, Session};
use weave::overlay::{self, OverlayConfig};
use weave::peer::PeerSet;
use weave::route::{Route, RouteSnapshot, RoutingTable};
use weave::topology::{LinkAdvert, LinkState, NodeId, Topology};
use weave::tun::{PacketReader, PacketWriter};
use weave::{packet, wire};

// ---------------------------------------------------------------------------
// pure micro-benchmarks
// ---------------------------------------------------------------------------

fn time_iters<F: FnMut()>(name: &str, iters: u32, mut f: F) {
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let per_op = elapsed.as_nanos() as f64 / f64::from(iters);
    println!("{name:<44} {per_op:>9.1} ns/op");
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn ipv4(len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p
}

fn bench_wire() {
    for size in [64usize, 512, 1400] {
        let body = payload(size);
        let frame = wire::encode(&body).expect("encode");
        time_iters(&format!("wire::encode/decode {size}B"), 200_000, || {
            let f = wire::encode(black_box(&body)).unwrap();
            black_box(wire::decode(black_box(&f)).unwrap());
        });
        time_iters(&format!("wire::decode {size}B"), 200_000, || {
            black_box(wire::decode(black_box(&frame)).unwrap());
        });
    }
}

fn bench_packet() {
    for size in [64usize, 512, 1400] {
        let p = ipv4(size);
        time_iters(&format!("packet::validate {size}B"), 500_000, || {
            black_box(packet::validate(black_box(&p)).is_ok());
        });
        time_iters(
            &format!("packet::decrement_hop_limit {size}B"),
            500_000,
            || {
                let mut copy = p.clone();
                black_box(packet::decrement_hop_limit(black_box(&mut copy)));
            },
        );
    }
}

fn bench_route_lookup() {
    let routes: Vec<Route> = (0..1000u32)
        .map(|i| {
            let addr = Ipv4Addr::from(0x0A00_0000 | i);
            Route::host(addr, "127.0.0.1:4000".parse().unwrap())
        })
        .collect();
    let table = RoutingTable::new(routes);
    let target = Ipv4Addr::from(0x0A00_0000 | 777);
    time_iters("route::lookup (1000 host routes)", 500_000, || {
        black_box(table.lookup(black_box(target)).unwrap());
    });
}

fn bench_noise() {
    let (initiator, responder) = session_pair();
    let body = payload(96);
    let sealed = initiator.seal(&body).unwrap();
    time_iters("noise::seal (96B control body)", 200_000, || {
        black_box(initiator.seal(black_box(&body)).unwrap());
    });
    time_iters("noise::open (96B control body)", 200_000, || {
        black_box(responder.open(black_box(&sealed)).unwrap());
    });
}

/// a deterministic identity for benchmarking (never used off the wire).
fn bench_identity(seed: u8) -> Identity {
    let mut private = [0u8; 32];
    private[0] = seed;
    private[31] = 0x77;
    Identity::from_private(private)
}

/// run a complete ik handshake locally and return both ends' sessions.
fn session_pair() -> (Session, Session) {
    let initiator = bench_identity(1);
    let responder = bench_identity(2);
    let mut init = Handshake::initiate(&initiator, &responder.public()).expect("initiate");
    let m1 = init.write().expect("m1");
    let mut resp = Handshake::respond(&responder).expect("respond");
    resp.read(&m1).expect("read m1");
    let m2 = resp.write().expect("m2");
    init.read(&m2).expect("read m2");
    (
        init.finish().expect("finish"),
        resp.finish().expect("finish"),
    )
}

fn bench_topology() {
    // a 128-node chain: 10.0.0.1 - 10.0.0.2 - ... - 10.0.0.128.
    let local = NodeId("10.0.0.1".parse().unwrap());
    let mut topo = Topology::new(local, "127.0.0.1:4101".parse().unwrap());
    topo.add_neighbor(
        NodeId("10.0.0.2".parse().unwrap()),
        "127.0.0.1:4102".parse().unwrap(),
        1,
    );
    for i in 2..128u8 {
        let from = NodeId(Ipv4Addr::new(10, 0, 0, i));
        let to = NodeId(Ipv4Addr::new(10, 0, 0, i + 1));
        let advert = LinkAdvert {
            origin: from,
            origin_addr: SocketAddr::from(([127, 0, 0, 1], 4100 + u16::from(i))),
            seq: 1,
            from,
            to,
            metric: 1,
            state: LinkState::Up,
            ttl: 8,
        };
        topo.apply(&advert, Instant::now());
    }
    time_iters("topology::routes (128-node chain)", 5_000, || {
        black_box(topo.routes());
    });
}

// ---------------------------------------------------------------------------
// end-to-end overlay benchmark over loopback udp
// ---------------------------------------------------------------------------

struct FakeReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

#[allow(clippy::manual_async_fn)]
impl PacketReader for FakeReader {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move {
            match self.rx.recv().await {
                Some(packet) => {
                    let len = packet.len().min(buf.len());
                    buf[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                }
                None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tun closed")),
            }
        }
    }
}

struct FakeWriter {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

#[allow(clippy::manual_async_fn)]
impl PacketWriter for FakeWriter {
    fn send<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> impl Future<Output = io::Result<()>> + Send + 'a {
        async move {
            self.tx
                .send(packet.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tun closed"))
        }
    }
}

fn tun() -> (
    FakeReader,
    FakeWriter,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (inject, rx) = mpsc::unbounded_channel();
    let (tx, collect) = mpsc::unbounded_channel();
    (FakeReader { rx }, FakeWriter { tx }, inject, collect)
}

fn overlay_config(local: &str, route: Route, peer: SocketAddr) -> OverlayConfig {
    OverlayConfig {
        local: vec![local.parse().unwrap()],
        mtu: 1420,
        queue_depth: 1024,
        routes: RouteSnapshot::new(RoutingTable::new(vec![route])),
        peers: Arc::new(PeerSet::new([peer])),
        control: None,
        identity: None,
        links: None,
        serve_relay: false,
    }
}

fn packet_of(total: usize) -> Vec<u8> {
    packet_between([10, 0, 0, 1], [10, 0, 0, 2], total)
}

fn packet_between(src: [u8; 4], dst: [u8; 4], total: usize) -> Vec<u8> {
    let payload = total.saturating_sub(20);
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    for (i, byte) in p[20..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    debug_assert_eq!(p.len(), 20 + payload);
    p
}

async fn bind() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

/// send `n` packets and count how many arrive, giving up after `idle` of
/// silence. forwarding uses bounded queues that may drop under load, so fewer
/// than `n` can arrive; the rate is computed over what actually did.
async fn flood(
    inject: &mpsc::UnboundedSender<Vec<u8>>,
    collect: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    pkt: &[u8],
    n: usize,
    idle: Duration,
) -> (usize, Duration) {
    let start = Instant::now();
    for _ in 0..n {
        inject.send(pkt.to_vec()).unwrap();
    }
    let mut got = 0usize;
    while got < n {
        match tokio::time::timeout(idle, collect.recv()).await {
            Ok(Some(_)) => got += 1,
            _ => break,
        }
    }
    (got, start.elapsed())
}

/// one-way latency samples: send one, wait for it, time it.
async fn latency_samples(
    inject: &mpsc::UnboundedSender<Vec<u8>>,
    collect: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    pkt: &[u8],
    iters: usize,
) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        inject.send(pkt.to_vec()).unwrap();
        match tokio::time::timeout(Duration::from_secs(1), collect.recv()).await {
            Ok(Some(_)) => samples.push(start.elapsed()),
            _ => break,
        }
    }
    samples.sort_unstable();
    samples
}

async fn bench_overlay(total: usize, latency_iters: usize, throughput_packets: usize) {
    let (a_reader, a_writer, a_inject, _a_collect) = tun();
    let (b_reader, b_writer, _b_inject, mut b_collect) = tun();
    let (a_socket, a_addr) = bind().await;
    let (b_socket, b_addr) = bind().await;

    let a_config = overlay_config(
        "10.0.0.1",
        Route::host("10.0.0.2".parse().unwrap(), b_addr),
        b_addr,
    );
    let b_config = overlay_config(
        "10.0.0.2",
        Route::host("10.0.0.1".parse().unwrap(), a_addr),
        a_addr,
    );
    let (a_stop, a_stop_rx) = watch::channel(false);
    let (b_stop, b_stop_rx) = watch::channel(false);
    let a_task = tokio::spawn(overlay::run(
        a_reader, a_writer, a_config, a_socket, a_stop_rx,
    ));
    let b_task = tokio::spawn(overlay::run(
        b_reader, b_writer, b_config, b_socket, b_stop_rx,
    ));

    let pkt = packet_of(total);

    let _ = flood(
        &a_inject,
        &mut b_collect,
        &pkt,
        200,
        Duration::from_millis(500),
    )
    .await;

    let samples = latency_samples(&a_inject, &mut b_collect, &pkt, latency_iters).await;
    let median = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95) / 100];

    // throughput: flood, then clock how long the far end takes to drain.
    let (got, elapsed) = flood(
        &a_inject,
        &mut b_collect,
        &pkt,
        throughput_packets,
        Duration::from_millis(500),
    )
    .await;
    let pps = got as f64 / elapsed.as_secs_f64();
    let mbps = pps * total as f64 * 8.0 / 1_000_000.0;

    println!(
        "overlay direct {total:>4}B  latency median {:>6.1} us  p95 {:>6.1} us   throughput {pps:>10.0} pkt/s  {mbps:>8.1} Mbps",
        median.as_secs_f64() * 1e6,
        p95.as_secs_f64() * 1e6,
    );

    let _ = a_stop.send(true);
    let _ = b_stop.send(true);
    let _ = a_task.await;
    let _ = b_task.await;
}

fn overlay_config_n(local: &str, routes: Vec<Route>, peers: Vec<SocketAddr>) -> OverlayConfig {
    OverlayConfig {
        local: vec![local.parse().unwrap()],
        mtu: 1420,
        queue_depth: 1024,
        routes: RouteSnapshot::new(RoutingTable::new(routes)),
        peers: Arc::new(PeerSet::new(peers)),
        control: None,
        identity: None,
        links: None,
        serve_relay: false,
    }
}

/// a two-hop path: a -> b -> c, where b forwards on behalf of a. measures the
/// extra cost of one forwarding hop over the direct path.
async fn bench_overlay_via(total: usize, latency_iters: usize, throughput_packets: usize) {
    let (a_reader, a_writer, a_inject, _a_collect) = tun();
    let (b_reader, b_writer, _b_inject, _b_collect) = tun();
    let (c_reader, c_writer, _c_inject, mut c_collect) = tun();
    let (a_socket, a_addr) = bind().await;
    let (b_socket, b_addr) = bind().await;
    let (c_socket, c_addr) = bind().await;

    let a_config = overlay_config_n(
        "10.0.0.1",
        vec![Route::host("10.0.0.3".parse().unwrap(), b_addr)],
        vec![b_addr],
    );
    // b reaches c directly, and forwards a's traffic toward it.
    let b_config = overlay_config_n(
        "10.0.0.2",
        vec![Route::host("10.0.0.3".parse().unwrap(), c_addr)],
        vec![a_addr, c_addr],
    );
    let c_config = overlay_config_n(
        "10.0.0.3",
        vec![Route::host("10.0.0.1".parse().unwrap(), b_addr)],
        vec![b_addr],
    );
    let (a_stop, a_stop_rx) = watch::channel(false);
    let (b_stop, b_stop_rx) = watch::channel(false);
    let (c_stop, c_stop_rx) = watch::channel(false);
    let a_task = tokio::spawn(overlay::run(
        a_reader, a_writer, a_config, a_socket, a_stop_rx,
    ));
    let b_task = tokio::spawn(overlay::run(
        b_reader, b_writer, b_config, b_socket, b_stop_rx,
    ));
    let c_task = tokio::spawn(overlay::run(
        c_reader, c_writer, c_config, c_socket, c_stop_rx,
    ));

    let pkt = packet_between([10, 0, 0, 1], [10, 0, 0, 3], total);

    let _ = flood(
        &a_inject,
        &mut c_collect,
        &pkt,
        200,
        Duration::from_millis(500),
    )
    .await;

    let samples = latency_samples(&a_inject, &mut c_collect, &pkt, latency_iters).await;
    let median = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95) / 100];

    let (got, elapsed) = flood(
        &a_inject,
        &mut c_collect,
        &pkt,
        throughput_packets,
        Duration::from_millis(500),
    )
    .await;
    let pps = got as f64 / elapsed.as_secs_f64();
    let mbps = pps * total as f64 * 8.0 / 1_000_000.0;

    println!(
        "overlay 2-hop  {total:>4}B  latency median {:>6.1} us  p95 {:>6.1} us   throughput {pps:>10.0} pkt/s  {mbps:>8.1} Mbps",
        median.as_secs_f64() * 1e6,
        p95.as_secs_f64() * 1e6,
    );

    let _ = a_stop.send(true);
    let _ = b_stop.send(true);
    let _ = c_stop.send(true);
    let _ = a_task.await;
    let _ = b_task.await;
    let _ = c_task.await;
}

#[tokio::main]
async fn main() {
    println!("weave baseline benchmarks");
    println!(
        "note: results depend on hardware, OS, compiler and load; loopback end-to-end numbers are not a real network.\n"
    );

    bench_wire();
    bench_packet();
    bench_route_lookup();
    bench_noise();
    bench_topology();

    println!();
    for total in [64usize, 512, 1400] {
        bench_overlay(total, 2_000, 50_000).await;
    }

    println!();
    for total in [64usize, 512, 1400] {
        bench_overlay_via(total, 2_000, 50_000).await;
    }
}
