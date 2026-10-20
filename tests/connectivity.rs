//! m6 integration tests over real loopback udp.
//!
//! the deterministic endpoint-migration logic is covered by unit tests in
//! `src/endpoints.rs`, `src/connectivity.rs` and `src/router.rs`. this file
//! exercises the *data plane* end to end: a peer that cannot be reached
//! directly has its traffic carried by a relay, the inner packet is preserved
//! byte for byte, and an unreachable relay does not wedge the node.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

use weave::connectivity::LinkSnapshot;
use weave::overlay::{self, OverlayConfig};
use weave::peer::PeerSet;
use weave::route::{RouteSnapshot, RoutingTable};
use weave::router::{Neighbor, RouterConfig};
use weave::topology::NodeId;
use weave::tun::{PacketReader, PacketWriter};
use weave::{relay, wire};

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn node(s: &str) -> NodeId {
    NodeId(ip(s))
}

// ---------------------------------------------------------------------------
// fake tun
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

struct FakeTun {
    reader: FakeReader,
    writer: FakeWriter,
    inject: mpsc::UnboundedSender<Vec<u8>>,
    collect: mpsc::UnboundedReceiver<Vec<u8>>,
}

// the handles a test needs after the reader/writer have been handed to the
// overlay.
struct TunHandle {
    inject: mpsc::UnboundedSender<Vec<u8>>,
    collect: mpsc::UnboundedReceiver<Vec<u8>>,
}

fn fake_tun() -> FakeTun {
    let (inject, read_rx) = mpsc::unbounded_channel();
    let (write_tx, collect) = mpsc::unbounded_channel();
    FakeTun {
        reader: FakeReader { rx: read_rx },
        writer: FakeWriter { tx: write_tx },
        inject,
        collect,
    }
}

fn ipv4_packet(src: &str, dst: &str, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&ip(src).octets());
    packet[16..20].copy_from_slice(&ip(dst).octets());
    packet[20..].copy_from_slice(payload);
    packet
}

// ---------------------------------------------------------------------------
// node harness
// ---------------------------------------------------------------------------

struct Node {
    stop: watch::Sender<bool>,
    handle: JoinHandle<io::Result<()>>,
}

struct Spawn {
    local: &'static str,
    neighbors: Vec<(NodeId, SocketAddr)>,
    relay: Option<SocketAddr>,
    serve_relay: bool,
    /// extra addresses to accept datagrams from (e.g. a relay that is not a
    /// configured neighbour).
    extra_peers: Vec<SocketAddr>,
    heartbeat_ms: u64,
    link_timeout_ms: u64,
}

fn spawn(spec: Spawn, socket: UdpSocket) -> (Node, TunHandle) {
    let FakeTun {
        reader,
        writer,
        inject,
        collect,
    } = fake_tun();
    let local_addr = socket.local_addr().unwrap();

    let neighbors: Vec<Neighbor> = spec
        .neighbors
        .iter()
        .map(|(id, addr)| Neighbor {
            id: *id,
            addr: *addr,
        })
        .collect();

    let mut peer_addrs: Vec<SocketAddr> = neighbors.iter().map(|n| n.addr).collect();
    peer_addrs.extend(spec.extra_peers.iter().copied());
    if let Some(relay) = spec.relay {
        if !peer_addrs.contains(&relay) {
            peer_addrs.push(relay);
        }
    }

    let mut config = RouterConfig::new(node(spec.local), local_addr, neighbors);
    config.relay = spec.relay;
    config.serve_relay = spec.serve_relay;
    config.heartbeat = Duration::from_millis(spec.heartbeat_ms);
    config.link_timeout = Duration::from_millis(spec.link_timeout_ms);

    let overlay_config = OverlayConfig {
        local: vec![ip(spec.local)],
        mtu: 1420,
        queue_depth: 64,
        routes: RouteSnapshot::new(RoutingTable::default()),
        peers: Arc::new(PeerSet::new(peer_addrs)),
        control: Some(config),
        identity: Some(node(spec.local)),
        links: Some(LinkSnapshot::new()),
        serve_relay: spec.serve_relay,
    };

    let (stop, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(overlay::run(
        reader,
        writer,
        overlay_config,
        socket,
        stop_rx,
    ));
    (Node { stop, handle }, TunHandle { inject, collect })
}

async fn bind_free() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.expect("bind")
}

async fn shutdown(node: Node) {
    node.stop.send(true).unwrap();
    timeout(Duration::from_secs(2), node.handle)
        .await
        .expect("overlay did not stop")
        .expect("join")
        .expect("overlay returned an error");
}

// a socket nobody reads from: datagrams to it are dropped, so a direct path to
// it never gets a reply.
async fn black_hole() -> SocketAddr {
    bind_free().await.local_addr().unwrap()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_carries_traffic_when_the_direct_peer_is_unreachable() {
    // A cannot reach B directly (B's configured endpoint is a black hole), so
    // A sends B's traffic to relay R. R forwards it to B.
    let a_socket = bind_free().await;
    let b_socket = bind_free().await;
    let r_socket = bind_free().await;
    let b_addr = b_socket.local_addr().unwrap();
    let r_addr = r_socket.local_addr().unwrap();
    let dead = black_hole().await;

    // R: a relay that peers with both A and B and forwards for them.
    let a_port = a_socket.local_addr().unwrap();
    let (relay_node, _relay_tun) = spawn(
        Spawn {
            local: "10.0.0.9",
            neighbors: vec![(node("10.0.0.1"), a_port), (node("10.0.0.2"), b_addr)],
            relay: None,
            serve_relay: true,
            extra_peers: vec![],
            heartbeat_ms: 20,
            link_timeout_ms: 5000,
        },
        r_socket,
    );

    // B: peers with the relay only.
    let (b_node, mut b_tun) = spawn(
        Spawn {
            local: "10.0.0.2",
            neighbors: vec![(node("10.0.0.9"), r_addr)],
            relay: None,
            serve_relay: false,
            extra_peers: vec![],
            heartbeat_ms: 20,
            link_timeout_ms: 5000,
        },
        b_socket,
    );

    // A: B is a neighbour at a black-hole address; the relay is configured.
    let (a_node, a_tun) = spawn(
        Spawn {
            local: "10.0.0.1",
            neighbors: vec![(node("10.0.0.2"), dead)],
            relay: Some(r_addr),
            serve_relay: false,
            extra_peers: vec![],
            heartbeat_ms: 20,
            // long enough that A never marks its (silent) neighbour B down.
            link_timeout_ms: 60_000,
        },
        a_socket,
    );

    let packet = ipv4_packet("10.0.0.1", "10.0.0.2", 64, b"through the relay");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = None;
    while Instant::now() < deadline {
        a_tun.inject.send(packet.clone()).unwrap();
        match timeout(Duration::from_millis(100), b_tun.collect.recv()).await {
            Ok(Some(received)) => {
                got = Some(received);
                break;
            }
            _ => continue,
        }
    }

    let received = got.expect("traffic never arrived through the relay");
    assert_eq!(
        received, packet,
        "the inner packet must be preserved byte for byte"
    );
    assert_eq!(
        &received[16..20],
        &ip("10.0.0.2").octets(),
        "inner destination changed"
    );
    assert_eq!(
        &received[12..16],
        &ip("10.0.0.1").octets(),
        "inner source changed"
    );

    shutdown(a_node).await;
    shutdown(b_node).await;
    shutdown(relay_node).await;
}

#[tokio::test]
async fn an_unreachable_relay_does_not_hang_the_node() {
    let a_socket = bind_free().await;
    let relay = black_hole().await;
    let dead = black_hole().await;

    let (a_node, a_tun) = spawn(
        Spawn {
            local: "10.0.0.1",
            neighbors: vec![(node("10.0.0.2"), dead)],
            relay: Some(relay),
            serve_relay: false,
            extra_peers: vec![],
            heartbeat_ms: 20,
            link_timeout_ms: 60_000,
        },
        a_socket,
    );

    // with no direct path and a dead relay there is nowhere to send; the node
    // must keep running and drop the packets rather than block or panic.
    for _ in 0..10 {
        a_tun
            .inject
            .send(ipv4_packet("10.0.0.1", "10.0.0.2", 64, b"lost"))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // it shuts down cleanly and promptly.
    shutdown(a_node).await;
}

#[tokio::test]
async fn a_peer_cannot_relay_on_behalf_of_another_peer() {
    // regression: the relay used to forward any envelope from a *known* peer
    // regardless of the source identity it claimed, so a peer could wrap traffic
    // pretending to come from a different peer. the source must be bound to the
    // endpoint the envelope actually arrived from.
    let r_socket = bind_free().await;
    let r_addr = r_socket.local_addr().unwrap();
    let b_socket = bind_free().await;
    let b_addr = b_socket.local_addr().unwrap();
    let attacker = bind_free().await;
    let attacker_addr = attacker.local_addr().unwrap();

    let (relay_node, _relay_tun) = spawn(
        Spawn {
            local: "10.0.0.9",
            neighbors: vec![(node("10.0.0.2"), b_addr)],
            relay: None,
            serve_relay: true,
            // the attacker's socket is an accepted source, but not the address
            // b is proven to be reachable at.
            extra_peers: vec![attacker_addr],
            heartbeat_ms: 20,
            link_timeout_ms: 60_000,
        },
        r_socket,
    );
    let (b_node, mut b_tun) = spawn(
        Spawn {
            local: "10.0.0.2",
            neighbors: vec![(node("10.0.0.9"), r_addr)],
            relay: None,
            serve_relay: false,
            extra_peers: vec![],
            heartbeat_ms: 20,
            link_timeout_ms: 60_000,
        },
        b_socket,
    );

    // let the relay learn b's endpoint so it has b bound as a direct peer.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let inner = ipv4_packet("10.0.0.2", "10.0.0.2", 64, b"spoofed");
    let body = relay::encode(node("10.0.0.2"), node("10.0.0.2"), 4, &inner).unwrap();
    let frame = wire::encode_relay(&body).unwrap();
    attacker.send_to(&frame, r_addr).await.unwrap();

    assert!(
        timeout(Duration::from_millis(300), b_tun.collect.recv())
            .await
            .is_err(),
        "the relay forwarded an envelope with a spoofed source identity"
    );

    shutdown(b_node).await;
    shutdown(relay_node).await;
}
