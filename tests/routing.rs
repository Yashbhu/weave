//! integration tests for multi-hop forwarding between real udp sockets.
//!
//! each node runs the real overlay pipeline with a fake tun backed by channels,
//! so a test can inject a packet at one end and collect it at the other.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use weave::overlay::{self, OverlayConfig};
use weave::peer::PeerSet;
use weave::route::{Route, RouteSnapshot, RoutingTable};
use weave::tun::{PacketReader, PacketWriter};

const TIMEOUT: Duration = Duration::from_secs(2);

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

// a fake tun: inject feeds packets into the reader, collect sees what the writer wrote.
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

struct Node {
    stop: watch::Sender<bool>,
    handle: JoinHandle<io::Result<()>>,
}

impl Node {
    async fn shutdown(self) {
        let _ = self.stop.send(true);
        timeout(TIMEOUT, self.handle)
            .await
            .expect("overlay did not stop")
            .expect("join")
            .expect("overlay returned an error");
    }
}

async fn bind() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("local_addr");
    (socket, addr)
}

fn spawn_node(
    local: &str,
    reader: FakeReader,
    writer: FakeWriter,
    socket: UdpSocket,
    routes: Vec<Route>,
    peers: Arc<PeerSet>,
) -> Node {
    let config = OverlayConfig {
        local: vec![local.parse().unwrap()],
        mtu: 1420,
        queue_depth: 64,
        routes: RouteSnapshot::new(RoutingTable::new(routes)),
        peers,
        control: None,
        identity: None,
        links: None,
        serve_relay: false,
    };
    let (stop, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(overlay::run(reader, writer, config, socket, stop_rx));
    Node { stop, handle }
}

fn host(dest: &str, next_hop: SocketAddr) -> Route {
    Route::host(dest.parse().unwrap(), next_hop)
}

fn peers(addrs: impl IntoIterator<Item = SocketAddr>) -> Arc<PeerSet> {
    Arc::new(PeerSet::new(addrs))
}

// a valid ipv4 packet with the given addresses, ttl and payload bytes.
fn ipv4_packet(src: &str, dst: &str, ttl: u8, payload: usize) -> Vec<u8> {
    let total = 20 + payload;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
    packet[16..20].copy_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
    packet
}

#[tokio::test]
async fn three_nodes_carry_traffic_from_a_to_c_through_b() {
    let (a_reader, a_writer, a_inject, _a_collect) = tun();
    let (b_reader, b_writer, _b_inject, mut b_collect) = tun();
    let (c_reader, c_writer, _c_inject, mut c_collect) = tun();

    let (a_socket, a_udp) = bind().await;
    let (b_socket, b_udp) = bind().await;
    let (c_socket, c_udp) = bind().await;

    // a reaches c through b; b reaches c directly; c only accepts from b.
    let a = spawn_node(
        "10.0.0.1",
        a_reader,
        a_writer,
        a_socket,
        vec![host("10.0.0.2", b_udp), host("10.0.0.3", b_udp)],
        peers([b_udp]),
    );
    let b = spawn_node(
        "10.0.0.2",
        b_reader,
        b_writer,
        b_socket,
        vec![host("10.0.0.3", c_udp)],
        peers([a_udp, c_udp]),
    );
    let c = spawn_node(
        "10.0.0.3",
        c_reader,
        c_writer,
        c_socket,
        vec![],
        peers([b_udp]),
    );

    let packet = ipv4_packet("10.0.0.1", "10.0.0.3", 64, 16);
    a_inject.send(packet.clone()).expect("inject");

    let got = timeout(TIMEOUT, c_collect.recv())
        .await
        .expect("c timed out")
        .expect("c closed");

    assert_eq!(&got[12..16], &packet[12..16], "source address preserved");
    assert_eq!(
        &got[16..20],
        &packet[16..20],
        "destination address preserved"
    );
    assert_eq!(got[8], 63, "ttl decremented once by the one transit hop");

    assert!(
        timeout(Duration::from_millis(100), b_collect.recv())
            .await
            .is_err(),
        "b delivered a transit packet locally"
    );

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
}

#[tokio::test]
async fn packets_without_a_route_are_dropped() {
    let (reader, writer, inject, mut collect) = tun();
    let (socket, _udp) = bind().await;

    let node = spawn_node("10.0.0.1", reader, writer, socket, vec![], peers([]));

    inject
        .send(ipv4_packet("10.0.0.1", "10.0.0.9", 64, 8))
        .expect("inject");

    assert!(
        timeout(Duration::from_millis(200), collect.recv())
            .await
            .is_err(),
        "a packet with no route was delivered"
    );

    node.shutdown().await;
}

#[tokio::test]
async fn an_unavailable_next_hop_drops_the_packet() {
    let (reader, writer, inject, mut collect) = tun();
    let (socket, _udp) = bind().await;
    let (_, b_udp) = bind().await;

    let peer_set = PeerSet::new([b_udp]);
    peer_set.set_available(b_udp, false);

    let node = spawn_node(
        "10.0.0.1",
        reader,
        writer,
        socket,
        vec![host("10.0.0.3", b_udp)],
        Arc::new(peer_set),
    );

    inject
        .send(ipv4_packet("10.0.0.1", "10.0.0.3", 64, 8))
        .expect("inject");

    assert!(
        timeout(Duration::from_millis(200), collect.recv())
            .await
            .is_err(),
        "a packet was sent to an unavailable next hop"
    );

    node.shutdown().await;
}

#[tokio::test]
async fn cyclic_routes_do_not_forward_indefinitely() {
    let (a_reader, a_writer, a_inject, mut a_collect) = tun();
    let (b_reader, b_writer, _b_inject, mut b_collect) = tun();

    let (a_socket, a_udp) = bind().await;
    let (b_socket, b_udp) = bind().await;

    // both a and b route x through the other, so any packet for x ping-pongs.
    let a = spawn_node(
        "10.0.0.1",
        a_reader,
        a_writer,
        a_socket,
        vec![host("10.9.9.9", b_udp)],
        peers([b_udp]),
    );
    let b = spawn_node(
        "10.0.0.2",
        b_reader,
        b_writer,
        b_socket,
        vec![host("10.9.9.9", a_udp)],
        peers([a_udp]),
    );

    a_inject
        .send(ipv4_packet("10.0.0.1", "10.9.9.9", 64, 8))
        .expect("inject");

    // a sends it to b, b would send it straight back to a, so b drops it.
    assert!(
        timeout(Duration::from_millis(300), b_collect.recv())
            .await
            .is_err(),
        "b delivered a packet it should have dropped"
    );
    assert!(
        timeout(Duration::from_millis(100), a_collect.recv())
            .await
            .is_err(),
        "the packet looped back to a"
    );

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn repeated_startup_and_shutdown_is_clean() {
    // lifecycle: the overlay spawns several tasks; starting and stopping it many
    // times must not leak tasks, hang, or return an error.
    for _ in 0..10 {
        let (reader, writer, inject, _collect) = tun();
        let (socket, _udp) = bind().await;
        let (_, dead) = bind().await;
        let node = spawn_node(
            "10.0.0.1",
            reader,
            writer,
            socket,
            vec![host("10.0.0.2", dead)],
            peers([dead]),
        );
        // leave a packet in flight while shutting down.
        inject
            .send(ipv4_packet("10.0.0.1", "10.0.0.2", 64, 8))
            .expect("inject");
        node.shutdown().await;
    }
}

#[tokio::test]
async fn sustained_overload_on_a_bounded_queue_does_not_wedge() {
    // resource: far more packets than the bounded queues hold must be dropped or
    // backpressured, never buffered without limit, and the node must still stop
    // promptly and cleanly.
    let (reader, writer, inject, _collect) = tun();
    let (socket, _udp) = bind().await;
    let (_, dead) = bind().await;
    let node = spawn_node(
        "10.0.0.1",
        reader,
        writer,
        socket,
        vec![host("10.0.0.2", dead)],
        peers([dead]),
    );

    for _ in 0..1000 {
        inject
            .send(ipv4_packet("10.0.0.1", "10.0.0.2", 64, 8))
            .expect("inject");
    }

    node.shutdown().await;
}
