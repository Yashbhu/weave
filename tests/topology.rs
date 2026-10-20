//! m5 integration tests: topology exchange, route calculation, failure
//! detection and recovery.
//!
//! two levels of test live here:
//!
//! 1. a deterministic in-memory simulation. four nodes run the real `Router`
//!    core, but messages are shuttled between them directly and time is passed
//!    in, so there is no sleeping and every run is reproducible. it covers
//!    convergence, a link failure, and recovery.
//! 2. a real-socket test. four overlay pipelines run over loopback udp with the
//!    control plane enabled; we forward a packet across two possible paths, kill
//!    the middle node on the active path, and check traffic moves to the other.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

use weave::connectivity::LinkSnapshot;
use weave::control::Message;
use weave::overlay::{self, OverlayConfig};
use weave::peer::PeerSet;
use weave::route::{RouteSnapshot, RoutingTable};
use weave::router::{Neighbor, Router, RouterConfig};
use weave::topology::{LinkAdvert, LinkState, NodeId};
use weave::tun::{PacketReader, PacketWriter};

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn node(s: &str) -> NodeId {
    NodeId(ip(s))
}

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// `(overlay-ip, udp-port, neighbours)` for one simulated node.
type NodeSpec = (&'static str, u16, &'static [(&'static str, u16)]);

fn neighbors(spec: &[(&str, u16)]) -> Vec<Neighbor> {
    spec.iter()
        .map(|(id, port)| Neighbor {
            id: node(id),
            addr: addr(*port),
        })
        .collect()
}

fn build_router(id: &str, port: u16, spec: &[(&str, u16)]) -> Router {
    let neighbors = neighbors(spec);
    let peers = Arc::new(PeerSet::new(neighbors.iter().map(|n| n.addr)));
    let mut config = RouterConfig::new(node(id), addr(port), neighbors);
    config.link_timeout = Duration::from_millis(500);
    Router::new(
        config,
        peers,
        RouteSnapshot::new(RoutingTable::default()),
        LinkSnapshot::new(),
    )
}

// ---------------------------------------------------------------------------
// deterministic simulation
// ---------------------------------------------------------------------------

struct SimNode {
    id: NodeId,
    addr: SocketAddr,
    router: Router,
    active: bool,
}

struct Sim {
    nodes: Vec<SimNode>,
    by_addr: HashMap<SocketAddr, usize>,
    floods: usize,
    // deterministic fault injection: a fixed-seed prng drops a percentage of
    // messages and holds another percentage for `delay`, so loss and reordering
    // are reproducible without any sleeping or real clock.
    seed: u64,
    loss_percent: u32,
    delay: Duration,
    held: Vec<(StdInstant, SocketAddr, SocketAddr, Message)>,
}

impl Sim {
    fn from_nodes(nodes: Vec<SimNode>, by_addr: HashMap<SocketAddr, usize>) -> Self {
        Self {
            nodes,
            by_addr,
            floods: 0,
            seed: 0x9e37_79b9_7f4a_7c15,
            loss_percent: 0,
            delay: Duration::ZERO,
            held: Vec::new(),
        }
    }

    /// the standard four-node two-path topology:
    /// a-b-d and a-c-d, plus the reverse links.
    fn two_paths() -> Self {
        let spec: [NodeSpec; 4] = [
            ("10.0.0.1", 4101, &[("10.0.0.2", 4102), ("10.0.0.3", 4103)]),
            ("10.0.0.2", 4102, &[("10.0.0.1", 4101), ("10.0.0.4", 4104)]),
            ("10.0.0.3", 4103, &[("10.0.0.1", 4101), ("10.0.0.4", 4104)]),
            ("10.0.0.4", 4104, &[("10.0.0.2", 4102), ("10.0.0.3", 4103)]),
        ];
        let mut nodes = Vec::new();
        let mut by_addr = HashMap::new();
        for (id, port, neigh) in spec {
            let router = build_router(id, port, neigh);
            by_addr.insert(addr(port), nodes.len());
            nodes.push(SimNode {
                id: node(id),
                addr: addr(port),
                router,
                active: true,
            });
        }
        Self::from_nodes(nodes, by_addr)
    }

    fn set_impairment(&mut self, loss_percent: u32, delay: Duration) {
        self.loss_percent = loss_percent;
        self.delay = delay;
    }

    fn rng(&mut self) -> u64 {
        self.seed = self
            .seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.seed
    }

    /// rebuild a node's router from scratch, simulating a restart where every
    /// other node still holds the old version's state.
    fn restart(&mut self, id: &str, port: u16, spec: &[(&str, u16)]) {
        let id = node(id);
        for node in &mut self.nodes {
            if node.id == id {
                node.router = build_router(&node.id.0.to_string(), port, spec);
                node.active = true;
            }
        }
    }

    fn set_active(&mut self, id: &str, active: bool) {
        let id = node(id);
        for node in &mut self.nodes {
            if node.id == id {
                node.active = active;
            }
        }
    }

    fn start(&mut self, now: StdInstant) {
        let mut queue = Vec::new();
        for node in self.nodes.iter_mut().filter(|n| n.active) {
            for (to, message) in node.router.start(now) {
                queue.push((node.addr, to, message));
            }
        }
        self.deliver(queue, now);
    }

    /// deliver anything the delay buffer is holding that is now due.
    fn flush_due(&mut self, now: StdInstant) {
        let mut due = Vec::new();
        let mut still_held = Vec::new();
        for (at, from, to, message) in self.held.drain(..) {
            if at <= now {
                due.push((from, to, message));
            } else {
                still_held.push((at, from, to, message));
            }
        }
        self.held = still_held;
        self.process(due, now);
    }

    /// one heartbeat interval across every active node, then flood everything.
    fn round(&mut self, now: StdInstant) {
        self.flush_due(now);
        let mut queue = Vec::new();
        for node in self.nodes.iter_mut().filter(|n| n.active) {
            for (to, message) in node.router.tick(now) {
                queue.push((node.addr, to, message));
            }
        }
        self.deliver(queue, now);
    }

    fn deliver(&mut self, queue: Vec<(SocketAddr, SocketAddr, Message)>, now: StdInstant) {
        let mut process = Vec::new();
        for (from, to, message) in queue {
            if (self.rng() % 100) < u64::from(self.loss_percent) {
                continue;
            }
            if self.delay > Duration::ZERO && (self.rng() % 2) == 0 {
                self.held.push((now + self.delay, from, to, message));
                continue;
            }
            process.push((from, to, message));
        }
        self.process(process, now);
    }

    fn process(&mut self, mut queue: Vec<(SocketAddr, SocketAddr, Message)>, now: StdInstant) {
        // a hard budget turns any accidental flood loop into a test failure
        // instead of a hang.
        let mut budget = 100_000;
        while let Some((from, to, message)) = queue.pop() {
            budget -= 1;
            assert!(budget > 0, "flood did not terminate");
            let Some(&index) = self.by_addr.get(&to) else {
                continue;
            };
            if !self.nodes[index].active {
                continue;
            }
            let out = self.nodes[index].router.handle(from, message, now);
            for (next, message) in out {
                self.floods += 1;
                queue.push((self.nodes[index].addr, next, message));
            }
        }
    }

    fn converge(&mut self, now: StdInstant, rounds: usize) {
        for _ in 0..rounds {
            self.round(now);
        }
    }

    fn route_to(&self, id: &str, dest: &str) -> Option<SocketAddr> {
        let id = node(id);
        let dest = ip(dest);
        self.nodes
            .iter()
            .find(|node| node.id == id)
            .and_then(|node| {
                node.router
                    .routes()
                    .lookup(dest)
                    .map(|route| route.next_hop)
            })
    }
}

#[test]
fn multi_node_topology_converges_then_reroutes_and_recovers() {
    let t0 = StdInstant::now();
    let mut sim = Sim::two_paths();
    sim.start(t0);
    sim.converge(t0, 2);

    // both paths cost 2; the tie breaks on the lower next-hop id, so a goes
    // through b.
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.4"),
        Some(addr(4102)),
        "a should reach d through b"
    );

    // b goes silent; after the link timeout a must drop it and fall back to c.
    sim.set_active("10.0.0.2", false);
    let t1 = t0 + Duration::from_millis(600);
    sim.converge(t1, 2);
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.4"),
        Some(addr(4103)),
        "a should have failed over to c"
    );
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.2"),
        None,
        "the failed neighbour must be unreachable"
    );

    // b comes back; a restores the preferred path.
    sim.set_active("10.0.0.2", true);
    sim.converge(t1 + Duration::from_millis(100), 2);
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.4"),
        Some(addr(4102)),
        "a should recover the path through b"
    );
}

#[test]
fn a_failed_link_with_no_alternate_leaves_the_destination_unreachable() {
    let t0 = StdInstant::now();
    // a line: a - b - d, no alternate path.
    let mut nodes = Vec::new();
    let mut by_addr = HashMap::new();
    let spec: [NodeSpec; 3] = [
        ("10.0.0.1", 4201, &[("10.0.0.2", 4202)]),
        ("10.0.0.2", 4202, &[("10.0.0.1", 4201), ("10.0.0.4", 4204)]),
        ("10.0.0.4", 4204, &[("10.0.0.2", 4202)]),
    ];
    for (id, port, neigh) in spec {
        let router = build_router(id, port, neigh);
        by_addr.insert(addr(port), nodes.len());
        nodes.push(SimNode {
            id: node(id),
            addr: addr(port),
            router,
            active: true,
        });
    }
    let mut sim = Sim::from_nodes(nodes, by_addr);
    sim.start(t0);
    sim.converge(t0, 2);
    assert_eq!(sim.route_to("10.0.0.1", "10.0.0.4"), Some(addr(4202)));

    sim.set_active("10.0.0.2", false);
    sim.converge(t0 + Duration::from_millis(600), 2);
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.4"),
        None,
        "with no alternate path d is unreachable, not silently misrouted"
    );
}

// ---------------------------------------------------------------------------
// fault injection (deterministic)
// ---------------------------------------------------------------------------

#[test]
fn topology_converges_despite_packet_loss_and_reordering() {
    let t0 = StdInstant::now();
    let mut sim = Sim::two_paths();
    sim.set_impairment(30, Duration::from_millis(120));
    sim.start(t0);

    let mut converged = false;
    for i in 0..40u32 {
        sim.round(t0 + Duration::from_millis(u64::from(i) * 100));
        if sim.route_to("10.0.0.1", "10.0.0.4").is_some()
            && sim.route_to("10.0.0.4", "10.0.0.1").is_some()
        {
            converged = true;
            break;
        }
    }
    assert!(
        converged,
        "topology never converged under loss and reordering"
    );
}

#[test]
fn a_restarted_node_reconverges_with_peers_holding_stale_state() {
    let t0 = StdInstant::now();
    let mut sim = Sim::two_paths();
    sim.start(t0);
    sim.converge(t0, 2);
    assert_eq!(sim.route_to("10.0.0.1", "10.0.0.4"), Some(addr(4102)));

    // b is lost and a fails over to c.
    sim.set_active("10.0.0.2", false);
    let t1 = t0 + Duration::from_millis(600);
    sim.converge(t1, 2);
    assert_eq!(sim.route_to("10.0.0.1", "10.0.0.4"), Some(addr(4103)));

    // b returns as a fresh instance while a, c and d still hold its old state.
    sim.restart("10.0.0.2", 4102, &[("10.0.0.1", 4101), ("10.0.0.4", 4104)]);
    sim.converge(t1 + Duration::from_millis(100), 3);
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.4"),
        Some(addr(4102)),
        "the restarted node's state must be accepted by peers holding stale data"
    );
}

#[test]
fn sustained_loss_does_not_falsely_detect_a_failure() {
    let t0 = StdInstant::now();
    let mut sim = Sim::two_paths();
    sim.start(t0);
    sim.converge(t0, 2);
    assert_eq!(sim.route_to("10.0.0.1", "10.0.0.4"), Some(addr(4102)));

    // every node is alive; heartbeats still get through often enough that the
    // preferred path through b must not be torn down.
    sim.set_impairment(20, Duration::ZERO);
    for i in 1..=5u32 {
        sim.round(t0 + Duration::from_millis(u64::from(i) * 100));
    }
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.4"),
        Some(addr(4102)),
        "moderate loss must not be mistaken for a failure"
    );
}

#[test]
fn a_delayed_advert_cannot_resurrect_a_failed_link() {
    let t0 = StdInstant::now();
    let mut sim = Sim::two_paths();
    sim.start(t0);
    sim.converge(t0, 2);

    sim.set_active("10.0.0.2", false);
    let t1 = t0 + Duration::from_millis(600);
    sim.converge(t1, 2);
    assert_eq!(sim.route_to("10.0.0.1", "10.0.0.2"), None);

    // a very old advert from b (sequence 0), claiming b -> a is up, arrives at a
    // after recovery. it must be rejected as stale.
    let stale = LinkAdvert {
        origin: node("10.0.0.2"),
        origin_addr: addr(4102),
        seq: 0,
        from: node("10.0.0.2"),
        to: node("10.0.0.1"),
        metric: 1,
        state: LinkState::Up,
        ttl: 0,
    };
    let out = sim.nodes[0]
        .router
        .handle(addr(4102), Message::LinkAdvert(stale), t1);
    assert!(out.is_empty(), "a stale advert must not be flooded");
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.2"),
        None,
        "a delayed advert must not resurrect a failed link"
    );
}

#[test]
fn recovery_detection_and_convergence_are_measured() {
    let t0 = StdInstant::now();
    let mut sim = Sim::two_paths();
    let link_timeout = Duration::from_millis(500);
    let step = Duration::from_millis(100);
    sim.start(t0);
    sim.converge(t0, 2);
    assert_eq!(sim.route_to("10.0.0.1", "10.0.0.4"), Some(addr(4102)));

    // failure injected at t_fail. time is advanced in heartbeat-sized steps and
    // we record when a's chosen next hop actually changes (detection) and when
    // the new path is usable in both directions (convergence).
    let t_fail = t0 + Duration::from_millis(200);
    sim.set_active("10.0.0.2", false);
    let floods_before = sim.floods;

    let mut detection = None;
    let mut convergence = None;
    for i in 1..=15u32 {
        let now = t_fail + step * i;
        sim.round(now);
        let hop = sim.route_to("10.0.0.1", "10.0.0.4");
        if detection.is_none() && hop == Some(addr(4103)) {
            detection = Some(now - t_fail);
        }
        if hop == Some(addr(4103)) && sim.route_to("10.0.0.4", "10.0.0.1") == Some(addr(4103)) {
            convergence = Some(now - t_fail);
            break;
        }
    }

    let detection = detection.expect("failure was never detected");
    let convergence = convergence.expect("route never converged");
    let floods = sim.floods - floods_before;
    println!(
        "recovery: detection={}ms convergence={}ms floods={floods} (link_timeout={}ms, step={}ms)",
        detection.as_millis(),
        convergence.as_millis(),
        link_timeout.as_millis(),
        step.as_millis(),
    );
    assert!(
        detection <= link_timeout + step,
        "detection ({detection:?}) exceeded link_timeout + step"
    );
    assert!(
        convergence >= detection,
        "convergence reported before detection"
    );
}

#[test]
fn a_temporary_partition_heals_after_it_ends() {
    let t0 = StdInstant::now();
    let mut sim = Sim::two_paths();
    sim.start(t0);
    sim.converge(t0, 2);
    assert_eq!(sim.route_to("10.0.0.1", "10.0.0.4"), Some(addr(4102)));

    // total loss: the fabric is cut for longer than the link timeout, so every
    // route ages out.
    sim.set_impairment(100, Duration::ZERO);
    for i in 1..=8u32 {
        sim.round(t0 + Duration::from_millis(u64::from(i) * 100));
    }
    assert_eq!(
        sim.route_to("10.0.0.1", "10.0.0.4"),
        None,
        "a partitioned link stayed usable"
    );

    // the partition heals; heartbeats get through again and the topology must
    // reconverge on its own.
    sim.set_impairment(0, Duration::ZERO);
    let mut recovered = false;
    for i in 9..=40u32 {
        sim.round(t0 + Duration::from_millis(u64::from(i) * 100));
        if sim.route_to("10.0.0.1", "10.0.0.4").is_some() {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "the topology did not heal after the partition ended"
    );
}

// ---------------------------------------------------------------------------
// real sockets
// ---------------------------------------------------------------------------

const TIMEOUT: Duration = Duration::from_secs(5);

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

struct Node {
    stop: watch::Sender<bool>,
    handle: JoinHandle<io::Result<()>>,
}

impl Node {
    async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = timeout(TIMEOUT, self.handle).await;
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
    neigh: Vec<(NodeId, SocketAddr)>,
) -> (Node, RouteSnapshot) {
    let local_addr = socket.local_addr().unwrap();
    let peers = Arc::new(PeerSet::new(neigh.iter().map(|(_, addr)| *addr)));
    let mut config = RouterConfig::new(NodeId(ip(local)), local_addr, map_neighbors(&neigh));
    config.heartbeat = Duration::from_millis(50);
    config.link_timeout = Duration::from_millis(400);
    let routes = RouteSnapshot::new(RoutingTable::default());
    let overlay_config = OverlayConfig {
        local: vec![ip(local)],
        mtu: 1420,
        queue_depth: 64,
        routes: routes.clone(),
        peers,
        control: Some(config),
        identity: Some(NodeId(ip(local))),
        links: Some(LinkSnapshot::new()),
        serve_relay: false,
    };
    let (stop, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(overlay::run(
        reader,
        writer,
        overlay_config,
        socket,
        stop_rx,
    ));
    (Node { stop, handle }, routes)
}

fn map_neighbors(neigh: &[(NodeId, SocketAddr)]) -> Vec<Neighbor> {
    neigh
        .iter()
        .map(|(id, addr)| Neighbor {
            id: *id,
            addr: *addr,
        })
        .collect()
}

fn ipv4_packet(src: &str, dst: &str, ttl: u8, payload: usize) -> Vec<u8> {
    let total = 20 + payload;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&ip(src).octets());
    packet[16..20].copy_from_slice(&ip(dst).octets());
    packet
}

async fn wait_for_route(routes: &RouteSnapshot, dest: &str, next_hop: SocketAddr) {
    let dest = ip(dest);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if routes
            .current()
            .lookup(dest)
            .is_some_and(|route| route.next_hop == next_hop)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "route to {dest} via {next_hop} never appeared"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn traffic_moves_to_the_alternate_path_when_a_link_fails() {
    let (a_reader, a_writer, a_inject, _a_collect) = tun();
    let (b_reader, b_writer, _b_inject, _b_collect) = tun();
    let (c_reader, c_writer, _c_inject, _c_collect) = tun();
    let (d_reader, d_writer, _d_inject, mut d_collect) = tun();

    let (a_socket, a_udp) = bind().await;
    let (b_socket, b_udp) = bind().await;
    let (c_socket, c_udp) = bind().await;
    let (d_socket, d_udp) = bind().await;

    let (a, a_routes) = spawn_node(
        "10.0.0.1",
        a_reader,
        a_writer,
        a_socket,
        vec![(node("10.0.0.2"), b_udp), (node("10.0.0.3"), c_udp)],
    );
    let (b, _b_routes) = spawn_node(
        "10.0.0.2",
        b_reader,
        b_writer,
        b_socket,
        vec![(node("10.0.0.1"), a_udp), (node("10.0.0.4"), d_udp)],
    );
    let (c, _c_routes) = spawn_node(
        "10.0.0.3",
        c_reader,
        c_writer,
        c_socket,
        vec![(node("10.0.0.1"), a_udp), (node("10.0.0.4"), d_udp)],
    );
    let (d, d_routes) = spawn_node(
        "10.0.0.4",
        d_reader,
        d_writer,
        d_socket,
        vec![(node("10.0.0.2"), b_udp), (node("10.0.0.3"), c_udp)],
    );

    // let the topology converge: a picks b as the next hop to d and d reaches a.
    wait_for_route(&a_routes, "10.0.0.4", b_udp).await;
    wait_for_route(&d_routes, "10.0.0.1", b_udp).await;

    // traffic a -> d works over b.
    let first = ipv4_packet("10.0.0.1", "10.0.0.4", 64, 24);
    a_inject.send(first.clone()).unwrap();
    let got = timeout(TIMEOUT, d_collect.recv())
        .await
        .expect("d timed out on the primary path")
        .expect("d closed");
    assert_eq!(&got[16..20], &first[16..20]);

    // b fails. a must detect it and reroute through c.
    b.shutdown().await;
    wait_for_route(&a_routes, "10.0.0.4", c_udp).await;

    // traffic flows again over the remaining path.
    let second = ipv4_packet("10.0.0.1", "10.0.0.4", 64, 24);
    a_inject.send(second.clone()).unwrap();
    let got = timeout(TIMEOUT, d_collect.recv())
        .await
        .expect("d timed out on the alternate path")
        .expect("d closed");
    assert_eq!(&got[16..20], &second[16..20]);

    a.shutdown().await;
    c.shutdown().await;
    d.shutdown().await;
}
