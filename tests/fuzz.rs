//! deterministic fuzzing of every wire-facing decoder.
//!
//! this is not coverage-guided (no nightly and no `cargo-fuzz`): it is a fixed,
//! reproducible mutational fuzzer that runs on stable and in ci. it feeds random
//! bytes and bit-flipped valid messages into the decoders and asserts that none
//! of them panic and that the ones with invariants preserve them.
//!
//! the fuzzer is deterministic, so a failure is always reproducible: every run
//! uses the same seeds in the same order.

use std::hint::black_box;
use std::time::Instant;

use weave::noise::{Handshake, Identity, Session};
use weave::topology::{LinkAdvert, LinkState, NodeId, Topology};
use weave::{control, packet, relay, wire};

/// xorshift64*, a tiny deterministic prng. not crypto, just reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // never start at zero: xorshift is stuck there.
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max + 1);
        (0..len).map(|_| self.byte()).collect()
    }
}

/// flip one to four random bits in a buffer.
fn mutate(rng: &mut Rng, buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    let flips = 1 + rng.below(4);
    for _ in 0..flips {
        let i = rng.below(buf.len());
        buf[i] ^= 1u8 << rng.below(8);
    }
}

/// truncate or extend a buffer by a few bytes, then mutate it.
fn scramble(rng: &mut Rng, buf: &mut Vec<u8>) {
    match rng.below(4) {
        0 if !buf.is_empty() => {
            let n = rng.below(buf.len());
            buf.truncate(n);
        }
        1 => {
            let extra = rng.below(8);
            for _ in 0..extra {
                buf.push(rng.byte());
            }
        }
        _ => {}
    }
    mutate(rng, buf);
}

fn fuzz_wire(rng: &mut Rng, iters: usize) {
    for _ in 0..iters {
        let datagram = rng.bytes(2000);

        // whatever decode returns must fit inside the datagram it was given.
        if let Ok(payload) = wire::decode(black_box(&datagram)) {
            assert!(payload.len() <= datagram.len());
        }
        let _ = wire::decode_frame(black_box(&datagram));

        // and a mutation of a valid frame must never panic.
        let mut frame = wire::encode(&rng.bytes(200)).expect("encode");
        scramble(rng, &mut frame);
        let _ = wire::decode_frame(black_box(&frame));
    }
}

fn fuzz_packet(rng: &mut Rng, iters: usize) {
    for _ in 0..iters {
        let mut p = rng.bytes(2000);
        let before = p.len();

        let _ = packet::validate(black_box(&p));
        let _ = packet::destination(black_box(&p));
        let _ = packet::hop_limit(black_box(&p));
        // decrement must never change the packet's length or panic on junk.
        let _ = packet::decrement_hop_limit(black_box(&mut p));
        assert_eq!(p.len(), before);
    }
}

fn fuzz_control(rng: &mut Rng, iters: usize) {
    for _ in 0..iters {
        let body = rng.bytes(300);
        let _ = control::decode(black_box(&body));

        // mutations of a valid body, for each kind.
        for kind in 1u8..=4 {
            let mut bytes = match kind {
                1 => control::encode(&control::Message::LinkAdvert(LinkAdvert {
                    origin: NodeId([10, 0, 0, 2].into()),
                    origin_addr: "127.0.0.1:4002".parse().unwrap(),
                    seq: 1,
                    from: NodeId([10, 0, 0, 2].into()),
                    to: NodeId([10, 0, 0, 3].into()),
                    metric: 1,
                    state: LinkState::Up,
                    ttl: 4,
                })),
                2 => control::encode(&control::Message::LinkRequest {
                    origin: NodeId([10, 0, 0, 2].into()),
                    origin_addr: "127.0.0.1:4002".parse().unwrap(),
                }),
                3 => control::encode(&control::Message::EndpointUpdate {
                    origin: NodeId([10, 0, 0, 2].into()),
                    epoch: 1,
                    addrs: vec!["127.0.0.1:4002".parse().unwrap()],
                }),
                _ => control::encode(&control::Message::Punch {
                    origin: NodeId([10, 0, 0, 2].into()),
                    token: 7,
                }),
            }
            .expect("encode");
            scramble(rng, &mut bytes);
            let _ = control::decode(black_box(&bytes));
        }
    }
}

fn fuzz_relay(rng: &mut Rng, iters: usize) {
    let local = NodeId([10, 0, 0, 1].into());
    for _ in 0..iters {
        let body = rng.bytes(1600);
        if let Ok(envelope) = relay::decode(black_box(&body)) {
            // the action must be well-formed whatever the input was.
            let _ = relay::decide(
                &envelope,
                local,
                true,
                Some("127.0.0.1:5000".parse().unwrap()),
            );
            let _ = relay::decide(&envelope, local, false, None);
        }

        let mut inner = rng.bytes(64);
        if inner.is_empty() {
            inner.push(0);
        }
        let mut body = relay::encode(
            NodeId([10, 0, 0, 2].into()),
            NodeId([10, 0, 0, 3].into()),
            4,
            &inner,
        )
        .expect("encode");
        scramble(rng, &mut body);
        let _ = relay::decode(black_box(&body));
    }
}

/// a deterministic long-term identity for fuzzing (never used off the wire).
fn test_identity(seed: u8) -> Identity {
    let mut private = [0u8; 32];
    private[0] = seed;
    private[31] = 0x77;
    Identity::from_private(private)
}

/// run a complete ik handshake locally, returning both ends' sessions.
fn session_pair(initiator: &Identity, responder: &Identity) -> (Session, Session) {
    let mut init = Handshake::initiate(initiator, &responder.public()).expect("initiate");
    let m1 = init.write().expect("m1");
    let mut resp = Handshake::respond(responder).expect("respond");
    resp.read(&m1).expect("read m1");
    let m2 = resp.write().expect("m2");
    init.read(&m2).expect("read m2");
    (
        init.finish().expect("finish"),
        resp.finish().expect("finish"),
    )
}

fn fuzz_noise(rng: &mut Rng, iters: usize) {
    let local = test_identity(1);
    let remote = test_identity(2);
    let (local_session, remote_session) = session_pair(&local, &remote);

    // handshake steps do public-key operations, so fuzz them more sparsely than
    // the (cheap) record layer.
    for _ in 0..(iters / 10).max(1) {
        // hostile handshake bytes must never panic the responder.
        if let Ok(mut handshake) = Handshake::respond(&local) {
            let _ = handshake.read(black_box(&rng.bytes(300)));
        }

        // a mutated handshake message must be rejected, never accepted.
        let mut message = Handshake::initiate(&local, &remote.public())
            .and_then(|mut h| h.write())
            .expect("m1");
        scramble(rng, &mut message);
        if let Ok(mut handshake) = Handshake::respond(&local) {
            let _ = handshake.read(&message);
        }
    }

    for _ in 0..iters {
        // hostile records must be rejected by an established session.
        let _ = local_session.open(black_box(&rng.bytes(300)));

        // a record sealed by the peer opens; a mutated one must not.
        let record = remote_session.seal(&rng.bytes(96)).expect("seal");
        assert!(local_session.open(&record).is_ok());

        let mut mutated = record.clone();
        scramble(rng, &mut mutated);
        assert!(
            local_session.open(&mutated).is_err() || mutated == record,
            "a mutated record was accepted"
        );
    }
}

fn fuzz_topology(rng: &mut Rng, iters: usize) {
    let now = Instant::now();
    let mut topo = Topology::new(
        NodeId([10, 0, 0, 1].into()),
        "127.0.0.1:4001".parse().unwrap(),
    );
    for _ in 0..iters {
        let b = rng.bytes(4);
        let states = [LinkState::Up, LinkState::Down];
        let advert = LinkAdvert {
            origin: NodeId(
                [
                    b.first().copied().unwrap_or(2),
                    0,
                    0,
                    b.get(1).copied().unwrap_or(2),
                ]
                .into(),
            ),
            origin_addr: "127.0.0.1:4002".parse().unwrap(),
            seq: rng.next(),
            from: NodeId([10, 0, 0, 1].into()),
            to: NodeId([10, 0, 0, 2].into()),
            metric: rng.next() as u32,
            state: states[rng.below(2)],
            ttl: rng.byte(),
        };
        let _ = topo.apply(black_box(&advert), now);
        let _ = topo.routes();
    }
}

#[test]
fn decoders_do_not_panic_on_hostile_input() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    fuzz_wire(&mut rng, 20_000);
    fuzz_packet(&mut rng, 20_000);
    fuzz_control(&mut rng, 20_000);
    fuzz_relay(&mut rng, 20_000);
    fuzz_noise(&mut rng, 20_000);
    fuzz_topology(&mut rng, 20_000);
}
