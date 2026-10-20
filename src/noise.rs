//! m7: per-peer authenticated, forward-secret control channel (Noise IK).
//!
//! earlier milestones authenticated control messages with one group-shared
//! hmac key. that proved *someone* knew the key, but not *who*: any member could
//! forge another member's messages, and the bodies were plaintext.
//!
//! this module replaces that with the Noise Protocol Framework's `IK` pattern
//! (`Noise_IK_25519_ChaChaPoly_BLAKE2s`, via the `snow` crate). every node has a
//! long-term x25519 static key; each node is configured with its peers' static
//! public keys. a handshake authenticates both static keys and mixes in fresh
//! ephemeral keys, giving:
//!
//! - **per-peer identity**: a session only exists with a peer whose static key
//!   we configured (and whose static key the peer proved it holds);
//! - **forward secrecy**: session keys come from ephemeral diffie-hellman, so
//!   compromising a long-term key later does not expose past sessions;
//! - **confidentiality**: control bodies are encrypted, not just authenticated.
//!
//! # handshake
//!
//! `IK` is two messages:
//!
//! ```text
//!   initiator                          responder
//!   (knows responder's static key)
//!       -> e, es, s, ss
//!                                          (learns initiator's static key)
//!       <- e, ee, se
//! ```
//!
//! after it completes, both sides derive a pair of record keys from the
//! handshake hash.
//!
//! # record layer
//!
//! we do **not** use snow's `TransportState` directly: its implicit nonce is a
//! counter, so a single dropped or reordered udp datagram desynchronises the
//! stream permanently. control traffic runs over plain udp, so instead each
//! record is `[ nonce: 12 ][ chacha20-poly1305 ciphertext+tag ]` with a *random*
//! per-message nonce and keys derived from the handshake. that is tolerant of
//! loss and reordering. replay/duplication is left to the layers that already
//! handle it (advertisement sequence numbers, endpoint epochs).
//!
//! # what is still out of scope
//!
//! - no rekeying of a live session (a session lasts until the process ends or
//!   the peer re-handshakes);
//! - no identity rotation / revocation;
//! - static public keys are distributed out of band (configuration).

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// the noise pattern used for every control session.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// length of a static key (x25519) and of the handshake hash.
pub const KEY_LEN: usize = 32;

/// length of a chacha20-poly1305 tag.
pub const TAG_LEN: usize = 16;

/// length of a record nonce.
pub const NONCE_LEN: usize = 12;

/// largest handshake message we will produce or accept.
pub const HANDSHAKE_MAX: usize = 512;

/// a peer's long-term static public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// raw bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// build from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// lowercase hex.
    pub fn to_hex(self) -> String {
        to_hex(&self.0)
    }

    /// parse from hex.
    pub fn from_hex(s: &str) -> Result<Self, NoiseError> {
        Ok(Self(from_hex(s)?))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

/// this node's long-term keypair.
#[derive(Clone)]
pub struct Identity {
    private: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
}

impl Identity {
    /// generate a fresh identity from the os rng.
    pub fn generate() -> Result<Self, NoiseError> {
        let mut private = [0u8; KEY_LEN];
        getrandom::getrandom(&mut private).map_err(|_| NoiseError::Entropy)?;
        Ok(Self::from_private(private))
    }

    /// build an identity from a raw private key, deriving the public key.
    pub fn from_private(private: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(private);
        let public = X25519Public::from(&secret).to_bytes();
        Self { private, public }
    }

    /// parse an identity from hex private-key bytes.
    pub fn from_hex(private_hex: &str) -> Result<Self, NoiseError> {
        Ok(Self::from_private(from_hex(private_hex)?))
    }

    /// this node's public key.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.public)
    }

    /// hex of the private key. treat as a secret.
    pub fn private_hex(&self) -> String {
        to_hex(&self.private)
    }

    /// hex of the public key.
    pub fn public_hex(&self) -> String {
        to_hex(&self.public)
    }

    fn private_bytes(&self) -> &[u8; KEY_LEN] {
        &self.private
    }
}

/// never print key material.
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity(public={})", self.public_hex())
    }
}

/// which side of the handshake we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// we dial the peer; we must already know its static key.
    Initiator,
    /// we accept; we learn the peer's static key from the handshake.
    Responder,
}

/// an in-progress handshake with one peer.
pub struct Handshake {
    state: HandshakeState,
    role: Role,
}

impl Handshake {
    fn params() -> Result<NoiseParams, NoiseError> {
        NOISE_PATTERN.parse().map_err(|_| NoiseError::Parameters)
    }

    /// begin a handshake as the initiator, knowing the peer's static key.
    pub fn initiate(local: &Identity, remote: &PublicKey) -> Result<Self, NoiseError> {
        let builder = Builder::new(Self::params()?)
            .local_private_key(local.private_bytes())
            .remote_public_key(remote.as_bytes());
        let state = builder
            .build_initiator()
            .map_err(|e| NoiseError::Noise(e.to_string()))?;
        Ok(Self {
            state,
            role: Role::Initiator,
        })
    }

    /// begin a handshake as the responder, using only our own static key.
    pub fn respond(local: &Identity) -> Result<Self, NoiseError> {
        let builder = Builder::new(Self::params()?).local_private_key(local.private_bytes());
        let state = builder
            .build_responder()
            .map_err(|e| NoiseError::Noise(e.to_string()))?;
        Ok(Self {
            state,
            role: Role::Responder,
        })
    }

    /// which side we are.
    pub fn role(&self) -> Role {
        self.role
    }

    /// produce the next handshake message to send.
    pub fn write(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; HANDSHAKE_MAX];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| NoiseError::Noise(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// consume a handshake message from the peer.
    pub fn read(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        if message.len() > HANDSHAKE_MAX {
            return Err(NoiseError::TooLong { len: message.len() });
        }
        let mut payload = vec![0u8; HANDSHAKE_MAX];
        self.state
            .read_message(message, &mut payload)
            .map_err(|e| NoiseError::Noise(e.to_string()))?;
        Ok(())
    }

    /// has the handshake completed (both sides can now use the session)?
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// the remote static key, once the handshake has revealed it.
    pub fn remote_static(&self) -> Option<PublicKey> {
        self.state
            .get_remote_static()
            .and_then(|bytes| <[u8; KEY_LEN]>::try_from(bytes).ok())
            .map(PublicKey)
    }

    /// finish the handshake, deriving the record-layer session.
    pub fn finish(self) -> Result<Session, NoiseError> {
        if !self.state.is_handshake_finished() {
            return Err(NoiseError::NotFinished);
        }
        let hash = self.state.get_handshake_hash().to_vec();
        let remote = self.remote_static().ok_or(NoiseError::NoRemoteStatic)?.0;
        let i_to_r = derive_key(&hash, b"weave initiator->responder");
        let r_to_i = derive_key(&hash, b"weave responder->initiator");
        let (send, recv) = match self.role {
            Role::Initiator => (i_to_r, r_to_i),
            Role::Responder => (r_to_i, i_to_r),
        };
        Ok(Session {
            send,
            recv,
            remote_static: remote,
        })
    }
}

/// an established, authenticated record-layer session with one peer.
pub struct Session {
    send: [u8; KEY_LEN],
    recv: [u8; KEY_LEN],
    remote_static: [u8; KEY_LEN],
}

impl Session {
    /// the peer's static key this session is bound to.
    pub fn remote_static(&self) -> PublicKey {
        PublicKey(self.remote_static)
    }

    /// encrypt a control body into a record `[nonce][ciphertext+tag]`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| NoiseError::Entropy)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&self.send).map_err(|_| NoiseError::Key)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| NoiseError::Encrypt)?;
        let mut record = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }

    /// decrypt a record produced by the peer's `seal`.
    pub fn open(&self, record: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if record.len() < NONCE_LEN + TAG_LEN {
            return Err(NoiseError::BadRecord { len: record.len() });
        }
        let (nonce, ciphertext) = record.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.recv).map_err(|_| NoiseError::Key)?;
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| NoiseError::Decrypt)
    }
}

/// derive a 32-byte key from the handshake hash and a direction label.
fn derive_key(hash: &[u8], label: &[u8]) -> [u8; KEY_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hash).expect("hmac accepts any key length");
    mac.update(label);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&out);
    key
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Result<[u8; KEY_LEN], NoiseError> {
    let s = s.trim();
    if s.len() != KEY_LEN * 2 {
        return Err(NoiseError::Hex { len: s.len() });
    }
    let mut out = [0u8; KEY_LEN];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8, NoiseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(NoiseError::Hex { len: 1 }),
    }
}

/// what can go wrong building, running or using a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseError {
    /// the os rng failed.
    Entropy,
    /// the noise parameters failed to parse (a programming error).
    Parameters,
    /// the noise library rejected a step.
    Noise(String),
    /// the handshake was finished before its final message.
    NotFinished,
    /// a finished handshake had no remote static key.
    NoRemoteStatic,
    /// a key was the wrong length (a programming error).
    Key,
    /// encryption failed.
    Encrypt,
    /// a record did not authenticate.
    Decrypt,
    /// a record was too short to contain a nonce and tag.
    BadRecord {
        /// bytes we got.
        len: usize,
    },
    /// a handshake message was too long.
    TooLong {
        /// bytes we got.
        len: usize,
    },
    /// a hex key was malformed.
    Hex {
        /// length or position of the problem.
        len: usize,
    },
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy => write!(f, "the os rng failed"),
            Self::Parameters => write!(f, "invalid noise parameters"),
            Self::Noise(err) => write!(f, "noise handshake failed: {err}"),
            Self::NotFinished => write!(f, "handshake used before it finished"),
            Self::NoRemoteStatic => write!(f, "handshake produced no remote static key"),
            Self::Key => write!(f, "invalid key length"),
            Self::Encrypt => write!(f, "encryption failed"),
            Self::Decrypt => write!(f, "a control record failed authentication"),
            Self::BadRecord { len } => write!(f, "control record too short: {len} bytes"),
            Self::TooLong { len } => write!(f, "handshake message too long: {len} bytes"),
            Self::Hex { len } => write!(f, "malformed hex key (length {len})"),
        }
    }
}

impl std::error::Error for NoiseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Identity, Identity) {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        (a, b)
    }

    // run an ik handshake and return each side's session.
    fn handshake(a: &Identity, b: &Identity) -> (Session, Session) {
        let mut initiator = Handshake::initiate(a, &b.public()).unwrap();
        let mut responder = Handshake::respond(b).unwrap();

        let m1 = initiator.write().unwrap();
        responder.read(&m1).unwrap();
        assert!(!initiator.is_finished());
        let m2 = responder.write().unwrap();
        assert!(
            responder.is_finished(),
            "ik responder finishes after writing message 2"
        );
        initiator.read(&m2).unwrap();
        assert!(initiator.is_finished());

        let si = initiator.finish().unwrap();
        let sr = responder.finish().unwrap();
        (si, sr)
    }

    #[test]
    fn a_public_key_round_trips_through_hex() {
        let id = Identity::generate().unwrap();
        let hex = id.public_hex();
        assert_eq!(hex.len(), KEY_LEN * 2);
        assert_eq!(PublicKey::from_hex(&hex).unwrap(), id.public());
    }

    #[test]
    fn an_identity_round_trips_through_hex() {
        let id = Identity::generate().unwrap();
        let restored = Identity::from_hex(&id.private_hex()).unwrap();
        assert_eq!(restored.public(), id.public());
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!(Identity::from_hex("nope").is_err());
        assert!(Identity::from_hex(&"zz".repeat(KEY_LEN)).is_err());
    }

    #[test]
    fn the_responder_learns_the_initiators_static_key() {
        let (a, b) = pair();
        let mut initiator = Handshake::initiate(&a, &b.public()).unwrap();
        let m1 = initiator.write().unwrap();
        let mut responder = Handshake::respond(&b).unwrap();
        responder.read(&m1).unwrap();
        assert_eq!(responder.remote_static(), Some(a.public()));
    }

    #[test]
    fn both_sides_derive_matching_sessions() {
        let (a, b) = pair();
        let (si, sr) = handshake(&a, &b);
        assert_eq!(si.remote_static(), b.public());
        assert_eq!(sr.remote_static(), a.public());

        // initiator -> responder
        let record = si.seal(b"link advert").unwrap();
        assert_eq!(sr.open(&record).unwrap(), b"link advert");

        // responder -> initiator (the other direction key)
        let record = sr.seal(b"pong").unwrap();
        assert_eq!(si.open(&record).unwrap(), b"pong");
    }

    #[test]
    fn a_tampered_record_is_rejected() {
        let (a, b) = pair();
        let (si, sr) = handshake(&a, &b);
        let mut record = si.seal(b"hello").unwrap();
        let last = record.len() - 1;
        record[last] ^= 0x80;
        assert_eq!(sr.open(&record), Err(NoiseError::Decrypt));
    }

    #[test]
    fn a_short_record_is_rejected() {
        let (a, b) = pair();
        let (_, sr) = handshake(&a, &b);
        assert!(matches!(
            sr.open(&[0u8; NONCE_LEN]),
            Err(NoiseError::BadRecord { .. })
        ));
    }

    #[test]
    fn a_third_party_cannot_open_the_session() {
        let (a, b) = pair();
        let (si, _sr) = handshake(&a, &b);
        // a session built with a different peer's identity must not decrypt.
        let c = Identity::generate().unwrap();
        let (other, _) = handshake(&a, &c);
        let record = si.seal(b"secret").unwrap();
        assert_eq!(other.open(&record), Err(NoiseError::Decrypt));
    }

    #[test]
    fn a_dropped_message_does_not_desynchronise_the_session() {
        // the whole point of the explicit-nonce record layer: losing a record
        // must not stop later records from being read.
        let (a, b) = pair();
        let (si, sr) = handshake(&a, &b);
        let _lost = si.seal(b"first").unwrap();
        let delivered = si.seal(b"second").unwrap();
        assert_eq!(sr.open(&delivered).unwrap(), b"second");
    }

    #[test]
    fn an_untrusted_initiator_cannot_impersonate_a_peer() {
        // the responder does not know the initiator up front; it learns the
        // static key from the handshake and the caller must match it against the
        // configured peers.
        let (a, b) = pair();
        let (_, sr) = handshake(&a, &b);
        assert_eq!(sr.remote_static(), a.public());

        let impersonator = Identity::generate().unwrap();
        assert_ne!(sr.remote_static(), impersonator.public());
    }
}
