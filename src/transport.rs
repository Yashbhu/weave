//! the udp side. bind, send, recv. no crypto, no retries, no reordering.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::wire::{self, WireError, MAX_DATAGRAM_SIZE};

/// open a udp socket on addr
pub async fn bind(addr: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}

/// encode payload and send it to dest. encode errors come back as InvalidInput.
pub async fn send_message(socket: &UdpSocket, dest: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let bytes =
        wire::encode(payload).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    socket.send_to(&bytes, dest).await?;
    Ok(())
}

/// read one raw datagram, returns its length and who sent it. size buf to
/// MAX_DATAGRAM_SIZE + 1 so an oversized datagram reads back truncated.
pub async fn recv_datagram(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    socket.recv_from(buf).await
}

/// recv until shutdown is set. bad datagrams get logged and skipped.
pub async fn recv_loop(socket: UdpSocket, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
    if *shutdown.borrow() {
        return Ok(());
    }

    // +1 over the cap so a too-big datagram reads back truncated
    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE + 1];

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                debug!("shutdown signal received; stopping receive loop");
                return Ok(());
            }
            received = recv_datagram(&socket, &mut buf) => {
                match received {
                    Ok((len, from)) => handle_datagram(&buf[..len], from),
                    Err(err) => warn!(error = %err, "failed to receive datagram"),
                }
            }
        }
    }
}

/// decode a datagram and log it, or drop it if it doesn't parse
fn handle_datagram(datagram: &[u8], from: SocketAddr) {
    match wire::decode(datagram) {
        Ok(payload) => info!(%from, payload_len = payload.len(), "received message"),
        Err(err @ WireError::DatagramTooLarge { .. }) => {
            warn!(%from, error = %err, "ignored oversized or truncated datagram");
        }
        Err(err) => warn!(%from, error = %err, "rejected malformed datagram"),
    }
}
