//! tests for the udp transport. random free ports and short timeouts. each
//! test shuts its task down.

use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;
use weave::transport;
use weave::wire::{self, MAX_DATAGRAM_SIZE};

const TIMEOUT: Duration = Duration::from_secs(2);

// socket on a random free port
async fn bind_free_port() -> UdpSocket {
    transport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind socket")
}

#[tokio::test]
async fn binds_to_a_udp_socket() {
    let socket = bind_free_port().await;
    let addr = socket.local_addr().expect("local_addr");
    assert_ne!(addr.port(), 0, "expected a port to be assigned");
}

#[tokio::test]
async fn two_endpoints_exchange_a_message_and_identify_the_sender() {
    let sender = bind_free_port().await;
    let receiver = bind_free_port().await;
    let sender_addr = sender.local_addr().unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    transport::send_message(&sender, receiver_addr, b"ping")
        .await
        .expect("send");

    let mut buf = [0u8; MAX_DATAGRAM_SIZE];
    let (len, from) = timeout(TIMEOUT, transport::recv_datagram(&receiver, &mut buf))
        .await
        .expect("receive timed out")
        .expect("receive");

    assert_eq!(from, sender_addr, "sender address must be identified");
    assert_eq!(wire::decode(&buf[..len]).expect("decode"), b"ping");
}

#[tokio::test]
async fn recv_loop_ignores_malformed_input() {
    let server = bind_free_port().await;
    let server_addr = server.local_addr().unwrap();
    let client = bind_free_port().await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(transport::recv_loop(server, shutdown_rx));

    // too short to be a frame, gets dropped
    client
        .send_to(&[0x01, 0x02], server_addr)
        .await
        .expect("send malformed");

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(!handle.is_finished(), "recv loop should keep running");

    shutdown_tx.send(true).expect("signal shutdown");
    timeout(TIMEOUT, handle)
        .await
        .expect("recv loop did not stop")
        .expect("join")
        .expect("recv loop returned an error");
}

#[tokio::test]
async fn recv_loop_ignores_oversized_datagram() {
    let server = bind_free_port().await;
    let server_addr = server.local_addr().unwrap();
    let client = bind_free_port().await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(transport::recv_loop(server, shutdown_rx));

    // over the cap, gets dropped
    let oversized = vec![0u8; MAX_DATAGRAM_SIZE + 64];
    client
        .send_to(&oversized, server_addr)
        .await
        .expect("send oversized");

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(!handle.is_finished(), "recv loop should keep running");

    shutdown_tx.send(true).expect("signal shutdown");
    timeout(TIMEOUT, handle)
        .await
        .expect("recv loop did not stop")
        .expect("join")
        .expect("recv loop returned an error");
}

#[tokio::test]
async fn shutdown_terminates_the_recv_loop_cleanly() {
    let socket = bind_free_port().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(transport::recv_loop(socket, shutdown_rx));

    // let the task actually get into select! before we signal it
    tokio::time::sleep(Duration::from_millis(25)).await;
    shutdown_tx.send(true).expect("signal shutdown");

    timeout(TIMEOUT, handle)
        .await
        .expect("recv loop did not stop after shutdown")
        .expect("join")
        .expect("recv loop returned an error");
}

#[tokio::test]
async fn dropping_the_shutdown_sender_stops_the_recv_loop() {
    let socket = bind_free_port().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(transport::recv_loop(socket, shutdown_rx));

    tokio::time::sleep(Duration::from_millis(25)).await;
    drop(shutdown_tx);

    timeout(TIMEOUT, handle)
        .await
        .expect("recv loop did not stop when sender dropped")
        .expect("join")
        .expect("recv loop returned an error");
}
