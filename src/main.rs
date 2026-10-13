use std::error::Error;
use std::net::SocketAddr;

use clap::Parser;
use tokio::sync::watch;
use tokio::task::JoinError;
use tracing::{info, warn};

use weave::transport;

/// weave - a udp transport.
///
/// run two with --peer pointing at each other to exchange a frame.
/// no crypto, no routing, no tun, no delivery guarantees.
#[derive(Debug, Parser)]
#[command(name = "weave", version, about, long_about)]
struct Args {
    /// local udp addr to bind, e.g. 127.0.0.1:4000
    #[arg(long, value_name = "ADDR:PORT")]
    bind: SocketAddr,

    /// peer endpoint for the startup message, e.g. 127.0.0.1:4001
    /// leave it off to just sit and receive
    #[arg(long, value_name = "ADDR:PORT")]
    peer: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    run(Args::parse()).await
}

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let socket = transport::bind(args.bind).await?;
    info!(bind = %args.bind, "weave node listening");

    if let Some(peer) = args.peer {
        let payload = format!("hello from {}", args.bind);
        transport::send_message(&socket, peer, payload.as_bytes()).await?;
        info!(%peer, "sent initial data message");
    } else {
        info!("no --peer configured; running in receive-only mode");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut recv_handle = tokio::spawn(transport::recv_loop(socket, shutdown_rx));

    // whichever happens first: ctrl+c, or the recv task ending on its own
    let early_exit = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received; shutting down");
            None
        }
        result = &mut recv_handle => Some(result),
    };

    // stop the recv task and wait for it to finish
    let _ = shutdown_tx.send(true);
    match early_exit {
        Some(result) => report_receiver(result),
        None => report_receiver(recv_handle.await),
    }

    Ok(())
}

fn report_receiver(result: Result<std::io::Result<()>, JoinError>) {
    match result {
        Ok(Ok(())) => info!("receive task stopped cleanly"),
        Ok(Err(err)) => warn!(error = %err, "receive task ended with error"),
        Err(err) => warn!(error = %err, "receive task failed to join"),
    }
}
