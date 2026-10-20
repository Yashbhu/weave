//! weave-netbench: udp echo benchmark for real network paths.
//!
//! `weave-netbench echo` runs the target machine's echo server;
//! `weave-netbench probe` measures round-trip latency, throughput and loss
//! against it. run it once over the direct path (baseline) and once through
//! the weave overlay to quantify the overlay's overhead on a real network.
//! see BENCHMARKING.md for the full methodology.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::{sleep_until, timeout, timeout_at, Instant as TokioInstant};

const MAGIC: [u8; 4] = *b"WVNB";
const HEADER_LEN: usize = 12;
const RECV_BUF: usize = 65_535;
const DEFAULT_SIZES: &str = "64,512,1200,1400";

#[derive(Debug, Parser)]
#[command(
    name = "weave-netbench",
    version,
    about = "udp echo benchmark: measure rtt, throughput and loss on a real network path (baseline or through weave)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// udp echo server: run this on the target machine
    Echo {
        /// address to listen on
        #[arg(long, value_name = "ADDR:PORT", default_value = "0.0.0.0:9000")]
        bind: SocketAddr,
    },
    /// send probes to an echo server and report rtt, throughput and loss
    Probe(ProbeArgs),
}

#[derive(Debug, Args)]
struct ProbeArgs {
    /// echo server address to probe, e.g. 192.168.1.20:9000 or an overlay address 10.0.0.2:9000
    #[arg(long, value_name = "ADDR:PORT")]
    target: SocketAddr,

    /// label recorded in the output, e.g. baseline, weave, weave-2hop
    #[arg(long, default_value = "probe")]
    label: String,

    /// comma-separated udp payload sizes in bytes (ip+udp headers add 28 more)
    #[arg(long, value_name = "BYTES,...", default_value = DEFAULT_SIZES)]
    sizes: String,

    /// measured runs per size (each run: latency phase, then throughput phase)
    #[arg(long, default_value_t = 5)]
    runs: u32,

    /// warmup runs per size, discarded
    #[arg(long, default_value_t = 1)]
    warmup: u32,

    /// sequential rtt probes per run
    #[arg(long, default_value_t = 200)]
    probes: u32,

    /// throughput phase duration per run, in milliseconds
    #[arg(long, value_name = "MS", default_value_t = 3000)]
    duration_ms: u64,

    /// max unanswered probes in flight during the throughput phase
    #[arg(long, default_value_t = 128)]
    window: usize,

    /// cap the throughput-phase send rate; 0 sends as fast as the window allows
    #[arg(long, value_name = "PPS", default_value_t = 0)]
    pps: u64,

    /// per-probe reply timeout and throughput drain timeout, in milliseconds
    #[arg(long, value_name = "MS", default_value_t = 1000)]
    timeout_ms: u64,

    /// local address to send from; omit to let the kernel choose
    #[arg(long, value_name = "ADDR:PORT")]
    bind: Option<SocketAddr>,

    /// print a line per run to stderr
    #[arg(long)]
    verbose: bool,

    /// emit csv instead of the aligned table
    #[arg(long)]
    csv: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Echo { bind } => {
            run_echo(bind).await?;
        }
        Command::Probe(args) => {
            let csv = args.csv;
            let report = run_probe(args).await?;
            if csv {
                print!("{}", report.to_csv());
            } else {
                print!("{}", report.to_table());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// echo server
// ---------------------------------------------------------------------------

async fn serve_echo(
    socket: UdpSocket,
    echoed: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
) -> io::Result<()> {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        let _ = socket.send_to(&buf[..len], from).await;
        echoed.fetch_add(1, Ordering::Relaxed);
        bytes.fetch_add(len as u64, Ordering::Relaxed);
    }
}

async fn run_echo(bind: SocketAddr) -> io::Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    eprintln!("weave-netbench echo listening on {}", socket.local_addr()?);
    let echoed = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let (cpu_before, _) = cpu_and_rss();
    let handle = tokio::spawn(serve_echo(socket, echoed.clone(), bytes.clone()));
    tokio::signal::ctrl_c().await?;
    handle.abort();
    let (cpu, rss_kib) = cpu_and_rss();
    eprintln!(
        "echoed {} packets ({} bytes) in {:.1}s; cpu {:.2}s, peak rss {:.1} MB",
        echoed.load(Ordering::Relaxed),
        bytes.load(Ordering::Relaxed),
        cpu.saturating_sub(cpu_before).as_secs_f64(),
        cpu.as_secs_f64(),
        rss_kib as f64 / 1024.0,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// probe protocol
// ---------------------------------------------------------------------------

fn build_probe(size: usize, seq: u64) -> Vec<u8> {
    let mut probe = vec![0u8; size];
    probe[..4].copy_from_slice(&MAGIC);
    probe[4..12].copy_from_slice(&seq.to_be_bytes());
    for (i, byte) in probe[HEADER_LEN..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    probe
}

fn probe_seq(datagram: &[u8]) -> Option<u64> {
    if datagram.len() < HEADER_LEN || datagram[..4] != MAGIC {
        return None;
    }
    Some(u64::from_be_bytes(datagram[4..12].try_into().ok()?))
}

fn parse_sizes(spec: &str) -> io::Result<Vec<usize>> {
    let mut sizes = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let size: usize = part
            .parse()
            .map_err(|_| invalid(&format!("invalid payload size: {part:?}")))?;
        if size < HEADER_LEN {
            return Err(invalid(&format!(
                "payload size {size} is below the {HEADER_LEN}-byte probe header"
            )));
        }
        if size > 65_507 {
            return Err(invalid(&format!(
                "payload size {size} exceeds the maximum udp payload"
            )));
        }
        sizes.push(size);
    }
    if sizes.is_empty() {
        return Err(invalid("--sizes needs at least one payload size"));
    }
    Ok(sizes)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_owned())
}

// ---------------------------------------------------------------------------
// measurement
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ProbeCfg {
    target: SocketAddr,
    probes: u32,
    duration: Duration,
    window: usize,
    pps: u64,
    timeout: Duration,
}

struct RunResult {
    rtt: Vec<Duration>,
    probes: u32,
    thr_sent: u64,
    thr_received: u64,
}

impl RunResult {
    fn rtt_sorted(&self) -> Vec<Duration> {
        let mut sorted = self.rtt.clone();
        sorted.sort_unstable();
        sorted
    }

    fn rtt_loss_pct(&self) -> f64 {
        loss_pct(
            self.probes.saturating_sub(self.rtt.len() as u32) as u64,
            self.probes as u64,
        )
    }

    fn thr_pps(&self, duration: Duration) -> f64 {
        self.thr_received as f64 / duration.as_secs_f64()
    }

    fn thr_loss_pct(&self) -> f64 {
        loss_pct(
            self.thr_sent.saturating_sub(self.thr_received),
            self.thr_sent,
        )
    }
}

fn loss_pct(lost: u64, sent: u64) -> f64 {
    if sent == 0 {
        return 0.0;
    }
    lost.min(sent) as f64 / sent as f64 * 100.0
}

async fn latency_phase(
    socket: &UdpSocket,
    cfg: &ProbeCfg,
    size: usize,
    next_seq: &AtomicU64,
) -> io::Result<Vec<Duration>> {
    let mut samples = Vec::with_capacity(cfg.probes as usize);
    let mut buf = vec![0u8; RECV_BUF];
    for _ in 0..cfg.probes {
        let seq = next_seq.fetch_add(1, Ordering::Relaxed);
        let probe = build_probe(size, seq);
        let sent_at = Instant::now();
        socket.send_to(&probe, cfg.target).await?;
        let deadline = TokioInstant::now() + cfg.timeout;
        loop {
            match timeout_at(deadline, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => {
                    if probe_seq(&buf[..len]) == Some(seq) {
                        samples.push(sent_at.elapsed());
                        break;
                    }
                }
                Ok(Err(err)) => return Err(err),
                Err(_) => break,
            }
        }
    }
    Ok(samples)
}

struct ThrShared {
    outstanding: Mutex<HashSet<u64>>,
    sent: AtomicU64,
    received: AtomicU64,
    done: AtomicBool,
    wake: Notify,
    next_seq: AtomicU64,
}

async fn throughput_phase(
    socket: Arc<UdpSocket>,
    cfg: &ProbeCfg,
    size: usize,
    next_seq: &AtomicU64,
) -> io::Result<(u64, u64)> {
    let shared = Arc::new(ThrShared {
        outstanding: Mutex::new(HashSet::new()),
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
        done: AtomicBool::new(false),
        wake: Notify::new(),
        next_seq: AtomicU64::new(next_seq.load(Ordering::Relaxed)),
    });
    let deadline = Instant::now() + cfg.duration;

    let sender = {
        let socket = socket.clone();
        let shared = shared.clone();
        let target = cfg.target;
        let window = cfg.window;
        let pps = cfg.pps;
        tokio::spawn(async move {
            let mut pace =
                (pps > 0).then(|| tokio::time::interval(Duration::from_secs_f64(1.0 / pps as f64)));
            loop {
                if Instant::now() >= deadline {
                    break;
                }
                if shared.outstanding.lock().unwrap().len() >= window {
                    tokio::select! {
                        _ = shared.wake.notified() => continue,
                        _ = sleep_until(TokioInstant::from_std(deadline)) => break,
                    }
                }
                if let Some(interval) = pace.as_mut() {
                    interval.tick().await;
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                let seq = shared.next_seq.fetch_add(1, Ordering::Relaxed);
                let probe = build_probe(size, seq);
                shared.outstanding.lock().unwrap().insert(seq);
                if socket.send_to(&probe, target).await.is_err() {
                    shared.outstanding.lock().unwrap().remove(&seq);
                    break;
                }
                shared.sent.fetch_add(1, Ordering::Relaxed);
            }
            shared.done.store(true, Ordering::Release);
        })
    };
    next_seq.store(shared.next_seq.load(Ordering::Relaxed), Ordering::Relaxed);

    let mut buf = vec![0u8; RECV_BUF];
    let mut drain_deadline: Option<Instant> = None;
    loop {
        if shared.done.load(Ordering::Acquire) {
            if shared.outstanding.lock().unwrap().is_empty() {
                break;
            }
            let drain = *drain_deadline.get_or_insert_with(|| Instant::now() + cfg.timeout);
            if Instant::now() >= drain {
                break;
            }
        }
        match timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if let Some(seq) = probe_seq(&buf[..len]) {
                    if shared.outstanding.lock().unwrap().remove(&seq) {
                        shared.received.fetch_add(1, Ordering::Relaxed);
                        shared.wake.notify_one();
                    }
                }
            }
            Ok(Err(err)) => {
                let _ = sender.await;
                return Err(err);
            }
            Err(_) => {}
        }
    }
    let _ = sender.await;
    let received = shared.received.load(Ordering::Relaxed);
    next_seq.store(shared.next_seq.load(Ordering::Relaxed), Ordering::Relaxed);
    Ok((shared.sent.load(Ordering::Relaxed), received))
}

async fn measure_run(
    socket: &Arc<UdpSocket>,
    cfg: &ProbeCfg,
    size: usize,
    next_seq: &AtomicU64,
) -> io::Result<RunResult> {
    let rtt = latency_phase(socket, cfg, size, next_seq).await?;
    let probes = cfg.probes;
    let (thr_sent, thr_received) = throughput_phase(socket.clone(), cfg, size, next_seq).await?;
    Ok(RunResult {
        rtt,
        probes,
        thr_sent,
        thr_received,
    })
}

async fn run_probe(args: ProbeArgs) -> io::Result<ProbeReport> {
    let sizes = parse_sizes(&args.sizes)?;
    if args.runs == 0 {
        return Err(invalid("--runs must be at least 1"));
    }
    if args.probes == 0 {
        return Err(invalid("--probes must be at least 1"));
    }
    if args.window == 0 {
        return Err(invalid("--window must be at least 1"));
    }
    let socket = match args.bind {
        Some(bind) => UdpSocket::bind(bind).await?,
        None => UdpSocket::bind("0.0.0.0:0").await?,
    };
    let socket = Arc::new(socket);
    let cfg = ProbeCfg {
        target: args.target,
        probes: args.probes,
        duration: Duration::from_millis(args.duration_ms.max(50)),
        window: args.window,
        pps: args.pps,
        timeout: Duration::from_millis(args.timeout_ms.max(1)),
    };
    let (cpu_before, _) = cpu_and_rss();
    let wall_start = Instant::now();
    let next_seq = AtomicU64::new(0);

    let mut reports = Vec::with_capacity(sizes.len());
    for &size in &sizes {
        for _ in 0..args.warmup {
            measure_run(&socket, &cfg, size, &next_seq).await?;
        }
        let mut runs = Vec::with_capacity(args.runs as usize);
        for run in 1..=args.runs {
            let result = measure_run(&socket, &cfg, size, &next_seq).await?;
            if args.verbose {
                let sorted = result.rtt_sorted();
                eprintln!(
                    "  {size:>4}B run {run:>2}: rtt median {:>8.1}us p95 {:>8.1}us loss {:>5.2}% | thr {:>9.1} pkt/s {:>7.2} Mbps loss {:>5.2}%",
                    percentile(&sorted, 0.5).as_secs_f64() * 1e6,
                    percentile(&sorted, 0.95).as_secs_f64() * 1e6,
                    result.rtt_loss_pct(),
                    result.thr_pps(cfg.duration),
                    result.thr_pps(cfg.duration) * size as f64 * 8.0 / 1e6,
                    result.thr_loss_pct(),
                );
            }
            runs.push(result);
        }
        reports.push(SizeReport { size, runs });
    }

    let (cpu, rss_kib) = cpu_and_rss();
    Ok(ProbeReport {
        label: args.label,
        target: args.target,
        runs: args.runs,
        warmup: args.warmup,
        probes: args.probes,
        duration: cfg.duration,
        window: cfg.window,
        pps: cfg.pps,
        timeout: cfg.timeout,
        sizes: reports,
        cpu: cpu.saturating_sub(cpu_before),
        rss_kib,
        wall: wall_start.elapsed(),
    })
}

// ---------------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------------

struct SizeReport {
    size: usize,
    runs: Vec<RunResult>,
}

struct Agg {
    size: usize,
    rtt_median: Duration,
    rtt_p95: Duration,
    rtt_loss_pct: f64,
    thr_pps: f64,
    thr_mbps: f64,
    thr_loss_pct: f64,
}

struct ProbeReport {
    label: String,
    target: SocketAddr,
    runs: u32,
    warmup: u32,
    probes: u32,
    duration: Duration,
    window: usize,
    pps: u64,
    timeout: Duration,
    sizes: Vec<SizeReport>,
    cpu: Duration,
    rss_kib: u64,
    wall: Duration,
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let index = (((sorted.len() as f64 - 1.0) * p).round() as usize).min(sorted.len() - 1);
    sorted[index]
}

fn median_f64(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

impl ProbeReport {
    fn aggregates(&self) -> Vec<Agg> {
        self.sizes
            .iter()
            .map(|report| {
                let mut pooled: Vec<Duration> =
                    report.runs.iter().flat_map(|r| r.rtt.clone()).collect();
                pooled.sort_unstable();
                let probes: u32 = report.runs.iter().map(|r| r.probes).sum();
                let received: u32 = report.runs.iter().map(|r| r.rtt.len() as u32).sum();
                let mut pps: Vec<f64> = report
                    .runs
                    .iter()
                    .map(|r| r.thr_pps(self.duration))
                    .collect();
                let thr_pps = median_f64(&mut pps);
                let thr_sent: u64 = report.runs.iter().map(|r| r.thr_sent).sum();
                let thr_received: u64 = report.runs.iter().map(|r| r.thr_received).sum();
                Agg {
                    size: report.size,
                    rtt_median: percentile(&pooled, 0.5),
                    rtt_p95: percentile(&pooled, 0.95),
                    rtt_loss_pct: loss_pct(probes.saturating_sub(received) as u64, probes as u64),
                    thr_pps,
                    thr_mbps: thr_pps * report.size as f64 * 8.0 / 1e6,
                    thr_loss_pct: loss_pct(thr_sent.saturating_sub(thr_received), thr_sent),
                }
            })
            .collect()
    }

    fn to_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "weave-netbench  label={}  target={}\n",
            self.label, self.target
        ));
        out.push_str(&format!(
            "env: {}-{}  runs={} warmup={} probes/run={} duration={}ms window={} pps={} timeout={}ms sizes={}\n",
            std::env::consts::OS,
            std::env::consts::ARCH,
            self.runs,
            self.warmup,
            self.probes,
            self.duration.as_millis(),
            self.window,
            if self.pps == 0 { "max".to_owned() } else { self.pps.to_string() },
            self.timeout.as_millis(),
            self.sizes
                .iter()
                .map(|r| r.size.to_string())
                .collect::<Vec<_>>()
                .join(","),
        ));
        out.push('\n');
        out.push_str(&format!(
            "{:>7}  {:>11} {:>11} {:>9}  {:>11} {:>10} {:>9}\n",
            "payload", "rtt_median", "rtt_p95", "rtt_loss", "thr_pkt/s", "thr_mbps", "thr_loss"
        ));
        for agg in self.aggregates() {
            out.push_str(&format!(
                "{:>5}B  {:>8.1}us {:>8.1}us {:>8.2}%  {:>11.1} {:>10.2} {:>8.2}%\n",
                agg.size,
                agg.rtt_median.as_secs_f64() * 1e6,
                agg.rtt_p95.as_secs_f64() * 1e6,
                agg.rtt_loss_pct,
                agg.thr_pps,
                agg.thr_mbps,
                agg.thr_loss_pct,
            ));
        }
        out.push_str(&format!(
            "\nrtt is round-trip; throughput is application payload (echo goodput); loss is application-level (both directions).\n\
             cpu: user+sys {:.2}s   peak rss {:.1} MB   wall {:.1}s\n",
            self.cpu.as_secs_f64(),
            self.rss_kib as f64 / 1024.0,
            self.wall.as_secs_f64(),
        ));
        out
    }

    fn to_csv(&self) -> String {
        let mut out = String::from(
            "label,target,size,run,rtt_median_us,rtt_p95_us,rtt_loss_pct,thr_pkt_s,thr_mbps,thr_loss_pct\n",
        );
        for report in &self.sizes {
            for (index, run) in report.runs.iter().enumerate() {
                let sorted = run.rtt_sorted();
                out.push_str(&self.csv_row(&CsvRow {
                    size: report.size,
                    run: (index + 1).to_string(),
                    rtt_median: percentile(&sorted, 0.5),
                    rtt_p95: percentile(&sorted, 0.95),
                    rtt_loss: run.rtt_loss_pct(),
                    thr_pps: run.thr_pps(self.duration),
                    thr_loss: run.thr_loss_pct(),
                }));
            }
        }
        for agg in self.aggregates() {
            out.push_str(&self.csv_row(&CsvRow {
                size: agg.size,
                run: "avg".to_owned(),
                rtt_median: agg.rtt_median,
                rtt_p95: agg.rtt_p95,
                rtt_loss: agg.rtt_loss_pct,
                thr_pps: agg.thr_pps,
                thr_loss: agg.thr_loss_pct,
            }));
        }
        out
    }

    fn csv_row(&self, row: &CsvRow) -> String {
        format!(
            "{},{},{},{},{:.1},{:.1},{:.2},{:.1},{:.2},{:.2}\n",
            self.label,
            self.target,
            row.size,
            row.run,
            row.rtt_median.as_secs_f64() * 1e6,
            row.rtt_p95.as_secs_f64() * 1e6,
            row.rtt_loss,
            row.thr_pps,
            row.thr_pps * row.size as f64 * 8.0 / 1e6,
            row.thr_loss,
        )
    }
}

/// one csv data row for a size/report pair.
struct CsvRow {
    size: usize,
    run: String,
    rtt_median: Duration,
    rtt_p95: Duration,
    rtt_loss: f64,
    thr_pps: f64,
    thr_loss: f64,
}

// ---------------------------------------------------------------------------
// process cpu / memory
// ---------------------------------------------------------------------------

/// process cpu time (user+sys) and peak rss in kib.
fn cpu_and_rss() -> (Duration, u64) {
    // SAFETY: getrusage fills a caller-provided struct and returns early on error.
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return (Duration::ZERO, 0);
        }
        let to_duration = |t: libc::timeval| {
            Duration::new(t.tv_sec.max(0) as u64, t.tv_usec.max(0) as u32 * 1000)
        };
        let cpu = to_duration(usage.ru_utime) + to_duration(usage.ru_stime);
        let maxrss = usage.ru_maxrss.max(0) as u64;
        // linux reports kib, macos reports bytes.
        let kib = if cfg!(target_os = "macos") {
            maxrss / 1024
        } else {
            maxrss
        };
        (cpu, kib)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_header_round_trips() {
        let probe = build_probe(64, 42);
        assert_eq!(probe.len(), 64);
        assert_eq!(probe_seq(&probe), Some(42));
        assert_eq!(probe_seq(b"short"), None);
        assert_eq!(probe_seq(b"XXXXpaddingpastheader"), None);
    }

    #[test]
    fn size_specs_parse_and_validate() {
        assert_eq!(parse_sizes("64,512,1400").unwrap(), vec![64, 512, 1400]);
        assert_eq!(parse_sizes(" 64 , 512 ").unwrap(), vec![64, 512]);
        assert!(parse_sizes("").is_err());
        assert!(parse_sizes("64,abc").is_err());
        assert!(parse_sizes("8").is_err());
        assert!(parse_sizes("70000").is_err());
    }

    #[tokio::test]
    async fn measures_rtt_and_throughput_against_a_local_echo() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        tokio::spawn(serve_echo(
            server,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ));
        let args = ProbeArgs {
            target,
            label: "loopback".to_owned(),
            sizes: "64,512".to_owned(),
            runs: 1,
            warmup: 0,
            probes: 20,
            duration_ms: 150,
            window: 16,
            pps: 0,
            timeout_ms: 500,
            bind: None,
            verbose: false,
            csv: false,
        };
        let report = run_probe(args).await.unwrap();
        assert_eq!(report.sizes.len(), 2);
        for size_report in &report.sizes {
            let agg = report
                .aggregates()
                .into_iter()
                .find(|a| a.size == size_report.size)
                .unwrap();
            assert!(
                agg.rtt_median < Duration::from_millis(100),
                "median rtt on loopback should be well under 100ms"
            );
            assert_eq!(
                agg.rtt_loss_pct, 0.0,
                "loopback should not lose sequential probes"
            );
            assert!(
                size_report.runs[0].thr_received > 0,
                "loopback should deliver throughput probes"
            );
        }
        let table = report.to_table();
        assert!(table.contains("label=loopback"));
        assert!(table.contains("rtt_median"));
        let csv = report.to_csv();
        assert!(csv.lines().count() > 2);
        assert!(csv.contains("loopback"));
    }

    #[tokio::test]
    async fn a_dead_target_reports_rtt_loss_instead_of_hanging() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = blackhole.local_addr().unwrap();
        drop(blackhole);
        let args = ProbeArgs {
            target,
            label: "blackhole".to_owned(),
            sizes: "64".to_owned(),
            runs: 1,
            warmup: 0,
            probes: 3,
            duration_ms: 100,
            window: 4,
            pps: 0,
            timeout_ms: 100,
            bind: None,
            verbose: false,
            csv: false,
        };
        let started = Instant::now();
        let report = run_probe(args).await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "probe must respect timeouts"
        );
        let agg = &report.aggregates()[0];
        assert_eq!(agg.rtt_loss_pct, 100.0);
        assert_eq!(agg.thr_pps, 0.0);
    }
}
