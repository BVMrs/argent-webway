//! Does a bulk blob stream delay small control RPCs on the same QUIC connection?
//!
//! Model of `webway-quic/v0` (one bidi stream per A2A request, blobs on their own streams, R13) over
//! quinn 0.11, through a userspace bottleneck that emulates either a router with a shallow drop-tail
//! buffer or an iroh relay path (deep FIFO: per-client queue of 512 datagrams plus a TCP send buffer).
//!
//! Usage: quic-control-latency [secs] [filter]   (prints one TSV row per scenario)

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

const RATE_BPS: f64 = 20e6; // bottleneck rate, both directions
const ONE_WAY: Duration = Duration::from_millis(30); // RTT 60 ms
const UDP_IP_OVERHEAD: usize = 28;
const RPC_INTERVAL: Duration = Duration::from_millis(50);
const REQ_BYTES: usize = 512;
const RESP_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug)]
enum Cc {
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Clone, Debug)]
struct Scenario {
    buffer_name: &'static str,
    buffer_bytes: usize,
    cc: Cc,
    blobs: usize,
    prio: bool,
    /// receiver (client) connection+stream receive window cap
    rwnd: Option<u32>,
    /// blob streams on a second QUIC connection (as with a separate iroh-blobs ALPN)
    sep: bool,
}

// ---------------------------------------------------------------- bottleneck link

struct Link {
    next_free: Mutex<Instant>,
    buffer: usize,
    tx: mpsc::UnboundedSender<(Instant, Vec<u8>)>,
    drops: AtomicU64,
    max_q: AtomicU64,
}

impl Link {
    fn new(buffer: usize, out: Arc<UdpSocket>, dst: Arc<Mutex<Option<SocketAddr>>>) -> Arc<Self> {
        let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        tokio::spawn(async move {
            while let Some((at, pkt)) = rx.recv().await {
                tokio::time::sleep_until(at).await;
                let d = *dst.lock().unwrap();
                if let Some(d) = d {
                    let _ = out.send_to(&pkt, d).await;
                }
            }
        });
        Arc::new(Link {
            next_free: Mutex::new(Instant::now()),
            buffer,
            tx,
            drops: AtomicU64::new(0),
            max_q: AtomicU64::new(0),
        })
    }

    fn enqueue(&self, pkt: Vec<u8>) {
        let now = Instant::now();
        let wire = pkt.len() + UDP_IP_OVERHEAD;
        let mut nf = self.next_free.lock().unwrap();
        let start = if *nf > now { *nf } else { now };
        let backlog = ((start - now).as_secs_f64() * RATE_BPS / 8.0) as usize;
        if backlog + wire > self.buffer {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.max_q.fetch_max((backlog + wire) as u64, Ordering::Relaxed);
        let done = start + Duration::from_secs_f64(wire as f64 * 8.0 / RATE_BPS);
        *nf = done;
        let _ = self.tx.send((done + ONE_WAY, pkt));
    }
}

/// Proxy: client <-> [c_side] ==link==> [s_side] <-> server. Returns (addr for client, downlink).
async fn proxy(server: SocketAddr, buffer: usize) -> Result<(SocketAddr, Arc<Link>, Arc<Link>)> {
    let c_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let s_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client_addr = Arc::new(Mutex::new(None));
    let server_addr = Arc::new(Mutex::new(Some(server)));
    // client -> server (uplink, carries requests and ACKs)
    let up = Link::new(buffer, s_side.clone(), server_addr);
    // server -> client (downlink, carries the blob and the control responses)
    let down = Link::new(buffer, c_side.clone(), client_addr.clone());
    {
        let (c_side, up) = (c_side.clone(), up.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, from)) = c_side.recv_from(&mut buf).await else { return };
                *client_addr.lock().unwrap() = Some(from);
                up.enqueue(buf[..n].to_vec());
            }
        });
    }
    {
        let (s_side, down) = (s_side.clone(), down.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, _)) = s_side.recv_from(&mut buf).await else { return };
                down.enqueue(buf[..n].to_vec());
            }
        });
    }
    Ok((c_side.local_addr()?, up, down))
}

// ---------------------------------------------------------------- quinn setup

fn transport(cc: Cc, rwnd: Option<u32>) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    let f: Arc<dyn ControllerFactory + Send + Sync> = match cc {
        Cc::Cubic => Arc::new(CubicConfig::default()),
        Cc::NewReno => Arc::new(NewRenoConfig::default()),
        Cc::Bbr => Arc::new(BbrConfig::default()),
    };
    t.congestion_controller_factory(f);
    if let Some(w) = rwnd {
        t.stream_receive_window(w.into());
        t.receive_window(w.into());
    }
    t.max_concurrent_bidi_streams(1000u32.into());
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    Arc::new(t)
}

fn configs(cc: Cc, rwnd: Option<u32>) -> Result<(ServerConfig, ClientConfig)> {
    let cert = rcgen::generate_simple_self_signed(vec!["webway".into()])?;
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let mut sc = ServerConfig::with_single_cert(vec![der.clone()], key)?;
    sc.transport_config(transport(cc, None));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der)?;
    let mut cc_ = ClientConfig::with_root_certificates(Arc::new(roots))?;
    cc_.transport_config(transport(cc, rwnd));
    Ok((sc, cc_))
}

async fn serve(ep: Endpoint, prio: bool) {
    while let Some(inc) = ep.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = inc.await else { return };
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                tokio::spawn(async move {
                    let Ok(req) = recv.read_to_end(1 << 16).await else { return };
                    if req.first() == Some(&b'B') {
                        if prio {
                            let _ = send.set_priority(0);
                        }
                        let chunk = vec![0xAB; 64 * 1024];
                        while send.write_all(&chunk).await.is_ok() {}
                    } else {
                        if prio {
                            let _ = send.set_priority(10);
                        }
                        let _ = send.write_all(&vec![0xCD; RESP_BYTES]).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    }
                });
            }
        });
    }
}

// ---------------------------------------------------------------- one run

struct Out {
    base: Vec<f64>,
    startup: Vec<f64>,
    steady: Vec<f64>,
    lost_rpcs: usize,
    goodput_mbps: f64,
    drops_down: u64,
    maxq_down: u64,
}

async fn run(s: &Scenario, secs: u64) -> Result<Out> {
    let (sc, ccfg) = configs(s.cc, s.rwnd)?;
    let server = Endpoint::server(sc, "127.0.0.1:0".parse()?)?;
    let saddr = server.local_addr()?;
    tokio::spawn(serve(server.clone(), s.prio));
    let (paddr, _up, down) = proxy(saddr, s.buffer_bytes).await?;
    let mut client = Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(ccfg);
    let conn = client.connect(paddr, "webway")?.await?;
    let bconn = if s.sep { client.connect(paddr, "webway")?.await? } else { conn.clone() };

    let t0 = Instant::now();
    let total = Duration::from_secs(secs);
    let blob_start = Duration::from_secs(3);
    let blob_bytes = Arc::new(AtomicU64::new(0));
    let samples: Arc<Mutex<Vec<(f64, f64)>>> = Arc::default();
    let issued = Arc::new(AtomicU64::new(0));

    // blob streams
    for _ in 0..s.blobs {
        let (conn, bb) = (bconn.clone(), blob_bytes.clone());
        tokio::spawn(async move {
            tokio::time::sleep_until(t0 + blob_start).await;
            let Ok((mut send, mut recv)) = conn.open_bi().await else { return };
            let _ = send.write_all(b"B").await;
            let _ = send.finish();
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(Some(n)) = recv.read(&mut buf).await {
                bb.fetch_add(n as u64, Ordering::Relaxed);
            }
        });
    }

    // control RPCs on a fixed schedule
    let mut tick = tokio::time::interval_at(t0, RPC_INTERVAL);
    let mut handles = VecDeque::new();
    let measure_end = total - Duration::from_secs(1);
    while t0.elapsed() < measure_end {
        tick.tick().await;
        let at = t0.elapsed().as_secs_f64();
        let (conn, samples) = (conn.clone(), samples.clone());
        issued.fetch_add(1, Ordering::Relaxed);
        handles.push_back(tokio::spawn(async move {
            let st = Instant::now();
            let r: Result<()> = async {
                let (mut send, mut recv) = conn.open_bi().await?;
                let mut req = vec![b'C'; REQ_BYTES];
                req[0] = b'C';
                send.write_all(&req).await?;
                send.finish()?;
                let resp = recv.read_to_end(1 << 16).await?;
                anyhow::ensure!(resp.len() == RESP_BYTES);
                Ok(())
            }
            .await;
            if r.is_ok() {
                samples.lock().unwrap().push((at, st.elapsed().as_secs_f64() * 1e3));
            }
        }));
    }
    // let in-flight RPCs finish (bounded)
    tokio::time::sleep_until(t0 + total).await;
    let goodput_window = (total - blob_start).as_secs_f64();
    let bytes = blob_bytes.load(Ordering::Relaxed);
    conn.close(0u32.into(), b"done");
    bconn.close(0u32.into(), b"done");
    for h in handles {
        h.abort();
    }
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");

    let samples = samples.lock().unwrap().clone();
    let bs = blob_start.as_secs_f64();
    let mut out = Out {
        base: vec![],
        startup: vec![],
        steady: vec![],
        lost_rpcs: issued.load(Ordering::Relaxed) as usize - samples.len(),
        goodput_mbps: bytes as f64 * 8.0 / goodput_window / 1e6,
        drops_down: down.drops.load(Ordering::Relaxed),
        maxq_down: down.max_q.load(Ordering::Relaxed),
    };
    for (at, ms) in samples {
        if at < bs {
            out.base.push(ms)
        } else if at < bs + 3.0 {
            out.startup.push(ms)
        } else {
            out.steady.push(ms)
        }
    }
    Ok(out)
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((p / 100.0) * (v.len() - 1) as f64).round() as usize;
    v[i]
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let filter = args.get(2).cloned().unwrap_or_default();

    let bdp = (RATE_BPS / 8.0 * 0.060) as usize; // 150 kB
    let buffers: [(&'static str, usize); 3] =
        [("router-1bdp", bdp), ("relay-1MB", 1 << 20), ("relay-4MB", 4 << 20)];
    let mut scen = vec![];
    let mitig = std::env::var("MATRIX").as_deref() == Ok("mitig");
    if mitig {
        // receive-window caps in multiples of the 150 kB BDP; separate blob connection
        for &(bn, bb) in &buffers {
            for cc in [Cc::Cubic, Cc::Bbr] {
                for blobs in [1usize, 4] {
                    for (rwnd, sep, prio) in [
                        (None, true, false),
                        (Some(2 * bdp as u32), false, false),
                        (Some(4 * bdp as u32), false, false),
                        (Some(2 * bdp as u32), true, false),
                        (Some(2 * bdp as u32), false, true),
                    ] {
                        scen.push(Scenario { buffer_name: bn, buffer_bytes: bb, cc, blobs, prio, rwnd, sep });
                    }
                }
            }
        }
    }
    for &(bn, bb) in buffers.iter().filter(|_| !mitig) {
        for cc in [Cc::Cubic, Cc::NewReno, Cc::Bbr] {
            for blobs in [0usize, 1, 4] {
                for prio in [false, true] {
                    if blobs == 0 && prio {
                        continue;
                    }
                    scen.push(Scenario { buffer_name: bn, buffer_bytes: bb, cc, blobs, prio, rwnd: None, sep: false });
                }
            }
        }
    }
    println!(
        "buffer\tcc\tblobs\tprio\trwnd_kB\tsep\tbase_p50\tstartup_p50\tstartup_p99\tsteady_p50\tsteady_p95\tsteady_p99\tsteady_max\tlost_rpcs\tgoodput_mbps\tdown_drops\tdown_maxq_kB"
    );
    for s in scen {
        let tag = format!("{}/{:?}/{}/{}/{:?}/{}", s.buffer_name, s.cc, s.blobs, s.prio, s.rwnd, s.sep);
        if !tag.contains(&filter) {
            continue;
        }
        let mut o = run(&s, secs).await?;
        println!(
            "{}\t{:?}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{}\t{:.2}\t{}\t{}",
            s.buffer_name,
            s.cc,
            s.blobs,
            s.prio,
            s.rwnd.map(|w| (w / 1000).to_string()).unwrap_or("default".into()),
            s.sep,
            pct(&mut o.base, 50.0),
            pct(&mut o.startup, 50.0),
            pct(&mut o.startup, 99.0),
            pct(&mut o.steady, 50.0),
            pct(&mut o.steady, 95.0),
            pct(&mut o.steady, 99.0),
            pct(&mut o.steady, 100.0),
            o.lost_rpcs,
            o.goodput_mbps,
            o.drops_down,
            o.maxq_down / 1000,
        );
    }
    Ok(())
}
