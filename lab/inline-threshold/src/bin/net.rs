//! Time to deliver an artefact of S bytes to the receiver, inline versus by blob reference, over quinn
//! through an emulated bottleneck (same userspace link model as lab/quic-control-latency), and the extra
//! latency it causes for concurrent small control RPCs on the `webway/0` connection.
//!
//! Modes:
//!   inline   one response on a warm control connection: envelope (1.7 kB) + base64(S)
//!   inline-fresh  inline on a fresh connection that carried only 3 small RPCs (cwnd = initial window)
//!   ref-open small envelope on the control connection, then a fetch on an already-open, idle blob connection
//!   ref-hot  as ref-open, but the blob connection carried an 8 MiB blob before (grown cwnd, no idle reset)
//!   ref-new  small envelope, then a new QUIC connection (1-RTT handshake, no 0-RTT) and the fetch
//! Blob responses are S*(1+1/256)+8 bytes (bao, 16 KiB groups). Fetch requests carry a 700 B capability.
//! Background: a 512 B / 2 KiB control RPC every 50 ms on the control connection.
//!
//! Usage: net [reps] [filter]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

const UDP_IP_OVERHEAD: usize = 28;
const ENV_BYTES: usize = 1700;
const CAP_BYTES: usize = 700;

#[derive(Clone, Copy)]
struct Path { name: &'static str, rate: f64, one_way_ms: u64, buffer: usize }

struct Link { next_free: Mutex<Instant>, buffer: usize, rate: f64, one_way: Duration, tx: mpsc::UnboundedSender<(Instant, Vec<u8>)> }

impl Link {
    fn new(p: Path, out: Arc<UdpSocket>, dst: Arc<Mutex<Option<SocketAddr>>>) -> Arc<Self> {
        let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        tokio::spawn(async move {
            while let Some((at, pkt)) = rx.recv().await {
                tokio::time::sleep_until(at).await;
                let d = *dst.lock().unwrap();
                if let Some(d) = d { let _ = out.send_to(&pkt, d).await; }
            }
        });
        Arc::new(Link { next_free: Mutex::new(Instant::now()), buffer: p.buffer, rate: p.rate,
            one_way: Duration::from_millis(p.one_way_ms), tx })
    }
    fn enqueue(&self, pkt: Vec<u8>) {
        let now = Instant::now();
        let wire = pkt.len() + UDP_IP_OVERHEAD;
        let mut nf = self.next_free.lock().unwrap();
        let start = if *nf > now { *nf } else { now };
        let backlog = ((start - now).as_secs_f64() * self.rate / 8.0) as usize;
        if backlog + wire > self.buffer { return; }
        let done = start + Duration::from_secs_f64(wire as f64 * 8.0 / self.rate);
        *nf = done;
        let _ = self.tx.send((done + self.one_way, pkt));
    }
}

/// One UDP proxy per client socket address pair is not needed: the proxy forwards to the last client
/// address seen, and all client connections share one client endpoint (one UDP socket).
async fn proxy(server: SocketAddr, p: Path) -> Result<SocketAddr> {
    let c_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let s_side = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client_addr = Arc::new(Mutex::new(None));
    let up = Link::new(p, s_side.clone(), Arc::new(Mutex::new(Some(server))));
    let down = Link::new(p, c_side.clone(), client_addr.clone());
    { let c_side = c_side.clone(); tokio::spawn(async move { let mut buf = vec![0u8; 65536];
        loop { let Ok((n, from)) = c_side.recv_from(&mut buf).await else { return };
            *client_addr.lock().unwrap() = Some(from); up.enqueue(buf[..n].to_vec()); } }); }
    { let s_side = s_side.clone(); tokio::spawn(async move { let mut buf = vec![0u8; 65536];
        loop { let Ok((n, _)) = s_side.recv_from(&mut buf).await else { return };
            down.enqueue(buf[..n].to_vec()); } }); }
    Ok(c_side.local_addr()?)
}

fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(1000u32.into());
    t.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    Arc::new(t)
}

fn configs() -> Result<(ServerConfig, ClientConfig)> {
    let cert = rcgen::generate_simple_self_signed(vec!["webway".into()])?;
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let mut sc = ServerConfig::with_single_cert(vec![der.clone()], key)?;
    sc.transport_config(transport());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der)?;
    let mut cc = ClientConfig::with_root_certificates(Arc::new(roots))?;
    cc.transport_config(transport());
    Ok((sc, cc))
}

fn inline_len(s: usize) -> usize { ENV_BYTES + s.div_ceil(3) * 4 }
fn blob_len(s: usize) -> usize { s + s / 256 + 8 }

async fn serve(ep: Endpoint) {
    while let Some(inc) = ep.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = inc.await else { return };
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                tokio::spawn(async move {
                    let Ok(req) = recv.read_to_end(1 << 16).await else { return };
                    let size: usize = std::str::from_utf8(&req[1..req.iter().position(|&c| c == b';').unwrap_or(1)])
                        .ok().and_then(|s| s.parse().ok()).unwrap_or(0);
                    let n = match req[0] { b'C' => 2048, b'I' => inline_len(size), b'R' => ENV_BYTES, b'F' => blob_len(size), _ => 0 };
                    let _ = send.write_all(&vec![0xAB; n]).await;
                    let _ = send.finish();
                    let _ = send.stopped().await;
                });
            }
        });
    }
}

async fn rpc(conn: &quinn::Connection, tag: u8, size: usize, pad: usize) -> Result<usize> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut req = format!("{}{};", tag as char, size).into_bytes();
    req.resize(req.len().max(pad), b' ');
    send.write_all(&req).await?;
    send.finish()?;
    Ok(recv.read_to_end(64 << 20).await?.len())
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() { return f64::NAN; }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((p / 100.0) * (v.len() - 1) as f64).round() as usize]
}

async fn run(p: Path, mode: &str, sizes: &[usize], reps: usize) -> Result<()> {
    let (sc, cc) = configs()?;
    let server = Endpoint::server(sc, "127.0.0.1:0".parse()?)?;
    tokio::spawn(serve(server.clone()));
    let paddr = proxy(server.local_addr()?, p).await?;
    let mut client = Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(cc);
    let conn = client.connect(paddr, "webway")?.await?;
    let bconn = client.connect(paddr, "webway")?.await?;
    // warm up both connections with a few small exchanges (handshake, RTT estimate), not bulk
    for _ in 0..5 { rpc(&conn, b'C', 0, 512).await?; rpc(&bconn, b'C', 0, 512).await?; }
    if mode == "ref-hot" { rpc(&bconn, b'F', 8 << 20, CAP_BYTES).await?; tokio::time::sleep(Duration::from_millis(500)).await; }

    let t0 = Instant::now();
    let ctl: Arc<Mutex<Vec<(f64, f64)>>> = Arc::default();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (conn, ctl, stop) = (conn.clone(), ctl.clone(), stop.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                tick.tick().await;
                let (conn, ctl) = (conn.clone(), ctl.clone());
                tokio::spawn(async move {
                    let st = Instant::now();
                    if rpc(&conn, b'C', 0, 512).await.is_ok() {
                        ctl.lock().unwrap().push(((st - t0).as_secs_f64(), st.elapsed().as_secs_f64() * 1e3));
                    }
                });
            }
        });
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let rtt = 2.0 * p.one_way_ms as f64;
    for &s in sizes {
        let mut d = vec![]; let mut windows = vec![];
        for _ in 0..reps {
            let st = Instant::now();
            match mode {
                "inline" => { let n = rpc(&conn, b'I', s, 0).await?; assert_eq!(n, inline_len(s)); }
                "inline-fresh" => {
                    // timing starts after a fresh connection did 3 small RPCs (handshake + RTT estimate, cwnd = initial)
                    let c = client.connect(paddr, "webway")?.await?;
                    for _ in 0..3 { rpc(&c, b'C', 0, 512).await?; }
                    let st2 = Instant::now();
                    let n = rpc(&c, b'I', s, 0).await?; assert_eq!(n, inline_len(s));
                    c.close(0u32.into(), b"");
                    let ms = st2.elapsed().as_secs_f64() * 1e3;
                    d.push(ms);
                    windows.push(((st2 - t0).as_secs_f64(), (st2 - t0).as_secs_f64() + ms / 1e3));
                    let xfer = s as f64 * 8.0 / p.rate;
                    tokio::time::sleep(Duration::from_secs_f64(0.6 + 1.0 * xfer + 4.0 * rtt / 1e3)).await;
                    continue;
                }
                _ => {
                    rpc(&conn, b'R', s, 0).await?;
                    let c = if mode == "ref-new" { client.connect(paddr, "webway")?.await? } else { bconn.clone() };
                    let n = rpc(&c, b'F', s, CAP_BYTES).await?;
                    assert_eq!(n, blob_len(s));
                    if mode == "ref-new" { c.close(0u32.into(), b""); }
                }
            }
            let ms = st.elapsed().as_secs_f64() * 1e3;
            d.push(ms);
            windows.push(((st - t0).as_secs_f64(), (st - t0).as_secs_f64() + ms / 1e3));
            let xfer = s as f64 * 8.0 / p.rate;
            tokio::time::sleep(Duration::from_secs_f64(0.6 + 1.0 * xfer + 4.0 * rtt / 1e3)).await;
        }
        tokio::time::sleep(Duration::from_millis(300 + 2 * rtt as u64)).await;
        // control RPCs that started during a transfer
        let all = ctl.lock().unwrap().clone();
        let mut during: Vec<f64> = all.iter().filter(|(a, _)| windows.iter().any(|(b, e)| a >= b && a <= e)).map(|x| x.1).collect();
        let mut idle: Vec<f64> = all.iter().filter(|(a, _)| !windows.iter().any(|(b, e)| *a >= b - 0.2 && *a <= e + 0.5)).map(|x| x.1).collect();
        let ideal = rtt + s as f64 * 8.0 / p.rate * 1e3;
        println!("{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.2}\t{:.1}\t{:.1}\t{:.1}\t{}",
            p.name, mode, s, pct(&mut d, 50.0), pct(&mut d, 90.0), pct(&mut d, 100.0), ideal,
            pct(&mut d, 50.0) / rtt, pct(&mut idle, 50.0), pct(&mut during.clone(), 50.0), pct(&mut during, 100.0), during.len());
        ctl.lock().unwrap().clear();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    conn.close(0u32.into(), b""); bconn.close(0u32.into(), b"");
    client.close(0u32.into(), b""); server.close(0u32.into(), b"");
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let reps: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let filter = std::env::args().nth(2).unwrap_or_default();
    let bdp = |r: f64, ow: u64| ((r / 8.0 * 2.0 * ow as f64 / 1e3) as usize).max(64 << 10);
    let paths = [
        Path { name: "100M-20ms", rate: 100e6, one_way_ms: 10, buffer: bdp(100e6, 10) },
        Path { name: "20M-60ms", rate: 20e6, one_way_ms: 30, buffer: bdp(20e6, 30) },
        Path { name: "20M-60ms-relay1MB", rate: 20e6, one_way_ms: 30, buffer: 1 << 20 },
        Path { name: "5M-200ms", rate: 5e6, one_way_ms: 100, buffer: bdp(5e6, 100) },
    ];
    let sizes = [4usize << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20];
    println!("path\tmode\tsize\tp50_ms\tp90_ms\tmax_ms\tideal_ms\tp50_rtts\tctl_idle_p50\tctl_during_p50\tctl_during_max\tctl_n");
    for p in paths {
        for mode in ["inline", "inline-fresh", "ref-open", "ref-new", "ref-hot"] {
            if !format!("{}/{}", p.name, mode).contains(&filter) { continue; }
            run(p, mode, &sizes, reps).await?;
        }
    }
    Ok(())
}
