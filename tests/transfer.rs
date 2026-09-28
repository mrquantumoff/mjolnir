use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use mjolnir::bitset::{AtomicBitset, PartState};
use mjolnir::crypto::REJECTED;
use mjolnir::filemap::Preserve;
use mjolnir::manifest::mtime_of;
use mjolnir::{
    Cancelled, Cipher, Phase, PrivateKey, Progress, PublicKey, Receiver, RecvConfig, RecvReport,
    SendConfig, SendReport,
};
use tempfile::TempDir;

const CHUNK: u32 = 16 << 10;
/// Crypto workers per side. `MJOLNIR_TEST_THREADS` overrides it, so the
/// whole suite can run at 1 and at 8 threads.
static THREADS: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
    std::env::var("MJOLNIR_TEST_THREADS").map_or(4, |v| v.parse().unwrap())
});

/// Deterministic pseudo-random bytes (xorshift), distinct per seed.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

struct RunningReceiver {
    addr: SocketAddr,
    public: PublicKey,
    progress: Arc<Progress>,
    handle: JoinHandle<Result<RecvReport>>,
}

fn recv_config(key: PrivateKey, authorized: Vec<PublicKey>, out: &Path) -> RecvConfig {
    RecvConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        key,
        authorized,
        out_dir: out.to_owned(),
        force: false,
        verify: true,
        threads: *THREADS,
        apply: Default::default(),
    }
}

fn start_receiver(key: PrivateKey, authorized: Vec<PublicKey>, out: &Path) -> RunningReceiver {
    start(recv_config(key, authorized, out))
}

fn start(cfg: RecvConfig) -> RunningReceiver {
    let receiver = Receiver::bind(cfg).unwrap();
    let progress = Arc::new(Progress::default());
    let (addr, public) = (receiver.local_addr(), receiver.public_key());
    let p = progress.clone();
    let handle = thread::spawn(move || receiver.run(p));
    RunningReceiver {
        addr,
        public,
        progress,
        handle,
    }
}

impl RunningReceiver {
    fn join(self) -> Result<RecvReport> {
        self.handle.join().unwrap()
    }

    /// Still serving after a failed session: give it a moment to settle.
    fn assert_waiting(&self) {
        thread::sleep(Duration::from_millis(200));
        assert!(!self.handle.is_finished(), "receiver exited");
        assert_eq!(self.progress.phase(), Phase::Connecting);
    }
}

struct Send {
    key: PrivateKey,
    peer: PublicKey,
    connections: usize,
    chunk_size: u32,
    cipher: Cipher,
    threads: usize,
    hash: bool,
    preserve: Preserve,
}

impl Send {
    fn to(key: PrivateKey, peer: PublicKey) -> Self {
        Send {
            key,
            peer,
            connections: 8,
            chunk_size: CHUNK,
            cipher: Cipher::Aes256Gcm,
            threads: *THREADS,
            hash: false,
            preserve: Preserve::default(),
        }
    }

    fn config(&self, addr: SocketAddr, paths: &[&Path]) -> SendConfig {
        SendConfig {
            addr: addr.to_string(),
            key: self.key.clone(),
            peer: self.peer,
            connections: self.connections,
            chunk_size: self.chunk_size,
            cipher: self.cipher,
            threads: self.threads,
            paths: paths.iter().map(|p| p.to_path_buf()).collect(),
            hash: self.hash,
            preserve: self.preserve,
        }
    }

    fn run(&self, addr: SocketAddr, paths: &[&Path]) -> Result<SendReport> {
        mjolnir::send(self.config(addr, paths), Arc::new(Progress::default()))
    }
}

fn keypair() -> (PrivateKey, PublicKey) {
    let k = PrivateKey::generate();
    let p = k.public_key();
    (k, p)
}

/// Every file under `dir`, relative, sorted.
fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = walkdir::WalkDir::new(dir)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(dir).unwrap();
            let rel = rel.to_str().unwrap().replace('\\', "/");
            (rel, fs::read(e.path()).unwrap())
        })
        .collect();
    out.sort();
    out
}

fn assert_file_eq(a: &Path, b: &Path) {
    let (x, y) = (fs::read(a).unwrap(), fs::read(b).unwrap());
    assert!(x == y, "{} differs from {}", a.display(), b.display());
}

#[test]
fn multiple_files_and_directories_both_ciphers() {
    let src = TempDir::new().unwrap();
    let data = src.path().join("data");
    write(&data.join("empty.bin"), b"");
    write(&data.join("one.bin"), b"x");
    write(&data.join("exact.bin"), &noise(4 * CHUNK as usize, 1));
    write(&data.join("odd.bin"), &noise(5 * CHUNK as usize + 123, 2));
    write(&data.join("nested/deeper/file.bin"), &noise(200_007, 3));
    write(&data.join("nested/empty-too"), b"");
    let single = src.path().join("single.txt");
    write(&single, &noise(CHUNK as usize - 1, 4));

    for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
        let out = TempDir::new().unwrap();
        let (rk, rpub) = keypair();
        let (sk, spub) = keypair();
        let rx = start_receiver(rk, vec![spub], out.path());
        let mut send = Send::to(sk, rx.public);
        send.cipher = cipher;
        let report = send.run(rx.addr, &[&data, &single]).unwrap();
        let recv = rx.join().unwrap();

        assert_eq!(recv.peer, send.key.public_key());
        assert_eq!(report.files, 7);
        assert_eq!(recv.files, 7);
        let total = 1 + 4 * CHUNK as u64 + 5 * CHUNK as u64 + 123 + 200_007 + CHUNK as u64 - 1;
        assert_eq!(report.bytes_sent, total);
        assert_eq!(recv.bytes_received, total);
        assert_eq!(recv.duplicate_chunks, 0);
        assert_eq!(report.chunks_resent, 0);
        assert_eq!(recv.repaired_chunks, 0);
        assert!(recv.verified && report.verified);
        assert_eq!(tree(&out.path().join("data")), tree(&data), "{cipher:?}");
        assert_file_eq(&single, &out.path().join("single.txt"));
        assert_eq!(tree(out.path()).len(), 7, "no leftover part or state files");
        let _ = rpub;
    }
}

#[test]
fn unauthorized_sender_is_dropped_and_receiver_keeps_waiting() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(100_000, 5));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (good, good_pub) = keypair();
    let (bad, _) = keypair();
    let rx = start_receiver(rk, vec![good_pub], out.path());

    let err = Send::to(bad, rx.public).run(rx.addr, &[&file]).unwrap_err();
    assert_eq!(err.to_string(), REJECTED);
    rx.assert_waiting();
    assert!(
        tree(out.path()).is_empty(),
        "no output after a rejected handshake"
    );

    Send::to(good, rx.public).run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert_file_eq(&file, &out.path().join("f.bin"));
}

#[test]
fn wrong_pinned_receiver_key_fails_and_receiver_keeps_waiting() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(50_000, 6));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());

    let (_, wrong) = keypair();
    let err = Send::to(sk.clone(), wrong)
        .run(rx.addr, &[&file])
        .unwrap_err();
    assert_eq!(err.to_string(), REJECTED);
    rx.assert_waiting();
    assert!(tree(out.path()).is_empty());

    Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert_file_eq(&file, &out.path().join("f.bin"));
}

/// Leaves `out` as an interrupted earlier session would for `file`:
/// chunks where `present(k)` hold the right bytes and digest and are marked
/// in the state file, and the rest hold garbage. Chunks in `rot` are marked
/// present with a valid digest, but their bytes are then corrupted, as a
/// disk fault would do. Returns the chunk count.
fn seed_resume(file: &Path, out: &Path, present: impl Fn(u64) -> bool, rot: &[u64]) -> u64 {
    let content = fs::read(file).unwrap();
    let chunks = (content.len() as u64).div_ceil(u64::from(CHUNK));
    let mut part = content.clone();
    let mut sums = vec![0u8; chunks as usize * 16];
    let have = AtomicBitset::new(chunks);
    for k in 0..chunks {
        let span = (k * CHUNK as u64) as usize
            ..((k + 1) * CHUNK as u64).min(content.len() as u64) as usize;
        if present(k) {
            have.set(k);
            let digest = blake3::hash(&content[span.clone()]);
            sums[k as usize * 16..][..16].copy_from_slice(&digest.as_bytes()[..16]);
        }
        if !present(k) || rot.contains(&k) {
            part[span].iter_mut().for_each(|b| *b ^= 0x5A);
        }
    }
    let name = file.file_name().unwrap().to_str().unwrap();
    fs::write(out.join(format!("{name}.mjolnir-part")), &part).unwrap();
    fs::write(out.join(format!("{name}.mjolnir-sums")), &sums).unwrap();
    PartState {
        size: content.len() as u64,
        mtime: mtime_of(&fs::metadata(file).unwrap()),
        chunk_size: CHUNK,
        bitmap: have.to_bytes(),
    }
    .save(&out.join(format!("{name}.mjolnir-state")))
    .unwrap();
    chunks
}

fn resume_source(src: &TempDir, chunks: u64, seed: u64) -> PathBuf {
    let file = src.path().join("big.bin");
    write(&file, &noise((chunks * CHUNK as u64) as usize - 1000, seed));
    file
}

#[test]
fn resume_sends_only_missing_chunks_and_rewrites_absent_bytes() {
    let src = TempDir::new().unwrap();
    let file = resume_source(&src, 32, 7);
    let out = TempDir::new().unwrap();
    let chunks = seed_resume(&file, out.path(), |k| k % 2 == 0, &[]);

    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let report = Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    let recv = rx.join().unwrap();

    assert_eq!(
        report.chunks_sent,
        chunks / 2,
        "present chunks are not re-sent"
    );
    assert_eq!(recv.chunks_received, chunks / 2);
    assert_eq!(recv.repaired_chunks, 0);
    assert_eq!(recv.duplicate_chunks, 0);
    assert_file_eq(&file, &out.path().join("big.bin"));
    for side in ["state", "part", "sums"] {
        assert!(!out.path().join(format!("big.bin.mjolnir-{side}")).exists());
    }
}

#[test]
fn verification_repairs_present_chunks_whose_bytes_rotted() {
    let src = TempDir::new().unwrap();
    let file = resume_source(&src, 32, 12);
    let out = TempDir::new().unwrap();
    let rot = [0, 6, 30];
    let chunks = seed_resume(&file, out.path(), |k| k % 2 == 0, &rot);

    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let report = Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    let recv = rx.join().unwrap();

    assert_eq!(recv.repaired_chunks, rot.len() as u64);
    assert_eq!(
        report.chunks_sent,
        chunks / 2 + rot.len() as u64,
        "only the missing and the rotted chunks travel"
    );
    assert_eq!(report.chunks_resent, 0);
    assert_eq!(report.rounds, 2);
    assert!(recv.verified && report.verified);
    assert_file_eq(&file, &out.path().join("big.bin"));
}

#[test]
fn verification_repairs_a_fully_present_resume() {
    let src = TempDir::new().unwrap();
    let file = resume_source(&src, 16, 13);
    let out = TempDir::new().unwrap();
    seed_resume(&file, out.path(), |_| true, &[3]);

    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let report = Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    let recv = rx.join().unwrap();

    assert_eq!(recv.repaired_chunks, 1);
    assert_eq!(report.chunks_sent, 1);
    assert_file_eq(&file, &out.path().join("big.bin"));
}

#[test]
fn no_verify_finishes_unverified() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(10 * CHUNK as usize + 3, 14));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let mut cfg = recv_config(rk, vec![spub], out.path());
    cfg.verify = false;
    let rx = start(cfg);
    let report = Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    let recv = rx.join().unwrap();
    assert!(!report.verified && !recv.verified);
    assert_file_eq(&file, &out.path().join("f.bin"));
}

#[test]
fn stale_state_is_ignored() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    let content = noise(4 * CHUNK as usize, 8);
    write(&file, &content);
    let out = TempDir::new().unwrap();
    fs::write(
        out.path().join("f.bin.mjolnir-part"),
        vec![0u8; content.len()],
    )
    .unwrap();
    PartState {
        size: content.len() as u64,
        mtime: 12345,
        chunk_size: CHUNK,
        bitmap: vec![0x0F],
    }
    .save(&out.path().join("f.bin.mjolnir-state"))
    .unwrap();

    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let report = Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert_eq!(report.chunks_sent, 4);
    assert_file_eq(&file, &out.path().join("f.bin"));
}

#[test]
fn more_connections_than_chunks() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("small.bin");
    write(&file, &noise(3 * CHUNK as usize - 5, 9));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.connections = 16;
    let report = send.run(rx.addr, &[&file]).unwrap();
    let recv = rx.join().unwrap();
    assert_eq!(report.chunks_sent, 3);
    assert_eq!(report.chunks_resent, 0);
    assert_eq!(recv.duplicate_chunks, 0);
    assert_file_eq(&file, &out.path().join("small.bin"));
}

#[test]
fn existing_target_fails_the_session_without_force() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, b"new");
    let out = TempDir::new().unwrap();
    fs::write(out.path().join("f.bin"), b"old").unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let err = Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap_err();
    assert!(format!("{err:#}").contains("already exists"), "{err:#}");
    rx.assert_waiting();
    assert_eq!(fs::read(out.path().join("f.bin")).unwrap(), b"old");
    rx.progress.cancel();
    assert!(rx.join().unwrap_err().is::<Cancelled>());
}

/// Sets `progress.cancel` once `trigger` sees enough bytes moved.
fn cancel_when(progress: Arc<Progress>, bytes: u64) -> JoinHandle<Instant> {
    thread::spawn(move || {
        while progress.bytes_done.load(Relaxed) < bytes {
            thread::sleep(Duration::from_micros(200));
        }
        progress.cancel();
        Instant::now()
    })
}

fn big_source(src: &TempDir, mib: usize) -> PathBuf {
    let file = src.path().join("big.bin");
    write(&file, &noise(mib << 20, 10));
    file
}

#[test]
fn sender_cancel_is_prompt_and_a_second_send_resumes() {
    let src = TempDir::new().unwrap();
    let file = big_source(&src, 64);
    let total_chunks = (64u64 << 20) / u64::from(CHUNK);
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.connections = 4;

    let progress = Arc::new(Progress::default());
    let cancelled_at = cancel_when(progress.clone(), 8 << 20);
    let err = mjolnir::send(send.config(rx.addr, &[&file]), progress.clone()).unwrap_err();
    let latency = cancelled_at.join().unwrap().elapsed();
    assert_eq!(
        err.downcast_ref::<Cancelled>(),
        Some(&Cancelled::Local),
        "{err:#}"
    );
    assert!(
        latency < Duration::from_secs(2),
        "sender took {latency:?} to stop"
    );
    assert_eq!(progress.phase(), Phase::Failed);

    rx.assert_waiting();
    assert!(out.path().join("big.bin.mjolnir-part").exists());

    let report = send.run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert!(
        report.chunks_sent > 0 && report.chunks_sent < total_chunks,
        "resumed run sent {} of {total_chunks} chunks",
        report.chunks_sent
    );
    assert_file_eq(&file, &out.path().join("big.bin"));
}

#[test]
fn receiver_cancel_is_prompt_and_a_new_receiver_resumes() {
    let src = TempDir::new().unwrap();
    let file = big_source(&src, 64);
    let total_chunks = (64u64 << 20) / u64::from(CHUNK);
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk.clone(), vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.connections = 4;

    let cancelled_at = cancel_when(rx.progress.clone(), 8 << 20);
    let sent = send.run(rx.addr, &[&file]);
    let recv = rx.join();
    let latency = cancelled_at.join().unwrap().elapsed();
    let recv_err = recv.unwrap_err();
    assert_eq!(
        recv_err.downcast_ref::<Cancelled>(),
        Some(&Cancelled::Local)
    );
    let sent_err = sent.unwrap_err();
    assert_eq!(
        sent_err.downcast_ref::<Cancelled>(),
        Some(&Cancelled::Peer),
        "{sent_err:#}"
    );
    assert!(
        latency < Duration::from_secs(2),
        "both sides took {latency:?} to stop"
    );

    let rx = start_receiver(rk, vec![spub], out.path());
    let report = send.run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert!(report.chunks_sent < total_chunks, "second run resumed");
    assert_file_eq(&file, &out.path().join("big.bin"));
}

#[test]
fn source_changed_during_transfer_fails_the_sender() {
    let src = TempDir::new().unwrap();
    let file = big_source(&src, 32);
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.connections = 1;

    let progress = Arc::new(Progress::default());
    let touch = {
        let (progress, file) = (progress.clone(), file.clone());
        thread::spawn(move || {
            while progress.chunks_done.load(Relaxed) == 0 {
                thread::sleep(Duration::from_micros(100));
            }
            let later = SystemTime::now() + Duration::from_secs(3600);
            fs::File::options()
                .write(true)
                .open(&file)
                .unwrap()
                .set_modified(later)
                .unwrap();
        })
    };
    let err = mjolnir::send(send.config(rx.addr, &[&file]), progress).unwrap_err();
    touch.join().unwrap();
    assert!(
        err.to_string()
            .contains("source file changed during transfer"),
        "{err:#}"
    );
    rx.assert_waiting();
    assert!(!out.path().join("big.bin").exists());
    rx.progress.cancel();
    assert!(rx.join().unwrap_err().is::<Cancelled>());
}

#[test]
fn a_stalled_handshake_does_not_block_a_real_sender() {
    use std::io::Write;
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(50_000, 11));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());

    let mut stall = std::net::TcpStream::connect(rx.addr).unwrap();
    stall.write_all(b"MJLN\x01\x00\xff").unwrap();
    thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_file_eq(&file, &out.path().join("f.bin"));
    drop(stall);
}

#[test]
fn a_second_control_connection_is_closed_during_a_session() {
    use std::io::{Read, Write};
    let src = TempDir::new().unwrap();
    let file = big_source(&src, 64);
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.connections = 2;
    let progress = Arc::new(Progress::default());
    let sender = {
        let (cfg, progress) = (send.config(rx.addr, &[&file]), progress.clone());
        thread::spawn(move || mjolnir::send(cfg, progress))
    };
    while rx.progress.phase() != Phase::Transferring {
        thread::sleep(Duration::from_millis(1));
    }

    let mut second = std::net::TcpStream::connect(rx.addr).unwrap();
    second.write_all(b"MJLN\x01\x00").unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buf = [0u8; 1];
    let closed = match second.read(&mut buf) {
        Ok(n) => n == 0,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    };
    assert!(closed, "second control connection was answered");

    sender.join().unwrap().unwrap();
    rx.join().unwrap();
    assert_file_eq(&file, &out.path().join("big.bin"));
}

#[test]
fn receiver_cancel_is_prompt_with_a_silent_connection_pending() {
    use std::io::Write;
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (_, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut silent = std::net::TcpStream::connect(rx.addr).unwrap();
    silent.write_all(b"MJLN\x01\x00").unwrap();
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    rx.progress.cancel();
    let err = rx.join().unwrap_err();
    let latency = started.elapsed();
    assert_eq!(err.downcast_ref::<Cancelled>(), Some(&Cancelled::Local));
    // The receiver returns at its next 5 ms accept poll, joining nothing;
    // the rest is waiting for a CPU. On a loaded Windows runner a 5 ms
    // sleep has overrun by 845 ms and this cancel took 2.1 s, so the bound
    // sits well above that and well below the 10 s handshake deadline a
    // receiver blocked on the silent peer would wait out.
    assert!(latency < Duration::from_secs(5), "cancel took {latency:?}");
}

#[test]
fn one_connection_many_workers_completes_out_of_order() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(2000 * 4096 + 17, 15));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let mut cfg = recv_config(rk, vec![spub], out.path());
    cfg.threads = 8;
    let rx = start(cfg);
    let mut send = Send::to(sk, rx.public);
    send.connections = 1;
    send.threads = 8;
    send.chunk_size = 4096;
    let report = send.run(rx.addr, &[&file]).unwrap();
    let recv = rx.join().unwrap();
    assert_eq!(report.chunks_sent, 2001);
    assert_eq!(recv.chunks_received, 2001);
    assert_eq!(recv.duplicate_chunks, 0);
    assert_file_eq(&file, &out.path().join("f.bin"));
}

#[test]
fn many_chunks_over_two_connections_arrive_once() {
    let src = TempDir::new().unwrap();
    let file = big_source(&src, 96);
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let mut cfg = recv_config(rk, vec![spub], out.path());
    cfg.threads = 2;
    let rx = start(cfg);
    let mut send = Send::to(sk, rx.public);
    send.connections = 2;
    send.threads = 8;
    send.chunk_size = 4096;
    let progress = Arc::new(Progress::default());
    let report = mjolnir::send(send.config(rx.addr, &[&file]), progress.clone()).unwrap();
    let recv = rx.join().unwrap();
    let chunks = (96u64 << 20) / 4096;
    assert_eq!(report.chunks_sent, chunks);
    assert_eq!(report.chunks_resent, 0);
    assert_eq!(recv.duplicate_chunks, 0);
    let p = progress.snapshot();
    assert_eq!((p.bytes_done, p.chunks_done), (96 << 20, chunks));
    // The sender's transfer phase lasts until the receiver has absorbed the
    // round, so it is never much shorter than the receiver's.
    let slack = Duration::from_millis(50);
    assert!(
        report.phase_times.transfer + slack >= recv.phase_times.transfer,
        "sender {:?} vs receiver {:?}",
        report.phase_times,
        recv.phase_times
    );
    assert!(
        !report.phase_times.verify.is_zero(),
        "the sender sees the verify phase"
    );
    assert_file_eq(&file, &out.path().join("big.bin"));
}

/// A receiver that admits one data connection and then never reads from
/// it, so the sender's writes block.
fn stalled_receiver(key: PrivateKey, sender: PublicKey) -> (SocketAddr, JoinHandle<()>) {
    use mjolnir::crypto::handshake_responder;
    use mjolnir::wire::{self, ADMITTED, Msg, Role};
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut control, _) = listener.accept().unwrap();
        wire::read_preamble(&mut control).unwrap();
        let (keys, _) = handshake_responder(&mut control, &key, &[sender]).unwrap();
        let (mut tx, mut rx) = wire::control_channel(
            control.try_clone().unwrap(),
            control.try_clone().unwrap(),
            &keys,
            Role::Receiver,
        );
        let Msg::Offer {
            files, chunk_size, ..
        } = rx.recv().unwrap()
        else {
            panic!("expected Offer")
        };
        let bitmaps = files
            .iter()
            .map(|f| vec![0u8; f.size.div_ceil(u64::from(chunk_size)).div_ceil(8) as usize])
            .collect();
        tx.send(&Msg::Have { bitmaps }).unwrap();
        let (mut data, _) = listener.accept().unwrap();
        wire::read_preamble(&mut data).unwrap();
        data.write_all(&[9u8; 32]).unwrap();
        let mut hello = [0u8; 40];
        data.read_exact(&mut hello).unwrap();
        data.write_all(&[ADMITTED]).unwrap();
        thread::sleep(Duration::from_secs(5));
        drop((data, control));
    });
    (addr, handle)
}

#[test]
fn cancel_is_prompt_while_the_receiver_stops_reading() {
    let src = TempDir::new().unwrap();
    let file = big_source(&src, 64);
    let (rk, rpub) = keypair();
    let (sk, spub) = keypair();
    let (addr, fake) = stalled_receiver(rk, spub);
    let mut send = Send::to(sk, rpub);
    send.connections = 1;
    let progress = Arc::new(Progress::default());
    let canceller = {
        let progress = progress.clone();
        thread::spawn(move || {
            while progress.bytes_done.load(Relaxed) == 0 {
                thread::sleep(Duration::from_millis(1));
            }
            thread::sleep(Duration::from_millis(500));
            progress.cancel();
            Instant::now()
        })
    };
    let err = mjolnir::send(send.config(addr, &[&file]), progress).unwrap_err();
    let latency = canceller.join().unwrap().elapsed();
    assert_eq!(err.downcast_ref::<Cancelled>(), Some(&Cancelled::Local));
    assert!(latency < Duration::from_secs(1), "cancel took {latency:?}");
    fake.join().unwrap();
}

#[test]
fn empty_directories_arrive() {
    let src = TempDir::new().unwrap();
    let tree = src.path().join("tree");
    fs::create_dir_all(tree.join("a/b/c")).unwrap();
    fs::create_dir_all(tree.join("empty")).unwrap();
    write(&tree.join("a/file.bin"), &noise(5000, 16));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let report = Send::to(sk, rx.public).run(rx.addr, &[&tree]).unwrap();
    let recv = rx.join().unwrap();
    assert!(report.warnings.is_empty() && recv.warnings.is_empty());
    for dir in ["tree/a/b/c", "tree/empty"] {
        assert!(out.path().join(dir).is_dir(), "{dir} missing");
    }
    assert_file_eq(
        &tree.join("a/file.bin"),
        &out.path().join("tree/a/file.bin"),
    );
}

#[test]
fn hash_check_reports_equal_file_hashes() {
    let src = TempDir::new().unwrap();
    let data = src.path().join("data");
    write(&data.join("one.bin"), &noise(7 * CHUNK as usize + 11, 17));
    write(&data.join("empty.bin"), b"");
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.hash = true;
    let report = send.run(rx.addr, &[&data]).unwrap();
    let recv = rx.join().unwrap();
    assert!(report.hashed && recv.hashed);
    assert_eq!(report.hash_repaired_chunks, 0);
    assert_eq!(recv.hash_repaired_chunks, 0);
    assert_eq!(report.file_hashes.len(), 2);
    assert_eq!(report.file_hashes, recv.file_hashes);
    assert_ne!(report.file_hashes[0].1, report.file_hashes[1].1);
}

#[test]
fn hash_check_repairs_a_source_changed_behind_size_and_mtime() {
    let src = TempDir::new().unwrap();
    let file = resume_source(&src, 16, 18);
    let out = TempDir::new().unwrap();
    seed_resume(&file, out.path(), |_| true, &[]);

    let mtime = fs::metadata(&file).unwrap().modified().unwrap();
    let mut changed = fs::read(&file).unwrap();
    changed[5 * CHUNK as usize + 3] ^= 0xFF;
    fs::write(&file, &changed).unwrap();
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.hash = true;
    let report = send.run(rx.addr, &[&file]).unwrap();
    let recv = rx.join().unwrap();
    assert_eq!(
        recv.repaired_chunks, 0,
        "the old bytes still match their digests"
    );
    assert_eq!(recv.hash_repaired_chunks, 1);
    assert_eq!(report.hash_repaired_chunks, 1);
    assert_eq!(report.chunks_sent, 1, "only the changed chunk travels");
    assert_eq!(report.file_hashes, recv.file_hashes);
    assert_eq!(fs::read(out.path().join("big.bin")).unwrap(), changed);
}

/// `a:b.` as the local file system can hold it: literally on Unix, with the
/// `:` and the trailing `.` escaped into U+F000 + byte on Windows.
fn awkward_name() -> &'static str {
    if cfg!(windows) {
        "a\u{F03A}b\u{F02E}"
    } else {
        "a:b."
    }
}

#[test]
fn awkward_names_round_trip() {
    let src = TempDir::new().unwrap();
    let file = src.path().join(awkward_name());
    write(&file, &noise(3000, 19));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.hash = true;
    let report = send.run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert_eq!(
        report.file_hashes[0].0, "a:b.",
        "the wire name is the raw name"
    );
    assert_file_eq(&file, &out.path().join(awkward_name()));
}

#[cfg(unix)]
#[test]
fn perms_times_and_non_utf8_names_arrive_on_unix() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let src = TempDir::new().unwrap();
    let dir = src.path().join("d");
    let odd = dir.join(OsStr::from_bytes(b"caf\xe9.bin"));
    write(&odd, &noise(4000, 20));
    fs::set_permissions(&odd, fs::Permissions::from_mode(0o640)).unwrap();
    let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    fs::File::options()
        .write(true)
        .open(&odd)
        .unwrap()
        .set_modified(when)
        .unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();

    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk, vec![spub], out.path());
    let mut send = Send::to(sk, rx.public);
    send.preserve = "perms,times".parse().unwrap();
    send.run(rx.addr, &[&dir]).unwrap();
    let recv = rx.join().unwrap();
    assert!(recv.warnings.is_empty(), "{:?}", recv.warnings);
    let got = out.path().join("d").join(OsStr::from_bytes(b"caf\xe9.bin"));
    assert_file_eq(&odd, &got);
    let meta = fs::metadata(&got).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o640);
    assert_eq!(meta.modified().unwrap(), when);
    let dmode = fs::metadata(out.path().join("d"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(dmode & 0o7777, 0o750);
}

/// A TCP proxy to `target` that also keeps the first `keep` bytes the first
/// client sends.
fn recording_proxy(
    target: SocketAddr,
    keep: usize,
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rec = recorded.clone();
    thread::spawn(move || {
        for (i, client) in listener.incoming().enumerate() {
            let Ok(client) = client else { return };
            let Ok(server) = TcpStream::connect(target) else {
                return;
            };
            let pipe = |mut from: TcpStream,
                        mut to: TcpStream,
                        record: Option<Arc<std::sync::Mutex<Vec<u8>>>>| {
                thread::spawn(move || {
                    let mut buf = [0u8; 64 << 10];
                    while let Ok(n) = from.read(&mut buf) {
                        if n == 0 || to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        if let Some(r) = &record {
                            let mut r = r.lock().unwrap();
                            let room = keep.saturating_sub(r.len()).min(n);
                            r.extend_from_slice(&buf[..room]);
                        }
                    }
                    let _ = to.shutdown(Shutdown::Write);
                });
            };
            pipe(
                client.try_clone().unwrap(),
                server.try_clone().unwrap(),
                (i == 0).then(|| rec.clone()),
            );
            pipe(server, client, None);
        }
    });
    (addr, recorded)
}

#[test]
fn a_silent_replayed_handshake_does_not_hold_the_receiver() {
    use std::io::Write;
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(20_000, 21));
    let (rk, rpub) = keypair();
    let (sk, spub) = keypair();

    let first = TempDir::new().unwrap();
    let rx = start(recv_config(rk.clone(), vec![spub], first.path()));
    let (proxy, recorded) = recording_proxy(rx.addr, 6 + 2 + 96);
    Send::to(sk.clone(), rpub).run(proxy, &[&file]).unwrap();
    rx.join().unwrap();
    let preamble_and_msg1 = recorded.lock().unwrap().clone();
    assert_eq!(preamble_and_msg1.len(), 104);

    let second = TempDir::new().unwrap();
    let rx = start(recv_config(rk, vec![spub], second.path()));
    let mut replay = std::net::TcpStream::connect(rx.addr).unwrap();
    replay.write_all(&preamble_and_msg1).unwrap();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(25));
        drop(replay);
    });
    thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    Send::to(sk, rpub).run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_secs(5),
        "real sender waited {waited:?}"
    );
    assert_file_eq(&file, &second.path().join("f.bin"));
}

#[test]
fn idle_connections_neither_block_a_sender_nor_pile_up() {
    use std::io::Read;
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(30_000, 22));
    let out = TempDir::new().unwrap();
    let (rk, _) = keypair();
    let (sk, spub) = keypair();
    let rx = start_receiver(rk.clone(), vec![spub], out.path());
    let idle: Vec<_> = (0..200)
        .map(|_| std::net::TcpStream::connect(rx.addr).unwrap())
        .collect();
    thread::sleep(Duration::from_millis(200));
    Send::to(sk, rx.public).run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    assert_file_eq(&file, &out.path().join("f.bin"));
    drop(idle);

    let spare = TempDir::new().unwrap();
    let rx = start_receiver(rk, vec![spub], spare.path());
    let flood: Vec<_> = (0..300)
        .map(|_| std::net::TcpStream::connect(rx.addr).unwrap())
        .collect();
    thread::sleep(Duration::from_millis(500));
    let closed = flood
        .into_iter()
        .filter(|s| {
            s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            matches!((&*s).read(&mut [0u8; 1]), Ok(0))
                || matches!((&*s).read(&mut [0u8; 1]), Err(e) if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut)
        })
        .count();
    assert!(
        closed >= 300 - 256,
        "only {closed} over-limit connections were closed"
    );
    rx.progress.cancel();
    assert!(rx.join().unwrap_err().is::<Cancelled>());
}

#[test]
fn a_replay_loop_never_takes_the_session_from_a_real_sender() {
    use std::io::Write;
    use std::sync::atomic::AtomicBool;
    let src = TempDir::new().unwrap();
    let file = src.path().join("f.bin");
    write(&file, &noise(20_000, 23));
    let (rk, rpub) = keypair();
    let (sk, spub) = keypair();

    let first = TempDir::new().unwrap();
    let rx = start(recv_config(rk.clone(), vec![spub], first.path()));
    let (proxy, recorded) = recording_proxy(rx.addr, 6 + 2 + 96);
    Send::to(sk.clone(), rpub).run(proxy, &[&file]).unwrap();
    rx.join().unwrap();
    let msg1 = recorded.lock().unwrap().clone();

    let second = TempDir::new().unwrap();
    let rx = start(recv_config(rk, vec![spub], second.path()));
    let stop = Arc::new(AtomicBool::new(false));
    let replayer = {
        let (stop, addr) = (stop.clone(), rx.addr);
        thread::spawn(move || {
            let mut held = Vec::new();
            while !stop.load(Relaxed) {
                if let Ok(mut s) = std::net::TcpStream::connect(addr) {
                    let _ = s.write_all(&msg1);
                    held.push(s);
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    thread::sleep(Duration::from_millis(350));
    let started = Instant::now();
    Send::to(sk, rpub).run(rx.addr, &[&file]).unwrap();
    rx.join().unwrap();
    let waited = started.elapsed();
    stop.store(true, Relaxed);
    replayer.join().unwrap();
    assert!(
        waited < Duration::from_secs(5),
        "real sender waited {waited:?}"
    );
    assert_file_eq(&file, &second.path().join("f.bin"));
}
