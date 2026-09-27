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
use mjolnir::manifest::mtime_of;
use mjolnir::{
    Cancelled, Cipher, Phase, PrivateKey, Progress, PublicKey, Receiver, RecvConfig, RecvReport,
    SendConfig, SendReport,
};
use tempfile::TempDir;

const CHUNK: u32 = 16 << 10;

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
}

impl Send {
    fn to(key: PrivateKey, peer: PublicKey) -> Self {
        Send {
            key,
            peer,
            connections: 8,
            chunk_size: CHUNK,
            cipher: Cipher::Aes256Gcm,
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
            paths: paths.iter().map(|p| p.to_path_buf()).collect(),
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
    assert_eq!(err.downcast_ref::<Cancelled>(), Some(&Cancelled::Local));
    assert!(started.elapsed() < Duration::from_secs(1));
}
