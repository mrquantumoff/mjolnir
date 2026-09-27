use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use mjolnir::filemap::{ApplyPolicy, Preserve};
use mjolnir::{
    Cipher, Phase, PrivateKey, Progress, PublicKey, Receiver, RecvConfig, SendConfig,
    load_authorized_keys, parse_size, web,
};

#[derive(Parser)]
#[command(
    version,
    about = "Fast authenticated file transfer over parallel TCP connections"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a private key file and print its public key.
    Keygen {
        #[arg(long, default_value = "mjolnir.key")]
        out: PathBuf,
    },
    /// Print the public key of an existing private key file.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Receive one transfer from an authorized sender.
    Recv {
        #[arg(long)]
        key: PathBuf,
        /// File of authorized sender keys, one `<base64> [comment]` per line.
        #[arg(long)]
        authorized: Option<PathBuf>,
        /// Authorize a sender public key (repeatable).
        #[arg(long)]
        allow: Vec<PublicKey>,
        #[arg(long, default_value = "0.0.0.0:7777")]
        listen: SocketAddr,
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
        /// Skip reading every chunk back to check its digest.
        #[arg(long)]
        no_verify: bool,
        /// Workers that decrypt, write, and verify chunks (0 = one per core).
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Apply file owners from the sender's map (only as root on Unix).
        #[arg(long)]
        allow_owner: bool,
        /// Keep setuid, setgid, and sticky bits from the sender's map.
        #[arg(long)]
        allow_special_bits: bool,
    },
    /// Send files or directories to a receiver.
    Send {
        /// Receiver address, HOST:PORT.
        addr: String,
        #[arg(long)]
        key: PathBuf,
        /// The receiver's public key.
        #[arg(long)]
        peer: PublicKey,
        /// Parallel data connections.
        #[arg(short = 'n', long, default_value_t = 8)]
        connections: usize,
        /// Chunk size, e.g. 256K, 1MiB, 4M (4 KiB to 64 MiB).
        #[arg(short = 'c', long, default_value = "1MiB", value_parser = parse_size)]
        chunk_size: u32,
        #[arg(long, value_enum, default_value_t = Cipher::Aes256Gcm)]
        cipher: Cipher,
        /// Workers that read and encrypt chunks (0 = one per core).
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// After delivery, re-read every file and have the receiver compare
        /// chunk digests; mismatched chunks are sent again.
        #[arg(long)]
        hash: bool,
        /// Metadata to send: `none`, or a list of perms, times, owner.
        #[arg(long, default_value = "perms")]
        preserve: Preserve,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Serve the local web UI.
    Serve {
        #[arg(long, default_value = "127.0.0.1:7878")]
        listen: SocketAddr,
        /// Private key file; defaults to the per-user config directory and is
        /// created there if missing.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Do not open a browser.
        #[arg(long)]
        no_open: bool,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse().cmd) {
        eprintln!("mjolnir: error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Keygen { out } => {
            let key = PrivateKey::generate();
            key.save(&out)?;
            eprintln!("wrote private key to {}", out.display());
            println!("{}", key.public_key());
        }
        Cmd::Pubkey { key } => println!("{}", PrivateKey::load(&key)?.public_key()),
        Cmd::Recv {
            key,
            authorized,
            mut allow,
            listen,
            out,
            force,
            no_verify,
            threads,
            allow_owner,
            allow_special_bits,
        } => {
            if let Some(path) = authorized {
                allow.extend(load_authorized_keys(&path)?);
            }
            if allow.is_empty() {
                bail!("no authorized sender keys: pass --authorized FILE or --allow KEY");
            }
            let receiver = Receiver::bind(RecvConfig {
                listen,
                key: PrivateKey::load(&key)?,
                authorized: allow,
                out_dir: out,
                force,
                verify: !no_verify,
                threads,
                apply: ApplyPolicy {
                    allow_special_bits,
                    allow_owner,
                },
            })?;
            eprintln!("public key {}", receiver.public_key());
            eprintln!("listening on {}", receiver.local_addr());
            let progress = Arc::new(Progress::default());
            let report = with_progress("received", &progress, || receiver.run(progress.clone()))?;
            summary(
                "received",
                report.bytes_received,
                report.elapsed,
                &format!(
                    "{} files, {} chunks, {} duplicates, {} repaired, {}, {} rounds, from {}",
                    report.files,
                    report.chunks_received,
                    report.duplicate_chunks,
                    report.repaired_chunks,
                    if report.verified {
                        "verified"
                    } else {
                        "not verified"
                    },
                    report.rounds,
                    report.peer
                ),
            );
            report_files(report.hashed, &report.file_hashes, &report.warnings);
        }
        Cmd::Send {
            addr,
            key,
            peer,
            connections,
            chunk_size,
            cipher,
            threads,
            hash,
            preserve,
            paths,
        } => {
            let cfg = SendConfig {
                addr,
                key: PrivateKey::load(&key)?,
                peer,
                connections,
                chunk_size,
                cipher,
                threads,
                paths,
                hash,
                preserve,
            };
            let progress = Arc::new(Progress::default());
            let report = with_progress("sent", &progress, || mjolnir::send(cfg, progress.clone()))?;
            summary(
                "sent",
                report.bytes_sent,
                report.elapsed,
                &format!(
                    "{} files, {} chunks, {} resent, {} rounds, receiver {}",
                    report.files,
                    report.chunks_sent,
                    report.chunks_resent,
                    report.rounds,
                    if report.verified {
                        "verified"
                    } else {
                        "did not verify"
                    }
                ),
            );
            report_files(report.hashed, &report.file_hashes, &report.warnings);
        }
        Cmd::Serve {
            listen,
            key,
            no_open,
        } => {
            let (key, key_path) = match key {
                Some(path) => (PrivateKey::load(&path)?, path),
                None => PrivateKey::load_or_create_default()?,
            };
            eprintln!("key {} (public {})", key_path.display(), key.public_key());
            web::serve(web::ServeConfig {
                listen,
                key,
                key_path,
                open_browser: !no_open,
            })?;
        }
    }
    Ok(())
}

const MIB: f64 = (1 << 20) as f64;

/// Runs `work` on a thread and prints progress to stderr about once a second.
fn with_progress<T: Send>(
    verb: &str,
    progress: &Progress,
    work: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    thread::scope(|s| {
        let worker = s.spawn(work);
        let mut last = (Instant::now(), 0u64);
        while !worker.is_finished() {
            thread::sleep(Duration::from_millis(50));
            let now = Instant::now();
            if now - last.0 < Duration::from_secs(1) {
                continue;
            }
            let p = progress.snapshot();
            if matches!(
                p.phase,
                Phase::Transferring | Phase::Verifying | Phase::Hashing | Phase::Finishing
            ) {
                let rate = (p.bytes_done - last.1.min(p.bytes_done)) as f64
                    / MIB
                    / (now - last.0).as_secs_f64();
                eprintln!(
                    "{verb} {:.1} / {:.1} MiB, {rate:.1} MiB/s, {} connections",
                    p.bytes_done as f64 / MIB,
                    p.bytes_total as f64 / MIB,
                    p.active_connections
                );
            }
            last = (now, p.bytes_done);
        }
        let result = worker.join().expect("transfer thread panicked");
        let phases: Vec<String> = progress
            .phase_times()
            .into_iter()
            .filter(|(p, _)| !matches!(p, Phase::Done | Phase::Failed))
            .map(|(p, d)| {
                format!(
                    "{} {:.2} s",
                    format!("{p:?}").to_lowercase(),
                    d.as_secs_f64()
                )
            })
            .collect();
        eprintln!("phases: {}", phases.join(", "));
        result
    })
}

/// CPU time this process has used, user plus kernel.
#[cfg(unix)]
fn process_cpu() -> Option<Duration> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    Some(tv(usage.ru_utime) + tv(usage.ru_stime))
}

#[cfg(windows)]
fn process_cpu() -> Option<Duration> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    };
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    (ok != 0).then(|| Duration::from_nanos((ticks(kernel) + ticks(user)) * 100))
}

/// Prints each file's hash after a `--hash` transfer, then any warnings.
fn report_files(hashed: bool, file_hashes: &[(String, String)], warnings: &[String]) {
    if hashed {
        for (path, hash) in file_hashes {
            eprintln!("file_hash {hash}  {path}");
        }
    }
    for w in warnings {
        eprintln!("warning: {w}");
    }
}

fn summary(verb: &str, bytes: u64, elapsed: Duration, detail: &str) {
    let secs = elapsed.as_secs_f64();
    if let Some(cpu) = process_cpu() {
        eprintln!(
            "cpu {:.2} s, {:.1} cores busy on average",
            cpu.as_secs_f64(),
            cpu.as_secs_f64() / secs.max(1e-9)
        );
    }
    eprintln!(
        "{verb} {bytes} bytes ({:.1} MiB) in {secs:.2} s, {:.1} MiB/s ({detail})",
        bytes as f64 / MIB,
        bytes as f64 / MIB / secs.max(1e-9)
    );
}
