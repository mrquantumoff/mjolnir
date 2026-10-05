#[cfg(windows)]
use std::ffi::OsString;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use mjolnir::filemap::{ApplyPolicy, Preserve};
use mjolnir::keys::AuthorizedKey;
use mjolnir::printable::escape;
#[cfg(windows)]
use mjolnir::service::{self, ServiceName};
use mjolnir::tunnel::{self, Backoff, ForwardSpec, HostPort, Pattern, Permits, Policy};
use mjolnir::{
    Cipher, Phase, PhaseTimes, PrivateKey, Progress, PublicKey, Receiver, RecvConfig, RecvReport,
    SendConfig, load_authorized_entries, parse_size, shutdown, transfer_keys, web,
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
        /// Let only SYSTEM and Administrators use the key, as a Windows
        /// service needs. Run it from an elevated terminal.
        #[cfg(windows)]
        #[arg(long)]
        system: bool,
    },
    /// Print the public key of an existing private key file.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Receive a transfer from an authorized sender.
    Recv {
        #[arg(long)]
        key: PathBuf,
        /// File of authorized sender keys, one `[options] <base64> [comment]`
        /// per line; a line with tunnel options needs `transfer` to send files.
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
        /// After a transfer, wait for the next sender instead of exiting.
        #[arg(short = 'k', long)]
        keep_listening: bool,
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
        #[arg(long, value_enum, default_value_t = Cipher::default())]
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
        /// Skip symbolic links, including ones given as paths, instead of
        /// sending what they point to.
        #[arg(long)]
        no_follow_symlinks: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Forward TCP ports through a tunnel server, like `ssh -L` and `ssh -R`.
    Tunnel {
        /// Tunnel server address, HOST:PORT.
        addr: String,
        #[arg(long)]
        key: PathBuf,
        /// The tunnel server's public key.
        #[arg(long)]
        peer: PublicKey,
        /// Listen here and connect from the server: [BIND:]PORT:HOST:HOSTPORT
        /// (repeatable).
        #[arg(short = 'L', long = "local", value_name = "SPEC")]
        local: Vec<ForwardSpec>,
        /// Listen on the server and connect from here:
        /// [BIND:]PORT:HOST:HOSTPORT (repeatable).
        #[arg(short = 'R', long = "remote", value_name = "SPEC")]
        remote: Vec<ForwardSpec>,
        /// Carry one stream to HOST:PORT (reached from the server) over stdin
        /// and stdout, like `ssh -W`; for use as an ssh ProxyCommand.
        #[arg(short = 'W', long, value_name = "HOST:PORT", conflicts_with_all = ["local", "remote"])]
        stdio: Option<HostPort>,
        /// Connections per stream; more than 1 stripes each stream across
        /// them.
        #[arg(short = 'n', long, default_value_t = 1)]
        connections: u32,
        #[arg(long, value_enum, default_value_t = Cipher::default())]
        cipher: Cipher,
        /// When a session ends, set up a new one, waiting 1 s, doubling to
        /// 60 s, between attempts. The first session must still succeed.
        #[arg(long, conflicts_with = "stdio")]
        reconnect: bool,
        /// Log every stream.
        #[arg(short = 'v', long)]
        verbose: bool,
    },
    /// Accept tunnel clients and carry their forwards.
    TunnelServer {
        #[arg(long)]
        key: PathBuf,
        /// File of authorized client keys, one `[options] <base64> [comment]`
        /// per line; `permitopen="HOST:PORT"` and `permitlisten="HOST:PORT"`
        /// options replace the --permit-* defaults for that key.
        #[arg(long)]
        authorized: Option<PathBuf>,
        /// Authorize a client public key (repeatable).
        #[arg(long)]
        allow: Vec<PublicKey>,
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], tunnel::DEFAULT_PORT)))]
        listen: SocketAddr,
        /// Let clients open connections to HOST:PORT for -L; `*` matches any
        /// host or port (repeatable).
        #[arg(long, value_name = "HOST:PORT")]
        permit_open: Vec<Pattern>,
        /// Let clients listen on HOST:PORT on this host for -R; `*` matches
        /// any host or port (repeatable).
        #[arg(long, value_name = "HOST:PORT")]
        permit_listen: Vec<Pattern>,
        /// Log every stream.
        #[arg(short = 'v', long)]
        verbose: bool,
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
    /// Replace this binary with the latest release from GitHub.
    #[cfg(feature = "self-update")]
    Update {
        /// Only report whether a newer release exists.
        #[arg(long)]
        check: bool,
    },
    /// Run recv, tunnel-server, or tunnel as a Windows service.
    #[cfg(windows)]
    #[command(subcommand)]
    Service(ServiceCmd),
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCmd {
    /// Install a service that runs the command after `--`.
    ///
    /// The service is `mjolnir-NAME`. It runs as LocalSystem, in the
    /// current directory, and starts at boot.
    Install {
        /// Letters, digits, `-`, and `_`.
        name: ServiceName,
        /// Log file [default: %ProgramData%\mjolnir\NAME.log]
        #[arg(long)]
        log: Option<PathBuf>,
        /// Start only on `mjolnir service start`, not at boot.
        #[arg(long)]
        manual: bool,
        /// `recv --keep-listening`, `tunnel-server`, or `tunnel --reconnect`,
        /// with their arguments.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Start an installed service.
    Start { name: ServiceName },
    /// Stop a running service.
    Stop { name: ServiceName },
    /// Print a service's state, PID, command, and log file.
    Status { name: ServiceName },
    /// Stop a service if it runs, then remove it.
    Uninstall { name: ServiceName },
    /// What the service manager starts.
    #[command(hide = true)]
    Run {
        name: ServiceName,
        #[arg(long)]
        cwd: PathBuf,
        #[arg(long)]
        log: PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}

fn main() {
    #[cfg(all(feature = "self-update", windows))]
    mjolnir::update::remove_leftover();
    if let Err(e) = run(Cli::parse().cmd, true) {
        eprintln!("mjolnir: error: {}", escape(&format!("{e:#}")));
        std::process::exit(1);
    }
}

/// Runs `cmd`, printing transfer progress about once a second if
/// `progress_lines`.
fn run(cmd: Cmd, progress_lines: bool) -> Result<()> {
    match cmd {
        Cmd::Keygen {
            out,
            #[cfg(windows)]
            system,
        } => {
            let key = PrivateKey::generate();
            #[cfg(windows)]
            let save = if system {
                PrivateKey::save_for_system
            } else {
                PrivateKey::save
            };
            #[cfg(not(windows))]
            let save = PrivateKey::save;
            save(&key, &out)?;
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
            keep_listening,
        } => {
            if let Some(path) = authorized {
                let entries = load_authorized_entries(&path)?;
                for entry in entries.iter().filter(|e| !e.grants_transfer()) {
                    eprintln!(
                        "mjolnir: {}: key {} has tunnel options and no `transfer` option, so it may not send files",
                        path.display(),
                        entry.key
                    );
                }
                allow.extend(transfer_keys(&entries));
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
            shutdown::on_request({
                let progress = progress.clone();
                move || progress.cancel()
            });
            let mut cpu_before = Duration::ZERO;
            let served = with_progress("received", &progress, progress_lines, || {
                receiver.serve(progress.clone(), |report| {
                    // Only the CPU spent since the previous transfer ended.
                    let cpu = process_cpu()
                        .map(|now| now.saturating_sub(std::mem::replace(&mut cpu_before, now)));
                    received(&report, cpu);
                    if keep_listening {
                        eprintln!("waiting for the next sender");
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(())
                    }
                })
            });
            if !shutdown::is_requested() {
                served?;
            }
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
            no_follow_symlinks,
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
                follow_symlinks: !no_follow_symlinks,
            };
            let progress = Arc::new(Progress::default());
            let report = with_progress("sent", &progress, progress_lines, || {
                mjolnir::send(cfg, progress.clone())
            })?;
            summary(
                "sent",
                report.bytes_sent,
                report.elapsed,
                process_cpu(),
                report.phase_times,
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
        Cmd::Tunnel {
            addr,
            key,
            peer,
            local,
            remote,
            stdio,
            connections,
            cipher,
            reconnect,
            verbose,
        } => {
            if stdio.is_none() && local.is_empty() && remote.is_empty() {
                bail!("nothing to forward: pass -L, -R, or -W");
            }
            let cfg = tunnel::ClientConfig {
                addr,
                key: PrivateKey::load(&key)?,
                peer,
                cipher,
                conns: connections,
                local,
                remote,
                verbose,
            };
            block_on(async move {
                let client = tunnel::TunnelClient::connect(cfg).await?;
                match stdio {
                    Some(target) => client.stdio(target).await.map(drop),
                    None => {
                        eprintln!("mjolnir: tunnel up");
                        if reconnect {
                            client.run_reconnecting(Backoff::default(), stopped()).await;
                            Ok(())
                        } else {
                            client.run_until(stopped()).await
                        }
                    }
                }
            })?;
        }
        Cmd::TunnelServer {
            key,
            authorized,
            allow,
            listen,
            permit_open,
            permit_listen,
            verbose,
        } => {
            let mut entries = match authorized {
                Some(path) => load_authorized_entries(&path)?,
                None => Vec::new(),
            };
            entries.extend(allow.into_iter().map(|key| AuthorizedKey {
                key,
                options: Vec::new(),
            }));
            let defaults = Permits {
                open: permit_open,
                listen: permit_listen,
            };
            let cfg = tunnel::ServerConfig {
                listen,
                key: PrivateKey::load(&key)?,
                policy: Policy::new(&entries, defaults)?,
                verbose,
            };
            block_on(async move {
                let server = tunnel::TunnelServer::bind(cfg).await?;
                eprintln!("public key {}", server.public_key());
                eprintln!("listening on {}", server.local_addr());
                server.run_until(stopped()).await
            })?;
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
        #[cfg(feature = "self-update")]
        Cmd::Update { check } => {
            use mjolnir::update::{self, Outcome};
            // A mirror of the official releases sets only the URL; a fork
            // that signs its own releases sets both.
            let (releases, key) = match std::env::var("MJOLNIR_RELEASES_URL") {
                Ok(releases) => (
                    releases,
                    std::env::var("MJOLNIR_RELEASE_KEY")
                        .unwrap_or_else(|_| update::RELEASE_KEY.to_string()),
                ),
                Err(_) => (
                    update::RELEASES_URL.to_string(),
                    update::RELEASE_KEY.to_string(),
                ),
            };
            let current = env!("CARGO_PKG_VERSION");
            match update::update(&releases, &key, check)? {
                Outcome::UpToDate { latest } => {
                    println!("mjolnir {current} is up to date (latest release {latest})")
                }
                Outcome::Available { latest } => {
                    println!(
                        "mjolnir {latest} is available (this is {current}); run `mjolnir update`"
                    )
                }
                Outcome::Updated { version, path } => {
                    println!("installed {version} to {}", path.display())
                }
            }
        }
        #[cfg(windows)]
        Cmd::Service(cmd) => run_service(cmd)?,
    }
    Ok(())
}

#[cfg(windows)]
fn run_service(cmd: ServiceCmd) -> Result<()> {
    match cmd {
        ServiceCmd::Install {
            name,
            log,
            manual,
            command,
        } => {
            let parsed = parse_service_command(&command)?;
            let log = std::path::absolute(log.unwrap_or_else(|| name.default_log()))?;
            let mut args: Vec<OsString> = vec![
                "service".into(),
                "run".into(),
                name.as_str().into(),
                "--cwd".into(),
                std::env::current_dir()?.into(),
                "--log".into(),
                log.clone().into(),
                "--".into(),
            ];
            args.extend(command);
            service::install(&name, &args, &service_inputs(&parsed), &log, manual)?;
            println!(
                "installed service {}; start it with `mjolnir service start {}`",
                name.service(),
                name.as_str()
            );
        }
        ServiceCmd::Start { name } => match service::start(&name) {
            Ok(pid) => println!("{} is running, PID {pid}", name.service()),
            Err(e) => {
                let installed = service::status(&name).ok();
                match installed.and_then(|s| installed_run(&s.command)) {
                    Some((_, log, _)) => bail!("{e:#}; its log is {}", log.display()),
                    None => return Err(e),
                }
            }
        },
        ServiceCmd::Stop { name } => match service::stop(&name)? {
            true => println!("{} stopped", name.service()),
            false => println!("{} was not running", name.service()),
        },
        ServiceCmd::Status { name } => {
            let status = service::status(&name)?;
            match status.pid {
                Some(pid) => println!("{}: {}, PID {pid}", name.service(), status.state),
                None => println!("{}: {}", name.service(), status.state),
            }
            if let Some(failure) = status.failure {
                println!("last stop: {failure}");
            }
            match installed_run(&status.command) {
                Some((cwd, log, command)) => {
                    let command = service::command_line(command.iter().map(AsRef::as_ref));
                    println!("command: mjolnir {}", command.display());
                    println!("directory: {}", cwd.display());
                    println!("log: {}", log.display());
                }
                None => {
                    let line = service::command_line(status.command.iter().map(AsRef::as_ref));
                    println!("command line: {}", line.display());
                }
            }
        }
        ServiceCmd::Uninstall { name } => {
            service::uninstall(&name)?;
            println!("removed {}", name.service());
        }
        ServiceCmd::Run {
            name,
            cwd,
            log,
            command,
        } => service::run(&name, cwd, log, move || {
            let cmd = parse_service_command(&command)?;
            service::check_inputs(&service_inputs(&cmd))?;
            run(cmd, false)
        })?,
    }
    Ok(())
}

/// Parses the command a service runs, refusing one that would end on its
/// own, after which the service would just show as stopped.
#[cfg(windows)]
fn parse_service_command(args: &[OsString]) -> Result<Cmd> {
    let cli = Cli::try_parse_from(std::iter::once(OsString::from("mjolnir")).chain(args.to_vec()))
        .map_err(|e| {
            eprint!("{}", e.render());
            anyhow::anyhow!("the service command does not parse")
        })?;
    match cli.cmd {
        Cmd::Recv {
            keep_listening: false,
            ..
        } => bail!("a recv service needs --keep-listening, or it stops after one transfer"),
        Cmd::Tunnel {
            reconnect: false, ..
        } => bail!("a tunnel service needs --reconnect, or it stops when its first session ends"),
        cmd @ (Cmd::Recv { .. } | Cmd::Tunnel { .. } | Cmd::TunnelServer { .. }) => Ok(cmd),
        _ => bail!(
            "a service runs `recv --keep-listening`, `tunnel-server`, or `tunnel --reconnect`"
        ),
    }
}

#[cfg(windows)]
fn service_inputs(cmd: &Cmd) -> service::Inputs<'_> {
    match cmd {
        Cmd::Recv {
            key,
            authorized,
            out,
            ..
        } => service::Inputs {
            key,
            authorized: authorized.as_deref(),
            out: Some(out),
        },
        Cmd::TunnelServer {
            key, authorized, ..
        } => service::Inputs {
            key,
            authorized: authorized.as_deref(),
            out: None,
        },
        Cmd::Tunnel { key, .. } => service::Inputs {
            key,
            authorized: None,
            out: None,
        },
        _ => unreachable!("parse_service_command accepts only these"),
    }
}

/// The `service run` arguments of a service's command line, if `install`
/// wrote it: the directory, the log, and the command.
#[cfg(windows)]
fn installed_run(command_line: &[OsString]) -> Option<(PathBuf, PathBuf, Vec<OsString>)> {
    match Cli::try_parse_from(command_line).ok()?.cmd {
        Cmd::Service(ServiceCmd::Run {
            cwd, log, command, ..
        }) => Some((cwd, log, command)),
        _ => None,
    }
}

const MIB: f64 = (1 << 20) as f64;

/// Completes on the shutdown request, which Ctrl-C makes from here on.
async fn stopped() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("mjolnir: interrupted, closing");
            shutdown::request();
        }
    });
    shutdown::requested().await
}

/// Runs `work` on a multi-threaded tokio runtime. Only the tunnel commands
/// use tokio. The runtime is not waited for on the way out: a blocking stdin
/// read would hold it up forever.
fn block_on<T>(work: impl Future<Output = Result<T>>) -> Result<T> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(work);
    rt.shutdown_background();
    result
}

/// Runs `work`, if `lines` on a thread while printing progress to stderr
/// about once a second.
fn with_progress<T: Send>(
    verb: &str,
    progress: &Progress,
    lines: bool,
    work: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    if !lines {
        return work();
    }
    thread::scope(|s| {
        let worker = s.spawn(work);
        let mut last = (Instant::now(), 0u64);
        while !worker.is_finished() {
            thread::sleep(Duration::from_millis(50));
            let now = Instant::now();
            if now - last.0 < Duration::from_secs(1) {
                continue;
            }
            // Held from the snapshot to its line, so a progress line taken
            // before a transfer ended never prints after the summary the
            // worker prints for it.
            let _stderr = std::io::stderr().lock();
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
        worker.join().expect("transfer thread panicked")
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

/// The most memory this process has had resident, in bytes.
#[cfg(unix)]
fn peak_memory() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    // Linux reports kibibytes, macOS bytes.
    let unit = if cfg!(target_os = "macos") { 1 } else { 1024 };
    Some(usage.ru_maxrss as u64 * unit)
}

#[cfg(windows)]
fn peak_memory() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut counters = unsafe { std::mem::zeroed::<PROCESS_MEMORY_COUNTERS>() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
    (ok != 0).then_some(counters.PeakWorkingSetSize as u64)
}

/// Prints each file's hash after a `--hash` transfer, then any warnings.
fn report_files(hashed: bool, file_hashes: &[(String, String)], warnings: &[String]) {
    if hashed {
        for (path, hash) in file_hashes {
            eprintln!("file_hash {hash}  {}", escape(path));
        }
    }
    for w in warnings {
        eprintln!("warning: {}", escape(w));
    }
}

fn received(report: &RecvReport, cpu: Option<Duration>) {
    summary(
        "received",
        report.bytes_received,
        report.elapsed,
        cpu,
        report.phase_times,
        &format!(
            "{} files, {} chunks, {} duplicates, {} repaired, {} stale, {}, {} rounds, from {}",
            report.files,
            report.chunks_received,
            report.duplicate_chunks,
            report.repaired_chunks,
            report.stale_chunks,
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

fn summary(
    verb: &str,
    bytes: u64,
    elapsed: Duration,
    cpu: Option<Duration>,
    phases: PhaseTimes,
    detail: &str,
) {
    let secs = elapsed.as_secs_f64();
    if let Some(cpu) = cpu {
        let peak = peak_memory().map_or(String::new(), |b| {
            format!(", peak memory {:.1} MiB", b as f64 / MIB)
        });
        eprintln!(
            "cpu {:.2} s, {:.1} cores busy on average{peak}",
            cpu.as_secs_f64(),
            cpu.as_secs_f64() / secs.max(1e-9)
        );
    }
    eprintln!(
        "{verb} {bytes} bytes ({:.1} MiB) in {secs:.2} s, {:.1} MiB/s ({detail})",
        bytes as f64 / MIB,
        bytes as f64 / MIB / secs.max(1e-9)
    );
    let t = phases.transfer.as_secs_f64();
    eprintln!(
        "transfer {t:.2} s ({:.0} MiB/s), verify {:.2} s, hash {:.2} s, finalize {:.2} s",
        bytes as f64 / MIB / t.max(1e-9),
        phases.verify.as_secs_f64(),
        phases.hash.as_secs_f64(),
        phases.finalize.as_secs_f64()
    );
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn parse(line: &str) -> Result<Cmd> {
        let peer = PrivateKey::generate().public_key();
        let line = line.replace("PEER", &peer.to_string());
        parse_service_command(&line.split(' ').map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn services_run_only_commands_that_keep_running() {
        for ok in [
            "recv --key k.key --allow PEER --keep-listening",
            "recv -k --key k.key --out D:/in",
            "tunnel-server --key k.key --allow PEER --permit-open db:5432",
            "tunnel h:7778 --key k.key --peer PEER -L 1:db:5432 --reconnect",
        ] {
            let cmd = parse(ok).unwrap_or_else(|e| panic!("{ok}: {e:#}"));
            assert_eq!(service_inputs(&cmd).key, std::path::Path::new("k.key"));
        }
        for (bad, says) in [
            ("recv --key k.key", "--keep-listening"),
            (
                "tunnel h:7778 --key k.key --peer PEER -R 1:h:2",
                "--reconnect",
            ),
            ("send h:7777 --key k.key --peer PEER file", "tunnel-server"),
            ("keygen", "tunnel-server"),
            ("service status x", "tunnel-server"),
            ("recv --key k.key --kep-listening", "does not parse"),
            (
                "tunnel h:7778 --key k.key --peer PEER -W h:22 --reconnect",
                "does not parse",
            ),
        ] {
            let Err(err) = parse(bad) else {
                panic!("{bad}: accepted")
            };
            let err = format!("{err:#}");
            assert!(err.contains(says), "{bad}: {err}");
        }
    }
}
