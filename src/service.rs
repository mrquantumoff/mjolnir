//! Windows services that run one long-running mjolnir command: installing,
//! starting, stopping, and removing them, and the side that runs inside the
//! service with its stderr in a log file.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::str::FromStr;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NEVER_STARTED, ERROR_SERVICE_NOT_ACTIVE, HANDLE,
    LocalFree,
};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, SetStdHandle};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, CreateServiceW, OpenSCManagerW, SC_HANDLE, SC_MANAGER_CREATE_SERVICE,
    SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

use crate::{PrivateKey, printable, shutdown};

/// After a failure the service manager restarts the service this long
/// later, up to `RESTARTS` times until a day passes without a failure.
const RESTART_DELAY: Duration = Duration::from_secs(10);
const RESTARTS: usize = 3;
const FAILURE_RESET: Duration = Duration::from_secs(24 * 60 * 60);
/// How long the service manager is told a stop may take.
const STOP_WAIT: Duration = Duration::from_secs(10);
/// How long `start`, `stop`, and `uninstall` wait for the service.
const SETTLE: Duration = Duration::from_secs(30);

/// Service-specific exit codes.
const EXIT_FAILED: u32 = 1;
const EXIT_NO_LOG: u32 = 2;

/// A service's NAME: ASCII letters, digits, `-`, and `_`. The service is
/// `mjolnir-NAME`, so these commands never touch another program's service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceName(String);

impl FromStr for ServiceName {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if s.is_empty() || !s.chars().all(allowed) {
            bail!("service name {s:?} must be ASCII letters, digits, `-`, and `_`");
        }
        Ok(ServiceName(s.to_owned()))
    }
}

impl ServiceName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name the service manager knows the service by.
    pub fn service(&self) -> String {
        format!("mjolnir-{}", self.0)
    }

    /// `%ProgramData%\mjolnir\NAME.log`.
    pub fn default_log(&self) -> PathBuf {
        let data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(data)
            .join("mjolnir")
            .join(format!("{}.log", self.0))
    }
}

/// Installs service `mjolnir-NAME` that runs `exe` with `args` as
/// LocalSystem, starting at boot unless `manual`, and restarting after a
/// failure. `key` is the private key the command loads, which must pass the
/// key check as LocalSystem. The service is not started.
pub fn install(
    name: &ServiceName,
    exe: &Path,
    args: &[OsString],
    key: &Path,
    manual: bool,
) -> Result<()> {
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CREATE_SERVICE) };
    if manager.is_null() {
        return Err(explain(name, io::Error::last_os_error().into()));
    }
    let manager = ScHandle(manager);
    PrivateKey::check_for_local_system(key)
        .context("the service runs as LocalSystem, which would refuse its key")?;
    let line = command_line(std::iter::once(exe.as_os_str()).chain(args.iter().map(AsRef::as_ref)));
    let start = if manual {
        SERVICE_DEMAND_START
    } else {
        SERVICE_AUTO_START
    };
    // Created here rather than through `windows_service`, which quotes the
    // command line itself, so the stored line is the one `command_line`
    // builds and its tests check.
    let service = unsafe {
        CreateServiceW(
            manager.0,
            wide(name.service().as_ref()).as_ptr(),
            wide(format!("mjolnir {}", name.0).as_ref()).as_ptr(),
            SERVICE_QUERY_STATUS,
            SERVICE_WIN32_OWN_PROCESS,
            start,
            SERVICE_ERROR_NORMAL,
            wide(&line).as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    if service.is_null() {
        return Err(explain(name, io::Error::last_os_error().into()));
    }
    drop(ScHandle(service));
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: RESTART_DELAY,
    };
    let service = open(name, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart; RESTARTS]),
    })?;
    // Otherwise only a crash counts as a failure, not a stop with an error.
    service.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

/// Starts the service and waits until it runs. Returns its PID.
pub fn start(name: &ServiceName) -> Result<u32> {
    let service = open(name, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    if let Err(e) = service.start::<&OsStr>(&[])
        && os_code(&e) != Some(ERROR_SERVICE_ALREADY_RUNNING)
    {
        return Err(explain(name, e.into()));
    }
    let status = settle(&service, |s| s != ServiceState::StartPending)?;
    match status.process_id {
        Some(pid) if status.current_state == ServiceState::Running => Ok(pid),
        _ => bail!(
            "{} stopped right after it started: {}",
            name.service(),
            exit_reason(status.exit_code).unwrap_or("no reason given")
        ),
    }
}

/// Stops the service and waits until it has. False if it was not running.
pub fn stop(name: &ServiceName) -> Result<bool> {
    let service = open(name, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    stop_service(name, &service)
}

/// Stops the service if it runs, then removes it.
pub fn uninstall(name: &ServiceName) -> Result<()> {
    let access = ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE;
    let service = open(name, access)?;
    stop_service(name, &service)?;
    service.delete().map_err(|e| explain(name, e.into()))
}

pub struct Status {
    /// `running`, `stopped`, `start pending`, ...
    pub state: &'static str,
    pub pid: Option<u32>,
    /// Why a stopped service last stopped, if not because it was asked to.
    pub failure: Option<&'static str>,
    /// The command line the service manager runs, split into arguments.
    pub command: Vec<OsString>,
}

pub fn status(name: &ServiceName) -> Result<Status> {
    let service = open(
        name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
    )?;
    let status = service.query_status()?;
    let config = service.query_config()?;
    Ok(Status {
        state: match status.current_state {
            ServiceState::Stopped => "stopped",
            ServiceState::StartPending => "start pending",
            ServiceState::StopPending => "stop pending",
            ServiceState::Running => "running",
            ServiceState::ContinuePending => "continue pending",
            ServiceState::PausePending => "pause pending",
            ServiceState::Paused => "paused",
        },
        pid: status.process_id,
        failure: match status.current_state {
            ServiceState::Stopped => exit_reason(status.exit_code),
            _ => None,
        },
        command: split_command_line(config.executable_path.as_os_str()),
    })
}

fn exit_reason(code: ServiceExitCode) -> Option<&'static str> {
    match code {
        ServiceExitCode::ServiceSpecific(EXIT_FAILED) => Some("the command failed; see its log"),
        ServiceExitCode::ServiceSpecific(EXIT_NO_LOG) => Some("it could not open its log file"),
        ServiceExitCode::Win32(0 | ERROR_SERVICE_NEVER_STARTED) => None,
        _ => Some("the process ended without reporting why; see its log"),
    }
}

fn open(name: &ServiceName, access: ServiceAccess) -> Result<Service> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|manager| manager.open_service(name.service(), access))
        .map_err(|e| explain(name, e.into()))
}

fn stop_service(name: &ServiceName, service: &Service) -> Result<bool> {
    match service.stop() {
        Ok(_) => {}
        Err(e) if os_code(&e) == Some(ERROR_SERVICE_NOT_ACTIVE) => return Ok(false),
        // Already stopping.
        Err(e) if os_code(&e) == Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL) => {}
        Err(e) => return Err(explain(name, e.into())),
    }
    let status = settle(service, |s| s == ServiceState::Stopped)?;
    if status.current_state != ServiceState::Stopped {
        bail!("{} did not stop within {SETTLE:?}", name.service());
    }
    Ok(true)
}

/// Polls the service until `done` holds for its state or `SETTLE` passes,
/// and returns the last status.
fn settle(service: &Service, done: impl Fn(ServiceState) -> bool) -> Result<ServiceStatus> {
    let deadline = Instant::now() + SETTLE;
    loop {
        let status = service.query_status()?;
        if done(status.current_state) || Instant::now() > deadline {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn os_code(e: &windows_service::Error) -> Option<u32> {
    match e {
        windows_service::Error::Winapi(e) => e.raw_os_error().map(|c| c as u32),
        _ => None,
    }
}

/// Puts the usual service manager failures in plain words.
fn explain(name: &ServiceName, e: anyhow::Error) -> anyhow::Error {
    let code = e
        .chain()
        .find_map(|c| c.downcast_ref::<io::Error>())
        .and_then(io::Error::raw_os_error);
    let service = name.service();
    match code.map(|c| c as u32) {
        Some(ERROR_ACCESS_DENIED) => anyhow!(
            "access denied: installing, starting, stopping, and removing services needs \
             an elevated terminal (Run as administrator)"
        ),
        Some(ERROR_SERVICE_DOES_NOT_EXIST) => anyhow!("there is no service {service}"),
        Some(ERROR_SERVICE_EXISTS) => anyhow!(
            "service {service} already exists; remove it first with \
             `mjolnir service uninstall {}`",
            name.0
        ),
        Some(ERROR_SERVICE_MARKED_FOR_DELETE) => anyhow!(
            "service {service} is being removed; close whatever holds it open, such as \
             the Services window, and try again"
        ),
        _ => e,
    }
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

type Job = Box<dyn FnOnce() + Send>;

/// What `service_main` runs; the dispatcher calls it with no context.
static JOB: Mutex<Option<Job>> = Mutex::new(None);

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Some(job) = JOB.lock().unwrap().take() {
        job();
    }
}

/// Runs as service `name`: reports it running, appends stderr to `log`,
/// and runs `command` in `cwd` until it ends or the service manager asks
/// it to stop, which makes the shutdown request. Returns once the service
/// has stopped. Only the service manager can start this.
pub fn run(
    name: &ServiceName,
    cwd: PathBuf,
    log: PathBuf,
    command: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<()> {
    let service = name.service();
    *JOB.lock().unwrap() = Some(Box::new(move || serve(&service, &cwd, &log, command)));
    service_dispatcher::start(name.service(), ffi_service_main).map_err(|e| match os_code(&e) {
        Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) => anyhow!(
            "`mjolnir service run` is for the service manager; use `mjolnir service start {}`",
            name.0
        ),
        _ => e.into(),
    })
}

fn serve(service: &str, cwd: &Path, log: &Path, command: impl FnOnce() -> Result<()>) {
    let handler = |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            shutdown::request();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(service, handler) else {
        return;
    };
    let report = move |state, exit_code| {
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: match state {
                ServiceState::Running => {
                    ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
                }
                _ => ServiceControlAccept::empty(),
            },
            exit_code,
            checkpoint: 0,
            wait_hint: match state {
                ServiceState::StopPending => STOP_WAIT,
                _ => Duration::ZERO,
            },
            process_id: None,
        });
    };
    let Ok(log) = Log::start(log) else {
        report(
            ServiceState::Stopped,
            ServiceExitCode::ServiceSpecific(EXIT_NO_LOG),
        );
        return;
    };
    report(ServiceState::Running, ServiceExitCode::NO_ERROR);
    shutdown::on_request(move || {
        eprintln!("mjolnir: service stop requested, closing");
        report(ServiceState::StopPending, ServiceExitCode::NO_ERROR);
    });
    eprintln!(
        "mjolnir {}: service {service} starting in {}",
        env!("CARGO_PKG_VERSION"),
        cwd.display()
    );
    let ended = std::env::set_current_dir(cwd)
        .with_context(|| format!("entering {}", cwd.display()))
        .and_then(|()| command());
    if let Err(e) = &ended {
        eprintln!("mjolnir: error: {}", printable::escape(&format!("{e:#}")));
    }
    let exit = if shutdown::is_requested() {
        eprintln!("mjolnir: service stopped");
        ServiceExitCode::NO_ERROR
    } else {
        eprintln!("mjolnir: service failed");
        ServiceExitCode::ServiceSpecific(EXIT_FAILED)
    };
    log.finish();
    report(ServiceState::Stopped, exit);
}

/// Opens the log for appending, creating it and its folder if missing.
fn open_log(path: &Path) -> Result<File> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening log {}", path.display()))
}

/// Stderr pointed at a pipe that a thread copies into the log file a line
/// at a time, each after a UTC timestamp. std looks the stderr handle up
/// on every write, so this catches `eprintln!` from every thread.
struct Log {
    pipe: OwnedHandle,
    copier: JoinHandle<()>,
    previous: HANDLE,
}

impl Log {
    fn start(path: &Path) -> Result<Log> {
        let file = open_log(path)?;
        let (mut read, mut write) = (null_mut(), null_mut());
        if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let (read, pipe) = unsafe {
            (
                File::from_raw_handle(read),
                OwnedHandle::from_raw_handle(write),
            )
        };
        let copier = thread::spawn(move || copy_lines(BufReader::new(read), file));
        let previous = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        unsafe { SetStdHandle(STD_ERROR_HANDLE, pipe.as_raw_handle()) };
        Ok(Log {
            pipe,
            copier,
            previous,
        })
    }

    /// Gives stderr back and waits until the last lines are in the file.
    fn finish(self) {
        {
            // No write is between looking the handle up and using it.
            let _stderr = io::stderr().lock();
            unsafe { SetStdHandle(STD_ERROR_HANDLE, self.previous) };
            drop(self.pipe);
        }
        let _ = self.copier.join();
    }
}

fn copy_lines(mut from: impl BufRead, mut to: impl Write) {
    let mut line = Vec::new();
    while matches!(from.read_until(b'\n', &mut line), Ok(n) if n > 0) {
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        let mut out = format!("{} ", utc_timestamp(SystemTime::now())).into_bytes();
        out.extend_from_slice(text);
        out.push(b'\n');
        let _ = to.write_all(&out);
        line.clear();
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
fn utc_timestamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, day_secs) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil_from_days, for days since 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_secs / 3_600,
        day_secs / 60 % 60,
        day_secs % 60
    )
}

const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;

/// Joins `args` into one Windows command line that `split_command_line`,
/// and the Rust runtime's own parser, split back into the same arguments.
pub fn command_line<'a>(args: impl IntoIterator<Item = &'a OsStr>) -> OsString {
    let mut line = Vec::new();
    for arg in args {
        if !line.is_empty() {
            line.push(u16::from(b' '));
        }
        let arg: Vec<u16> = arg.encode_wide().collect();
        let plain = !arg.is_empty()
            && !arg
                .iter()
                .any(|&c| matches!(c, 0x20 | 0x09 | 0x0a | 0x0b) || c == QUOTE);
        if plain {
            line.extend(arg);
            continue;
        }
        line.push(QUOTE);
        let mut backslashes = 0;
        for c in arg {
            if c == BACKSLASH {
                backslashes += 1;
                continue;
            }
            // Backslashes are literal unless a quote follows them.
            let n = if c == QUOTE {
                2 * backslashes + 1
            } else {
                backslashes
            };
            line.extend(std::iter::repeat_n(BACKSLASH, n));
            line.push(c);
            backslashes = 0;
        }
        line.extend(std::iter::repeat_n(BACKSLASH, 2 * backslashes));
        line.push(QUOTE);
    }
    OsString::from_wide(&line)
}

/// Splits a command line as `CommandLineToArgvW` does.
pub fn split_command_line(line: &OsStr) -> Vec<OsString> {
    let line = wide(line);
    let mut argc = 0;
    let argv = unsafe { CommandLineToArgvW(line.as_ptr(), &mut argc) };
    if argv.is_null() {
        return Vec::new();
    }
    let args = (0..argc as usize)
        .map(|i| {
            let arg = unsafe { *argv.add(i) };
            let len = (0..).take_while(|&j| unsafe { *arg.add(j) } != 0).count();
            OsString::from_wide(unsafe { std::slice::from_raw_parts(arg, len) })
        })
        .collect();
    unsafe { LocalFree(argv.cast()) };
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_letters_digits_dash_and_underscore() {
        for good in ["a", "inbox", "Tunnel-2", "db_fwd", "0"] {
            let name: ServiceName = good.parse().unwrap();
            assert_eq!(name.service(), format!("mjolnir-{good}"));
        }
        for bad in ["", "a b", "a/b", r"a\b", "x.y", "é", "a\"", "-\0"] {
            assert!(bad.parse::<ServiceName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn command_lines_split_back_into_their_arguments() {
        let exe = r"C:\Program Files\mjolnir\mjolnir.exe";
        let cases: &[&[&str]] = &[
            &["recv", "--keep-listening"],
            &[""],
            &["a b", "c\td", "line\nbreak"],
            &[r#"say "hi""#, r#"""#, r"\", r#"\""#, r#"a\\"b"#],
            &[
                r"C:\dir with space\",
                r"C:\trailing\",
                r"\\server\share\",
                r"C:\",
            ],
            &[r"C:\in coming\\", r"a\\b c", r#""quoted path\""#],
            &["ünï cødé", "--out", r"D:\été\"],
        ];
        for &args in cases {
            let all: Vec<&OsStr> = std::iter::once(&exe).chain(args).map(OsStr::new).collect();
            let line = command_line(all.iter().copied());
            let split = split_command_line(&line);
            assert_eq!(split, all, "{line:?}");
        }
        assert_eq!(
            command_line([r"C:\a b\", "plain", r#"x"y"#].map(OsStr::new)),
            r#""C:\a b\\" plain "x\"y""#
        );
    }

    #[test]
    fn timestamps_are_utc() {
        let at = |secs| utc_timestamp(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(at(1_709_164_799), "2024-02-28T23:59:59Z");
        assert_eq!(at(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(at(4_102_444_800), "2100-01-01T00:00:00Z");
    }

    /// Writes straight to the handle, as `eprintln!` does outside the test
    /// harness, which captures the macros.
    #[test]
    fn stderr_lands_in_the_log_until_finished() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(r"log dir\test.log");
        fs::create_dir(path.parent().unwrap()).unwrap();
        fs::write(&path, "earlier\n").unwrap();
        let log = Log::start(&path).unwrap();
        io::stderr().write_all(b"from the test\n").unwrap();
        thread::spawn(|| io::stderr().write_all(b"from a thread\nunfinished"))
            .join()
            .unwrap()
            .unwrap();
        log.finish();
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!(lines[0], "earlier");
        for (line, want) in lines[1..]
            .iter()
            .zip(["from the test", "from a thread", "unfinished"])
        {
            assert!(line.ends_with(&format!("Z {want}")), "{line}");
        }
    }

    #[test]
    fn log_lines_get_a_timestamp_each() {
        let mut out = Vec::new();
        copy_lines(&b"listening on 1.2.3.4:7777\r\n\nlast"[..], &mut out);
        let out = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        for (line, text) in lines.iter().zip(["listening on 1.2.3.4:7777", "", "last"]) {
            let (stamp, rest) = line.split_at(20);
            assert!(
                stamp.ends_with("Z") && stamp.as_bytes()[10] == b'T',
                "{line}"
            );
            assert_eq!(rest, format!(" {text}"));
        }
    }
}
