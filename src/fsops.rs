//! File system operations the receiver's storage depends on: durable
//! renames and removes, directory syncs, an exclusive lock per output
//! directory, and private (owner-only) staging files and directories.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

/// Syncs a directory's entries to disk, so a rename or unlink inside it
/// survives a crash. `fsync` of the file alone does not do that on Linux.
#[cfg(unix)]
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// NTFS flushes a directory's metadata through a handle opened with
/// backup semantics and write access.
#[cfg(windows)]
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    OpenOptions::new()
        .access_mode(FILE_GENERIC_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?
        .sync_all()
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Renames `from` to `to` and makes the rename durable. Without `replace`
/// the rename fails if `to` exists, atomically, so a file created at the
/// destination while the transfer ran is never overwritten.
pub fn rename_durable(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
    rename(from, to, replace)?;
    sync_dir(parent_of(to))?;
    let (a, b) = (parent_of(from), parent_of(to));
    if a != b {
        sync_dir(a)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
    if replace {
        return fs::rename(from, to);
    }
    use std::os::unix::ffi::OsStrExt;
    let (from, to) = (
        cstr(from.as_os_str().as_bytes())?,
        cstr(to.as_os_str().as_bytes())?,
    );
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
    if replace {
        return fs::rename(from, to);
    }
    use std::os::unix::ffi::OsStrExt;
    let (from, to) = (
        cstr(from.as_os_str().as_bytes())?,
        cstr(to.as_os_str().as_bytes())?,
    );
    let rc = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Other Unix: a hard link fails if the target exists, and the source is
/// unlinked afterwards.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rename(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
    if replace {
        return fs::rename(from, to);
    }
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}

#[cfg(unix)]
fn cstr(bytes: &[u8]) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(bytes).map_err(io::Error::other)
}

#[cfg(windows)]
fn rename(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Removes a file, if it exists, and syncs its directory.
pub fn remove_durable(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_dir(parent_of(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Removes a directory tree, then syncs its parent.
pub fn remove_tree_durable(dir: &Path) -> io::Result<()> {
    match fs::remove_dir_all(dir) {
        Ok(()) => sync_dir(parent_of(dir)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Creates `dir` readable by its owner only, and syncs its parent. An
/// existing directory is left as it is.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    create_private_dir_impl(dir)?;
    sync_dir(parent_of(dir))
}

#[cfg(unix)]
fn create_private_dir_impl(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(dir)
}

/// A protected DACL naming the current user and SYSTEM, with inheritance
/// to everything created inside, so no other account can read staged
/// plaintext through a permissive parent.
#[cfg(windows)]
fn create_private_dir_impl(dir: &Path) -> io::Result<()> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)", current_user_sid()?)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: the SDDL string is NUL-terminated; the descriptor comes back
    // as a LocalAlloc block that is freed below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let path = wide(dir);
    // SAFETY: the path is NUL-terminated and the attributes point at a
    // valid descriptor for the duration of the call.
    let created = unsafe { CreateDirectoryW(path.as_ptr(), &attrs) };
    let err = io::Error::last_os_error();
    unsafe { LocalFree(descriptor) };
    if created == 0 { Err(err) } else { Ok(()) }
}

#[cfg(windows)]
fn current_user_sid() -> io::Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: plain Win32 calls with out-pointers to locals; the token
    // handle is closed before returning.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        let err = io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(err);
        }
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        let mut text: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut n = 0;
        while *text.add(n) != 0 {
            n += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text.cast());
        Ok(sid)
    }
}

/// After a file leaves the private staging directory, its access rights
/// should be those of its new parent, like any file created there. On
/// Windows the moved file keeps the staging DACL until it is told to
/// inherit again; on Unix the mode set before publishing is the whole story.
#[cfg(windows)]
pub fn inherit_parent_acl(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows_sys::Win32::Security::{
        ACL, ACL_REVISION, DACL_SECURITY_INFORMATION, InitializeAcl,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    let mut empty = [0u8; std::mem::size_of::<ACL>()];
    let path = wide(path);
    // SAFETY: the buffer is at least sizeof(ACL) and the path is
    // NUL-terminated; an empty unprotected DACL means "inherit only".
    unsafe {
        if InitializeAcl(empty.as_mut_ptr().cast(), empty.len() as u32, ACL_REVISION) == 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            empty.as_ptr().cast(),
            std::ptr::null_mut(),
        );
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn inherit_parent_acl(_: &Path) -> io::Result<()> {
    Ok(())
}

/// Opens `path` for reading and writing, creating it readable by its
/// owner only when `create` is set, and never truncating it.
pub fn open_private(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Takes an exclusive lock on `file` without waiting; `Ok(false)` means
/// another process holds it. The lock lasts until `file` is dropped.
#[cfg(unix)]
pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    // SAFETY: flock on a valid descriptor.
    match unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } {
        0 => Ok(true),
        _ => {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(windows)]
pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: OVERLAPPED is plain data and the handle is valid.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok != 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// The process umask, so a published file gets the mode `creat` would
/// have given it.
#[cfg(unix)]
pub fn umask() -> u32 {
    // SAFETY: umask is always safe to call; the mask is restored at once.
    unsafe {
        let mask = libc::umask(0o077);
        libc::umask(mask);
        mask as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mjolnir-fsops-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rename_without_replace_keeps_an_existing_target() {
        let d = dir("rename");
        let (from, to) = (d.join("from"), d.join("to"));
        fs::write(&from, b"new").unwrap();
        fs::write(&to, b"old").unwrap();
        assert!(rename_durable(&from, &to, false).is_err());
        assert_eq!(fs::read(&to).unwrap(), b"old");
        assert!(from.exists());
        rename_durable(&from, &to, true).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"new");
        assert!(!from.exists());
        fs::write(&from, b"again").unwrap();
        fs::remove_file(&to).unwrap();
        rename_durable(&from, &to, false).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"again");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_lock_is_exclusive_across_handles() {
        let d = dir("lock");
        let path = d.join("lock");
        let a = open_private(&path, true).unwrap();
        assert!(try_lock_exclusive(&a).unwrap());
        let b = open_private(&path, true).unwrap();
        assert!(!try_lock_exclusive(&b).unwrap());
        drop(a);
        assert!(try_lock_exclusive(&b).unwrap());
        drop(b);
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_and_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("private");
        let p = d.join("staging");
        create_private_dir(&p).unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let f = p.join("part");
        drop(open_private(&f, true).unwrap());
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(d).unwrap();
    }

    /// The staging directory's DACL names only this user and SYSTEM, and a
    /// file moved out of it goes back to inheriting from its new parent.
    #[cfg(windows)]
    #[test]
    fn private_dir_acl_is_owner_only_and_published_files_inherit_again() {
        let d = dir("acl");
        let p = d.join("staging");
        create_private_dir(&p).unwrap();
        let icacls = |path: &Path| {
            let out = std::process::Command::new("icacls")
                .arg(path)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).to_string()
        };
        let listing = icacls(&p);
        for group in ["BUILTIN\\Users", "Everyone", "Authenticated Users"] {
            assert!(!listing.contains(group), "{listing}");
        }
        assert!(listing.contains("NT AUTHORITY\\SYSTEM"), "{listing}");
        let f = p.join("part");
        drop(open_private(&f, true).unwrap());
        let staged = icacls(&f);
        assert!(!staged.contains("BUILTIN\\Users"), "{staged}");
        let published = d.join("published");
        rename_durable(&f, &published, false).unwrap();
        inherit_parent_acl(&published).unwrap();
        let after = icacls(&published);
        assert!(after.contains("(I)"), "{after}");
        assert_eq!(
            after.contains("BUILTIN\\Users"),
            icacls(&d).contains("BUILTIN\\Users"),
            "{after}"
        );
        fs::remove_dir_all(d).unwrap();
    }
}
