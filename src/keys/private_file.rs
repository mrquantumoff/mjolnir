//! Key files only their owner can use: created with mode 0600 on Unix and
//! with a protected DACL on Windows, and refused on load when another
//! account can read or change them.

#[cfg(unix)]
pub(super) use unix::{check, create};

#[cfg(unix)]
mod unix {
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    use anyhow::{Result, bail};

    pub(in crate::keys) fn create(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    /// Fails when group or other has any access, as OpenSSH does.
    pub(in crate::keys) fn check(file: &File, path: &Path) -> Result<()> {
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "private key {} is accessible by other users (mode {mode:03o}); \
                 restrict it with `chmod 600 {}`",
                path.display(),
                path.display()
            );
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(super) use windows::{check, check_for_local_system, create, create_for_system};

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr::null_mut;

    use anyhow::{Context, Result, bail};
    use windows_sys::Win32::Foundation::{
        GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, IsWellKnownSid, PSID, SECURITY_ATTRIBUTES,
        SECURITY_MAX_SID_SIZE, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_READ_DATA,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, WRITE_DAC,
        WRITE_OWNER,
    };

    use crate::winacl::{CurrentUser, Security, account, check_bool, descriptor, sid_string, wide};

    /// Rights that let an account read the key, replace it, or grant
    /// itself either.
    const SENSITIVE: u32 = FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_READ
        | GENERIC_WRITE
        | GENERIC_ALL;

    /// Creates `path` with a protected DACL, so nothing is inherited from
    /// the directory: full control for this user, SYSTEM, and
    /// Administrators, and no access for anyone else. The DACL is part of
    /// the create call, so no other account can open the file in between.
    pub(in crate::keys) fn create(path: &Path) -> io::Result<File> {
        let user = CurrentUser::get()?;
        create_with(
            path,
            &format!(
                "D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)",
                sid_string(user.sid())?
            ),
        )
    }

    /// Like [`create`], but owned by Administrators and usable only by
    /// SYSTEM and Administrators. Setting that owner needs an elevated
    /// process.
    pub(in crate::keys) fn create_for_system(path: &Path) -> io::Result<File> {
        create_with(path, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
    }

    fn create_with(path: &Path, sddl: &str) -> io::Result<File> {
        let sd = descriptor(sddl)?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateFileW(
                wide(path.as_os_str()).as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    /// Fails when an allow entry in the file's DACL gives an account other
    /// than this user, SYSTEM, or Administrators a right in `SENSITIVE`.
    pub(in crate::keys) fn check(file: &File, path: &Path) -> Result<()> {
        check_for(file, path, CurrentUser::get()?.sid())
    }

    /// [`check`] as a process running as LocalSystem would make it.
    pub(in crate::keys) fn check_for_local_system(file: &File, path: &Path) -> Result<()> {
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = SECURITY_MAX_SID_SIZE;
        check_bool(unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                sid.as_mut_ptr().cast(),
                &mut len,
            )
        })?;
        check_for(file, path, sid.as_mut_ptr().cast())
    }

    /// Fails when an allow entry in the file's DACL gives an account other
    /// than `reader`, SYSTEM, or Administrators a right in `SENSITIVE`.
    fn check_for(file: &File, path: &Path, reader: PSID) -> Result<()> {
        let security = Security::of(file.as_raw_handle())
            .with_context(|| format!("reading the permissions of {}", path.display()))?;
        let fix = |explicit: &[String]| {
            let sids: String = explicit.iter().map(|sid| format!(" \"*{sid}\"")).collect();
            let remove = match explicit {
                [] => String::new(),
                _ => format!(" /remove{sids}"),
            };
            format!(
                "restrict it with `icacls \"{}\" /inheritance:r /grant:r \"*{}:F\"{remove}`",
                path.display(),
                sid_string(reader).unwrap_or_default()
            )
        };
        let Some(allowed) = security.allowed()? else {
            bail!(
                "private key {} has no access list, so every account can read it; {}",
                path.display(),
                fix(&[])
            );
        };
        // `/inheritance:r` drops inherited entries; explicit ones need `/remove`.
        let (mut names, mut explicit) = (Vec::new(), Vec::new());
        for (sid, mask, inherited) in allowed {
            let trusted = unsafe {
                EqualSid(sid, reader) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            };
            if !trusted && mask & SENSITIVE != 0 {
                names.push(account(sid)?);
                let sid = sid_string(sid)?;
                if !inherited && !explicit.contains(&sid) {
                    explicit.push(sid);
                }
            }
        }
        if !names.is_empty() {
            bail!(
                "private key {} is accessible by other accounts ({}); {}",
                path.display(),
                names.join(", "),
                fix(&explicit)
            );
        }
        Ok(())
    }
}
