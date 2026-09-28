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
pub(super) use windows::{check, create};

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr::null_mut;

    use anyhow::{Context, Result, bail};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_SUCCESS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetTokenInformation, INHERIT_ONLY_ACE, INHERITED_ACE, IsWellKnownSid, LookupAccountSidW,
        PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_READ_DATA,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, WRITE_DAC,
        WRITE_OWNER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`,
    /// which share the `ACCESS_ALLOWED_ACE` layout.
    const ALLOW_TYPES: [u8; 2] = [0, 9];
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

    /// Memory the system allocated with `LocalAlloc`.
    struct Local(*mut c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    fn check_bool(ok: i32) -> io::Result<()> {
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// The `TOKEN_USER` of this process, in a buffer that keeps its SID alive.
    struct CurrentUser(Vec<u64>);

    impl CurrentUser {
        fn get() -> io::Result<CurrentUser> {
            let mut token: HANDLE = null_mut();
            check_bool(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
            let mut len = 0u32;
            unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            let ok = unsafe {
                GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
            };
            unsafe { CloseHandle(token) };
            check_bool(ok)?;
            Ok(CurrentUser(buf))
        }

        fn sid(&self) -> PSID {
            unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
        }
    }

    fn sid_string(sid: PSID) -> io::Result<String> {
        let mut text = null_mut();
        check_bool(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
        let _free = Local(text.cast());
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text, len)
        }))
    }

    /// `DOMAIN\name (SID)`, or the SID alone when it names no account.
    fn account(sid: PSID) -> io::Result<String> {
        let sid_text = sid_string(sid)?;
        let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
        let (mut name_len, mut domain_len, mut kind) = (256u32, 256u32, 0);
        let found = unsafe {
            LookupAccountSidW(
                null_mut(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        } != 0;
        if !found {
            return Ok(sid_text);
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        Ok(match domain.is_empty() {
            true => format!("{name} ({sid_text})"),
            false => format!("{domain}\\{name} ({sid_text})"),
        })
    }

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain([0]).collect()
    }

    /// Creates `path` with a protected DACL, so nothing is inherited from
    /// the directory: full control for this user, SYSTEM, and
    /// Administrators, and no access for anyone else. The DACL is part of
    /// the create call, so no other account can open the file in between.
    pub(in crate::keys) fn create(path: &Path) -> io::Result<File> {
        let user = CurrentUser::get()?;
        let sddl = format!(
            "D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)",
            sid_string(user.sid())?
        );
        let mut sd = null_mut();
        check_bool(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl.as_ref()).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        })?;
        let sd = Local(sd);
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
        let mut dacl: *mut ACL = null_mut();
        let mut sd = null_mut();
        let err = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if err != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(err as i32))
                .with_context(|| format!("reading the permissions of {}", path.display()));
        }
        let _free = Local(sd);
        let user = CurrentUser::get()?;
        let fix = |explicit: &[String]| {
            let sids: String = explicit.iter().map(|sid| format!(" \"*{sid}\"")).collect();
            let remove = match explicit {
                [] => String::new(),
                _ => format!(" /remove{sids}"),
            };
            format!(
                "restrict it with `icacls \"{}\" /inheritance:r /grant:r \"*{}:F\"{remove}`",
                path.display(),
                sid_string(user.sid()).unwrap_or_default()
            )
        };
        if dacl.is_null() {
            bail!(
                "private key {} has no access list, so every account can read it; {}",
                path.display(),
                fix(&[])
            );
        }
        // `/inheritance:r` drops inherited entries; explicit ones need `/remove`.
        let (mut names, mut explicit) = (Vec::new(), Vec::new());
        for i in 0..unsafe { (*dacl).AceCount } {
            let mut ace = null_mut();
            check_bool(unsafe { GetAce(dacl, u32::from(i), &mut ace) })?;
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            let flags = u32::from(header.AceFlags);
            if !ALLOW_TYPES.contains(&header.AceType) || flags & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            let allow = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid: PSID = (&raw const allow.SidStart).cast_mut().cast();
            let trusted = unsafe {
                EqualSid(sid, user.sid()) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            };
            if !trusted && allow.Mask & SENSITIVE != 0 {
                names.push(account(sid)?);
                let sid = sid_string(sid)?;
                if flags & INHERITED_ACE == 0 && !explicit.contains(&sid) {
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
