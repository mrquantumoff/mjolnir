//! Reading and writing Windows access lists: the key-file checks, and the
//! check that nobody but SYSTEM, Administrators, and TrustedInstaller can
//! change what a service running as SYSTEM trusts.

use std::ffi::{OsStr, c_void};
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::ptr::null_mut;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation,
    INHERIT_ONLY_ACE, INHERITED_ACE, IsWellKnownSid, LookupAccountSidW, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`,
/// which share the `ACCESS_ALLOWED_ACE` layout.
const ALLOW_TYPES: [u8; 2] = [0, 9];
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const OWNER_RIGHTS: &str = "S-1-3-4";

/// Rights on a file that change it, or on a folder that change or add to
/// what it holds.
const CHANGE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
/// Rights on a folder above a path that let an account move what the path
/// names aside and put something else there.
const REPLACE: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

/// Memory the system allocated with `LocalAlloc`.
pub(crate) struct Local(pub(crate) *mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

pub(crate) fn check_bool(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// The `TOKEN_USER` of this process, in a buffer that keeps its SID alive.
pub(crate) struct CurrentUser(Vec<u64>);

impl CurrentUser {
    pub(crate) fn get() -> io::Result<CurrentUser> {
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

    pub(crate) fn sid(&self) -> PSID {
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

pub(crate) fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    check_bool(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
    let _free = Local(text.cast());
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, len)
    }))
}

/// `DOMAIN\name (SID)`, or the SID alone when it names no account.
pub(crate) fn account(sid: PSID) -> io::Result<String> {
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

/// A security descriptor built from SDDL.
pub(crate) fn descriptor(sddl: &str) -> io::Result<Local> {
    let mut sd = null_mut();
    check_bool(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl.as_ref()).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    })?;
    Ok(Local(sd))
}

/// The owner and DACL of an open handle; both point into `_sd`.
pub(crate) struct Security {
    pub(crate) owner: PSID,
    pub(crate) dacl: *mut ACL,
    _sd: Local,
}

impl Security {
    pub(crate) fn of(handle: HANDLE) -> io::Result<Security> {
        let (mut owner, mut dacl, mut sd): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) =
            (null_mut(), null_mut(), null_mut());
        let err = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if err != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        Ok(Security {
            owner,
            dacl,
            _sd: Local(sd),
        })
    }

    /// The allow entries that apply to the object itself: each SID, its
    /// rights, and whether it was inherited. `None` for a null DACL, which
    /// allows everything to everyone.
    pub(crate) fn allowed(&self) -> io::Result<Option<Vec<(PSID, u32, bool)>>> {
        if self.dacl.is_null() {
            return Ok(None);
        }
        let mut allowed = Vec::new();
        for i in 0..unsafe { (*self.dacl).AceCount } {
            let mut ace = null_mut();
            check_bool(unsafe { GetAce(self.dacl, u32::from(i), &mut ace) })?;
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            let flags = u32::from(header.AceFlags);
            if !ALLOW_TYPES.contains(&header.AceType) || flags & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            let allow = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid: PSID = (&raw const allow.SidStart).cast_mut().cast();
            allowed.push((sid, allow.Mask, flags & INHERITED_ACE != 0));
        }
        Ok(Some(allowed))
    }
}

/// SYSTEM, Administrators, or TrustedInstaller.
fn is_admin(sid: PSID) -> io::Result<bool> {
    Ok(unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    } || sid_string(sid)? == TRUSTED_INSTALLER)
}

/// Opens `path` itself, not what a link there points to, to read its
/// security.
fn open_for_security(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::io::FromRawHandle;
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}

/// The accounts other than SYSTEM, Administrators, and TrustedInstaller
/// that can change `path`, add files to it if it is a folder, or replace
/// it through a folder above it, each with where it can. Empty when there
/// are none. Refuses a path that is itself a link.
pub(crate) fn outside_writers(path: &Path) -> Result<Vec<String>> {
    use std::os::windows::io::AsRawHandle;
    let path = std::path::absolute(path)?;
    let meta =
        fs::symlink_metadata(&path).with_context(|| format!("reading {}", path.display()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("{} is a link (a reparse point)", path.display());
    }
    let mut found = Vec::new();
    let levels = std::iter::once((path.as_path(), CHANGE))
        .chain(path.ancestors().skip(1).map(|dir| (dir, REPLACE)));
    for (at, rights) in levels {
        let file = open_for_security(at)
            .with_context(|| format!("reading the permissions of {}", at.display()))?;
        let security = Security::of(file.as_raw_handle())?;
        let mut note = |who: String| {
            let entry = format!("{who} on {}", at.display());
            if !found.contains(&entry) {
                found.push(entry);
            }
        };
        let owner_trusted = is_admin(security.owner)?;
        if !owner_trusted {
            note(format!("owner {}", account(security.owner)?));
        }
        let Some(allowed) = security.allowed()? else {
            note("everyone (no access list)".into());
            continue;
        };
        for (sid, mask, _) in allowed {
            // OWNER RIGHTS grants whoever owns it, judged above.
            let owner_rights = sid_string(sid)? == OWNER_RIGHTS;
            if mask & rights != 0 && !is_admin(sid)? && !(owner_rights && owner_trusted) {
                note(account(sid)?);
            }
        }
    }
    Ok(found)
}

/// Creates the folder `dir`, owned by Administrators, with an access list
/// that inherits nothing: full control for SYSTEM and Administrators, read
/// and execute for Users. Setting that owner needs an elevated process.
pub(crate) fn create_protected_dir(dir: &Path) -> io::Result<()> {
    let sd = descriptor("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    check_bool(unsafe { CreateDirectoryW(wide(dir.as_os_str()).as_ptr(), &attrs) })
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;

    fn icacls(path: &Path, args: &[&str]) {
        let status = Command::new("icacls")
            .arg(path)
            .args(args)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn a_file_everyone_can_write_has_outside_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized.txt");
        fs::write(&path, "").unwrap();
        icacls(&path, &["/grant", "*S-1-1-0:W"]);
        let found = outside_writers(&path).unwrap();
        assert!(
            found
                .iter()
                .any(|w| w.contains("S-1-1-0") && w.contains("authorized.txt")),
            "{found:?}"
        );
    }

    #[test]
    fn system_files_have_none() {
        let root = std::env::var_os("SystemRoot").unwrap();
        let system32 = Path::new(&root).join("System32");
        for path in [system32.join("cmd.exe"), system32] {
            assert_eq!(
                outside_writers(&path).unwrap(),
                Vec::<String>::new(),
                "{path:?}"
            );
        }
    }

    #[test]
    fn a_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(std::env::var_os("SystemRoot").unwrap())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let err = format!("{:#}", outside_writers(&link).unwrap_err());
        assert!(err.contains("reparse point"), "{err}");
    }
}
