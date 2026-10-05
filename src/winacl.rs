//! Reading and writing Windows access lists.

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation,
    INHERIT_ONLY_ACE, INHERITED_ACE, LookupAccountSidW, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`,
/// which share the `ACCESS_ALLOWED_ACE` layout.
const ALLOW_TYPES: [u8; 2] = [0, 9];

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

/// The DACL of an open handle, which points into `_sd`.
pub(crate) struct Security {
    pub(crate) dacl: *mut ACL,
    _sd: Local,
}

impl Security {
    pub(crate) fn of(handle: HANDLE) -> io::Result<Security> {
        let (mut dacl, mut sd): (*mut ACL, PSECURITY_DESCRIPTOR) = (null_mut(), null_mut());
        let err = unsafe {
            GetSecurityInfo(
                handle,
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
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        Ok(Security {
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
