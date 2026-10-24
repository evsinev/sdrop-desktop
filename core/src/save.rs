//! Saving a received secret to a path the user chose in the save dialog (SPEC 8): readable only by
//! the user, also when an existing file is replaced. The data goes to a new file in the same
//! directory with private permissions set before any byte is written, then replaces the target.
//! If the permissions cannot be set, nothing is written.

use std::io::Write;
use std::path::{Path, PathBuf};

/// A file name for the save dialog from the sender's name (already a valid FORMAT.md name):
/// characters no OS accepts are replaced, Windows reserved names and trailing dots are avoided.
pub fn suggested_name(sender: &str) -> String {
    let mut s: String = sender
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        s.insert(0, '_');
    }
    if s.is_empty() || s.starts_with('.') && s.chars().all(|c| c == '.') {
        s = "file".into();
    }
    s
}

fn temp_path(target: &Path) -> std::io::Result<PathBuf> {
    let dir = target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| std::io::Error::other("no directory"))?;
    Ok(dir.join(format!(
        ".pnesecrets-{}.tmp",
        crate::history::new_local_id()
    )))
}

/// Writes `bytes` to `target` (replacing it), private to the current user.
pub fn save_private(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_path(target)?;
    let r = (|| {
        let mut f = create_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, target)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Windows: the file is created with a protected DACL granting only the current user (no
/// inherited entries from a shared directory).
#[cfg(windows)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_ALL, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        ACL, ACL_REVISION, AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl,
        InitializeSecurityDescriptor, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL};
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let err = std::io::Error::last_os_error;
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(err());
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return Err(err());
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = user.User.Sid;
        let acl_len = std::mem::size_of::<ACL>() as u32 + 16 + GetLengthSid(sid);
        let mut acl_buf = vec![0u8; acl_len as usize];
        let acl = acl_buf.as_mut_ptr() as *mut ACL;
        if InitializeAcl(acl, acl_len, ACL_REVISION) == 0
            || AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid) == 0
        {
            return Err(err());
        }
        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        let psd = &mut sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void;
        if InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) == 0
            || SetSecurityDescriptorDacl(psd, 1, acl, 0) == 0
            || SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED) == 0
        {
            return Err(err());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let h = CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return Err(err());
        }
        Ok(std::fs::File::from_raw_handle(h as _))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggested_names() {
        assert_eq!(suggested_name("stage-ca.pem"), "stage-ca.pem");
        assert_eq!(suggested_name("a:b?c*.txt"), "a_b_c_.txt");
        assert_eq!(suggested_name("CON"), "_CON");
        assert_eq!(suggested_name("com1.txt"), "_com1.txt");
        assert_eq!(suggested_name("COM10"), "COM10");
        assert_eq!(suggested_name("notes.txt. "), "notes.txt");
        assert_eq!(suggested_name("..."), "file");
        assert_eq!(suggested_name("a\u{1}b"), "a_b");
    }

    #[test]
    fn saved_file_is_private_and_replaces() {
        let dir = std::env::temp_dir().join(format!(
            "pnesecrets-save-{}",
            crate::history::new_local_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("out.bin");
        // An existing file with wide permissions is replaced, not reused.
        std::fs::write(&target, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        save_private(&target, b"secret bytes").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"secret bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let leftovers = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1, "no temp file left");
        // A directory that cannot be written: an error, the target untouched.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            assert!(save_private(&target, b"new").is_err());
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"secret bytes");
        }
        std::fs::remove_file(&target).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
