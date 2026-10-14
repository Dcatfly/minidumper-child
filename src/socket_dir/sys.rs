//! The Windows system calls used to choose the socket directory.

use std::{
    ffi::{c_void, OsString},
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr,
};

use windows_sys::{
    core::{GUID, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, APPMODEL_ERROR_NO_PACKAGE, ERROR_ALREADY_EXISTS,
            ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
        },
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::{
            FileSystem::{CreateDirectoryW, GetShortPathNameW},
            Packaging::Appx::GetCurrentPackageFamilyName,
        },
        System::{
            Com::CoTaskMemFree,
            SystemInformation::GetWindowsDirectoryW,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT},
    },
};

use super::{
    choose_socket_dir, fits, packaged_socket_file_name, private_dir_name, private_dir_sddl,
    PackageDirs, SocketDir,
};
use crate::OwnedSocketName;

/// How many random names to try when creating a private directory.
const PRIVATE_DIR_ATTEMPTS: usize = 8;

/// Returns `path` as a NUL terminated wide string.
fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Copies a NUL terminated wide string.
///
/// # Safety
///
/// `ptr` must point to a valid NUL terminated wide string.
unsafe fn from_wide_ptr(ptr: *const u16) -> OsString {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    OsString::from_wide(std::slice::from_raw_parts(ptr, len))
}

/// Frees memory allocated with `LocalAlloc` when dropped.
struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The pointer was allocated by the system with `LocalAlloc`
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Closes a handle when dropped.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: The handle is valid and owned by us
        unsafe { CloseHandle(self.0) };
    }
}

/// Returns the package family name, or `None` if the process has no package identity.
pub fn package_family_name() -> io::Result<Option<String>> {
    let mut len = 0u32;
    // SAFETY: A zero length with a null buffer queries the required length
    let rc = unsafe { GetCurrentPackageFamilyName(&mut len, ptr::null_mut()) };
    match rc {
        APPMODEL_ERROR_NO_PACKAGE => return Ok(None),
        ERROR_INSUFFICIENT_BUFFER => {}
        rc => return Err(io::Error::from_raw_os_error(rc as i32)),
    }

    let mut buf = vec![0u16; len as usize];
    // SAFETY: The buffer holds `len` wide characters
    let rc = unsafe { GetCurrentPackageFamilyName(&mut len, buf.as_mut_ptr()) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }

    // `len` includes the terminating NUL
    buf.truncate(len.saturating_sub(1) as usize);
    String::from_utf16(&buf)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid package family name"))
}

fn known_folder(id: &GUID) -> io::Result<PathBuf> {
    let mut path: PWSTR = ptr::null_mut();
    // SAFETY: `path` receives a string that has to be freed with `CoTaskMemFree`
    let hr =
        unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, ptr::null_mut(), &mut path) };

    let result = if hr >= 0 && !path.is_null() {
        // SAFETY: On success `path` is a NUL terminated wide string
        Ok(PathBuf::from(unsafe { from_wide_ptr(path) }))
    } else {
        Err(io::Error::other(format!(
            "SHGetKnownFolderPath failed: {hr:#010x}"
        )))
    };

    // SAFETY: The string must be freed even if the call failed, freeing null is a no-op
    unsafe { CoTaskMemFree(path as *const c_void) };

    result
}

/// Returns the user's local application data directory, e.g. `C:\Users\me\AppData\Local`.
pub fn local_app_data_dir() -> io::Result<PathBuf> {
    known_folder(&FOLDERID_LocalAppData)
}

/// Returns the `TempState` directory of the package with the given family name.
///
/// This is the same path as `ApplicationData.Current.TemporaryFolder`.
pub fn temp_state_dir(package_family_name: &str) -> io::Result<PathBuf> {
    Ok(local_app_data_dir()?
        .join("Packages")
        .join(package_family_name)
        .join("TempState"))
}

/// Returns the 8.3 short form of an existing path.
///
/// Returns the path unchanged if the volume has no short names.
pub fn short_path_name(path: &Path) -> io::Result<PathBuf> {
    let wide = to_wide(path);

    // SAFETY: A zero length with a null buffer queries the required length
    let mut len = unsafe { GetShortPathNameW(wide.as_ptr(), ptr::null_mut(), 0) };

    // The path could change between calls, so retry a few times
    for _ in 0..4 {
        if len == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf = vec![0u16; len as usize];
        // SAFETY: The buffer holds `len` wide characters
        let written = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), len) };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }

        // On success the length excludes the NUL, otherwise it's the required length
        if written < len {
            buf.truncate(written as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        len = written;
    }

    Err(io::Error::other("GetShortPathNameW kept growing"))
}

/// Returns the Windows directory, e.g. `C:\Windows`.
pub fn windows_dir() -> io::Result<PathBuf> {
    let mut len = 260u32;

    for _ in 0..4 {
        let mut buf = vec![0u16; len as usize];
        // SAFETY: The buffer holds `len` wide characters
        let written = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), len) };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }

        // On success the length excludes the NUL, otherwise it's the required length
        if written < len {
            buf.truncate(written as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        len = written;
    }

    Err(io::Error::other("GetWindowsDirectoryW kept growing"))
}

/// Returns the SID of the user the process runs as, e.g. `S-1-5-21-…-1001`.
pub fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that doesn't need closing
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);

    let mut len = 0u32;
    // SAFETY: A zero length with a null buffer queries the required length
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }

    // Use `u64` so the buffer is aligned for `TOKEN_USER`
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: The buffer holds at least `len` bytes
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: On success the buffer starts with a `TOKEN_USER`
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut sid_string: PWSTR = ptr::null_mut();
    // SAFETY: `sid` points into `buf` which is still alive
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_string = LocalMem(sid_string.cast());

    // SAFETY: On success this is a NUL terminated wide string
    let sid = unsafe { from_wide_ptr(sid_string.0.cast()) };
    sid.into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SID"))
}

/// Creates a directory with the security descriptor given as SDDL.
///
/// Fails with `ERROR_ALREADY_EXISTS` if the path already exists.
pub fn create_dir_with_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();

    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `descriptor` receives memory that has to be freed with `LocalFree`
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalMem(descriptor);

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };

    let wide = to_wide(path);
    // SAFETY: Both pointers are valid for the duration of the call
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Returns the owner and DACL of a file or directory as SDDL.
pub fn owner_and_dacl_sddl(path: &Path) -> io::Result<String> {
    let wide = to_wide(path);
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `descriptor` receives memory that has to be freed with `LocalFree`, `owner`
    // and `dacl` point into it
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            info,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let descriptor = LocalMem(descriptor);

    let mut sddl: PWSTR = ptr::null_mut();
    // SAFETY: `sddl` receives memory that has to be freed with `LocalFree`
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            info,
            &mut sddl,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sddl = LocalMem(sddl.cast());

    // SAFETY: On success this is a NUL terminated wide string
    let sddl = unsafe { from_wide_ptr(sddl.0.cast()) };
    sddl.into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SDDL"))
}

/// Creates a private directory that only the current user and `SYSTEM` can access.
///
/// `first` is tried first. If it already exists a new random name in the same parent
/// directory is tried, a few times. An existing directory is never reused, as someone else
/// may control it.
pub fn create_private_dir_at(first: &Path) -> io::Result<PathBuf> {
    let parent = first
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    let sddl = private_dir_sddl(&current_user_sid()?);

    let mut candidate = first.to_path_buf();
    let mut last_err = None;

    for _ in 0..PRIVATE_DIR_ATTEMPTS {
        match create_dir_with_sddl(&candidate, &sddl) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) => {
                last_err = Some(err);
                candidate = parent.join(private_dir_name(uuid::Uuid::new_v4()));
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)))
}

/// Creates a private directory with a random name in `parent`.
pub fn create_private_dir(parent: &Path) -> io::Result<PathBuf> {
    create_private_dir_at(&parent.join(private_dir_name(uuid::Uuid::new_v4())))
}

/// Returns the parent directory for private socket directories, `<Windows>\Temp`.
///
/// This is not the user's temporary directory, which is what `GetTempPath2W` returns for
/// processes not running as `SYSTEM`.
pub fn private_dir_parent() -> io::Result<PathBuf> {
    Ok(windows_dir()?.join("Temp"))
}

/// Gathers the facts needed to choose the socket directory of a packaged process.
pub fn package_dirs(package_family_name: &str) -> PackageDirs {
    let temp_state_long = temp_state_dir(package_family_name)
        .ok()
        // Don't create it, it is owned by the system
        .filter(|dir| dir.is_dir());

    let temp_state_short = temp_state_long
        .as_deref()
        .and_then(|dir| short_path_name(dir).ok());

    let private_dir = private_dir_parent()
        .ok()
        .map(|parent| parent.join(private_dir_name(uuid::Uuid::new_v4())));

    PackageDirs {
        temp_state_long,
        temp_state_short,
        private_dir,
    }
}

/// Returns the socket name for a packaged process, or `None` if the process has no package
/// identity or no packaged location works.
pub fn packaged_socket_name(session_id: uuid::Uuid) -> Option<OwnedSocketName> {
    let package_family_name = package_family_name().ok()??;
    let file_name = packaged_socket_file_name(session_id);

    match choose_socket_dir(Some(&package_dirs(&package_family_name)), &file_name) {
        SocketDir::Existing(dir) => Some(OwnedSocketName::Path(dir.join(file_name))),
        SocketDir::CreatePrivate(dir) => {
            let dir = create_private_dir_at(&dir).ok()?;
            let path = dir.join(&file_name);
            if fits(&path) {
                Some(OwnedSocketName::Path(path))
            } else {
                let _ = std::fs::remove_dir(&dir);
                None
            }
        }
        SocketDir::SystemTemp => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

    use super::*;
    use crate::socket_dir::is_private_dir_name;

    /// Splits SDDL with an owner and a DACL into the owner, the DACL flags and the ACEs.
    fn parse_sddl(sddl: &str) -> (String, String, BTreeSet<String>) {
        let rest = sddl.strip_prefix("O:").expect("no owner");
        let (owner, dacl) = rest.split_once("D:").expect("no DACL");
        let (flags, aces) = dacl.split_at(dacl.find('(').unwrap_or(dacl.len()));
        let aces = aces
            .split(')')
            .filter(|ace| !ace.is_empty())
            .map(|ace| format!("{ace})"))
            .collect();
        (owner.to_owned(), flags.to_owned(), aces)
    }

    #[test]
    fn private_dir_is_owned_by_user_and_only_accessible_by_user_and_system() {
        let sid = current_user_sid().unwrap();
        let parent = private_dir_parent().unwrap();

        let dir = create_private_dir(&parent).unwrap();
        let sddl = owner_and_dacl_sddl(&dir);
        let removed = fs::remove_dir(&dir);

        assert!(dir.starts_with(&parent));
        assert!(is_private_dir_name(dir.file_name().unwrap()));

        let sddl = sddl.unwrap();
        let (owner, flags, aces) = parse_sddl(&sddl);
        assert_eq!(owner, sid, "{sddl}");
        assert!(flags.contains('P'), "DACL should be protected: {sddl}");
        assert_eq!(
            aces,
            BTreeSet::from([
                format!("(A;OICI;FA;;;{sid})"),
                "(A;OICI;FA;;;SY)".to_owned()
            ]),
            "{sddl}"
        );

        removed.expect("private directory should be removable");
        assert!(!dir.exists());
    }

    #[test]
    fn private_dirs_are_unique() {
        let parent = private_dir_parent().unwrap();

        let first = create_private_dir(&parent).unwrap();
        let second = create_private_dir(&parent);
        // Asking for an existing directory never reuses it
        let third = create_private_dir_at(&first);

        let _ = fs::remove_dir(&first);
        if let Ok(second) = &second {
            let _ = fs::remove_dir(second);
        }
        if let Ok(third) = &third {
            let _ = fs::remove_dir(third);
        }

        let second = second.unwrap();
        let third = third.unwrap();
        assert_ne!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn short_path_name_of_existing_dir() {
        for dir in [windows_dir().unwrap(), std::env::temp_dir()] {
            let short = short_path_name(&dir).unwrap();
            assert!(!short.as_os_str().is_empty());
            assert!(short.is_dir(), "{short:?} from {dir:?}");
        }
    }

    #[test]
    fn short_path_name_of_missing_path_fails() {
        let missing = std::env::temp_dir().join(private_dir_name(uuid::Uuid::new_v4()));
        assert!(short_path_name(&missing).is_err());
    }

    #[test]
    fn package_identity_matches_environment() {
        // Works with and without package identity
        let package_family_name = package_family_name().unwrap();

        if let Some(package_family_name) = package_family_name {
            assert!(!package_family_name.is_empty());
            // The system creates `TempState` for every package
            let temp_state = temp_state_dir(&package_family_name).unwrap();
            assert!(temp_state.is_dir(), "{temp_state:?}");
        }
    }

    #[test]
    fn packaged_socket_name_is_only_used_with_package_identity() {
        let socket_name = packaged_socket_name(uuid::Uuid::new_v4());

        match package_family_name().unwrap() {
            None => assert_eq!(socket_name, None),
            Some(package_family_name) => {
                let Some(OwnedSocketName::Path(path)) = socket_name else {
                    panic!("expected a packaged socket path, got {socket_name:?}");
                };
                crate::socket_dir::remove_private_socket_dir(&OwnedSocketName::Path(path.clone()));

                assert!(fits(&path), "{path:?}");
                let dir = path.parent().unwrap();
                let temp_state = temp_state_dir(&package_family_name).unwrap();
                let in_temp_state =
                    dir == temp_state || Some(dir) == short_path_name(&temp_state).ok().as_deref();
                let in_private_dir = is_private_dir_name(dir.file_name().unwrap());
                assert!(in_temp_state || in_private_dir, "{path:?}");
            }
        }
    }
}
