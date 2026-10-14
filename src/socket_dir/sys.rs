//! The Windows system calls used to choose the socket directory.

use std::{
    ffi::{c_void, OsString},
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr,
};

use super::{choose_socket_dir, packaged_socket_file_name, PackageDirs, SocketDir};
use crate::OwnedSocketName;

/// Hand written bindings, so no extra dependency is needed for four functions.
///
/// The signatures follow the Microsoft Learn documentation of each function and match the
/// declarations in `windows-sys` 0.61.
mod bindings {
    use std::ffi::c_void;

    /// `GUID` from `guiddef.h`
    #[repr(C)]
    pub struct Guid {
        pub data1: u32,
        pub data2: u16,
        pub data3: u16,
        pub data4: [u8; 8],
    }

    /// `FOLDERID_LocalAppData` from `KnownFolders.h`,
    /// `{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}`
    pub const FOLDERID_LOCAL_APP_DATA: Guid = Guid {
        data1: 0xf1b32785,
        data2: 0x6fba,
        data3: 0x4fcf,
        data4: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
    };

    /// `KF_FLAG_DEFAULT` from `ShlObj_core.h`
    pub const KF_FLAG_DEFAULT: u32 = 0;
    /// `ERROR_INSUFFICIENT_BUFFER` from `winerror.h`
    pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
    /// `APPMODEL_ERROR_NO_PACKAGE` from `winerror.h`
    pub const APPMODEL_ERROR_NO_PACKAGE: i32 = 15700;
    /// `ERROR_SUCCESS` from `winerror.h`
    pub const ERROR_SUCCESS: i32 = 0;

    #[link(name = "kernel32")]
    extern "system" {
        /// `LONG GetCurrentPackageFamilyName(UINT32 *packageFamilyNameLength,
        /// PWSTR packageFamilyName)` from `appmodel.h`.
        ///
        /// `windows-sys` declares the return type as `WIN32_ERROR` (`u32`), which has the
        /// same ABI as `LONG`.
        pub fn GetCurrentPackageFamilyName(
            package_family_name_length: *mut u32,
            package_family_name: *mut u16,
        ) -> i32;

        /// `DWORD GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath,
        /// DWORD cchBuffer)` from `fileapi.h`
        pub fn GetShortPathNameW(
            long_path: *const u16,
            short_path: *mut u16,
            buffer_len: u32,
        ) -> u32;
    }

    #[link(name = "shell32")]
    extern "system" {
        /// `HRESULT SHGetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags,
        /// HANDLE hToken, PWSTR *ppszPath)` from `ShlObj_core.h`
        pub fn SHGetKnownFolderPath(
            rfid: *const Guid,
            flags: u32,
            token: *mut c_void,
            path: *mut *mut u16,
        ) -> i32;
    }

    #[link(name = "ole32")]
    extern "system" {
        /// `void CoTaskMemFree(LPVOID pv)` from `combaseapi.h`, in `Ole32.lib`.
        ///
        /// `windows-sys` links it from `combase.dll`, which `ole32.dll` forwards it to, and
        /// declares the pointer as `*const`, which has the same ABI.
        pub fn CoTaskMemFree(pv: *mut c_void);
    }
}

use bindings::*;

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

/// Returns the package family name, or `None` if the process has no package identity.
pub fn package_family_name() -> io::Result<Option<String>> {
    let mut len = 0u32;
    // SAFETY: A zero length with a null buffer queries the required length
    let rc = unsafe { GetCurrentPackageFamilyName(&mut len, ptr::null_mut()) };
    match rc {
        APPMODEL_ERROR_NO_PACKAGE => return Ok(None),
        ERROR_INSUFFICIENT_BUFFER => {}
        rc => return Err(io::Error::from_raw_os_error(rc)),
    }

    let mut buf = vec![0u16; len as usize];
    // SAFETY: The buffer holds `len` wide characters
    let rc = unsafe { GetCurrentPackageFamilyName(&mut len, buf.as_mut_ptr()) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc));
    }

    // `len` includes the terminating NUL
    buf.truncate(len.saturating_sub(1) as usize);
    String::from_utf16(&buf)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid package family name"))
}

/// Returns the user's local application data directory, e.g. `C:\Users\me\AppData\Local`.
pub fn local_app_data_dir() -> io::Result<PathBuf> {
    let mut path: *mut u16 = ptr::null_mut();
    // SAFETY: `path` receives a string that has to be freed with `CoTaskMemFree`
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LOCAL_APP_DATA,
            KF_FLAG_DEFAULT,
            ptr::null_mut(),
            &mut path,
        )
    };

    let result = if hr >= 0 && !path.is_null() {
        // SAFETY: On success `path` is a NUL terminated wide string
        Ok(PathBuf::from(unsafe { from_wide_ptr(path) }))
    } else {
        Err(io::Error::other(format!(
            "SHGetKnownFolderPath failed: {hr:#010x}"
        )))
    };

    // SAFETY: The string must be freed even if the call failed, freeing null is a no-op
    unsafe { CoTaskMemFree(path.cast::<c_void>()) };

    result
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

/// Gathers the facts needed to choose the socket directory of a packaged process.
pub fn package_dirs(package_family_name: &str) -> PackageDirs {
    let temp_state_long = temp_state_dir(package_family_name)
        .ok()
        // Don't create it, it is owned by the system
        .filter(|dir| dir.is_dir());

    let temp_state_short = temp_state_long
        .as_deref()
        .and_then(|dir| short_path_name(dir).ok());

    PackageDirs {
        temp_state_long,
        temp_state_short,
    }
}

/// Returns the socket name for a packaged process, or `None` if the process has no package
/// identity or the socket doesn't fit into `TempState`.
pub fn packaged_socket_name(session_id: uuid::Uuid) -> Option<OwnedSocketName> {
    let package_family_name = package_family_name().ok()??;
    let file_name = packaged_socket_file_name(session_id);

    match choose_socket_dir(Some(&package_dirs(&package_family_name)), &file_name) {
        SocketDir::Existing(dir) => Some(OwnedSocketName::Path(dir.join(file_name))),
        SocketDir::SystemTemp => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket_dir::fits;

    #[test]
    fn local_app_data_dir_matches_environment() {
        let dir = local_app_data_dir().unwrap();
        assert!(dir.is_dir(), "{dir:?}");

        // Both are the long form, inside and outside of packages. Windows paths are case
        // insensitive, so only the case of each component may differ.
        if let Some(env) = std::env::var_os("LOCALAPPDATA") {
            let env = PathBuf::from(env);
            assert!(paths_equal_ignoring_case(&dir, &env), "{dir:?} != {env:?}");
        }
    }

    /// Compares two paths component by component, ignoring case.
    fn paths_equal_ignoring_case(a: &Path, b: &Path) -> bool {
        let a: Vec<_> = a.components().collect();
        let b: Vec<_> = b.components().collect();
        a.len() == b.len()
            && a.iter().zip(&b).all(|(a, b)| {
                match (a.as_os_str().to_str(), b.as_os_str().to_str()) {
                    (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
                    _ => a == b,
                }
            })
    }

    #[test]
    fn paths_equal_ignoring_case_only_ignores_case() {
        let dir = Path::new(r"C:\Users\Me\AppData\Local");
        assert!(paths_equal_ignoring_case(
            dir,
            Path::new(r"c:\users\me\appdata\local")
        ));
        assert!(paths_equal_ignoring_case(
            dir,
            Path::new(r"C:\Users\Me\AppData\Local\")
        ));

        assert!(!paths_equal_ignoring_case(
            dir,
            Path::new(r"C:\Users\Me\AppData\Roaming")
        ));
        assert!(!paths_equal_ignoring_case(
            dir,
            Path::new(r"C:\Users\Me\AppData")
        ));
        assert!(!paths_equal_ignoring_case(
            dir,
            Path::new(r"C:\Users\Me\AppData\Local\x")
        ));
        assert!(!paths_equal_ignoring_case(
            dir,
            Path::new(r"C:\Users\Me\AppData\LocalLow")
        ));
    }

    #[test]
    fn short_path_name_of_existing_dir() {
        for dir in [local_app_data_dir().unwrap(), std::env::temp_dir()] {
            let short = short_path_name(&dir).unwrap();
            assert!(!short.as_os_str().is_empty());
            assert!(short.is_dir(), "{short:?} from {dir:?}");
        }
    }

    #[test]
    fn short_path_name_of_missing_path_fails() {
        let missing = std::env::temp_dir().join(format!("mdct-{}", uuid::Uuid::new_v4().simple()));
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

                assert!(fits(&path), "{path:?}");
                let dir = path.parent().unwrap();
                let temp_state = temp_state_dir(&package_family_name).unwrap();
                let short = short_path_name(&temp_state).ok();
                assert!(
                    dir == temp_state || Some(dir) == short.as_deref(),
                    "{path:?}"
                );
            }
        }
    }

    #[test]
    fn app_socket_name_is_unchanged_without_packaged_location() {
        let OwnedSocketName::Path(path) = crate::app_socket_name();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let parent = path.parent().map(Path::to_path_buf);

        // Packaged processes only fall back to the original name if `TempState` doesn't fit
        let packaged = package_family_name()
            .unwrap()
            .is_some_and(|package_family_name| {
                let file_name = packaged_socket_file_name(uuid::Uuid::nil());
                let dirs = package_dirs(&package_family_name);
                choose_socket_dir(Some(&dirs), &file_name) != SocketDir::SystemTemp
            });

        if !packaged {
            assert_eq!(parent, Some(std::env::temp_dir()), "{path:?}");
            let id = name.strip_prefix("temp-socket-").expect(&name);
            assert_eq!(id.len(), 32, "{name}");
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
        } else {
            assert_ne!(parent, Some(std::env::temp_dir()), "{path:?}");
            assert!(name.starts_with("s-"), "{name}");
        }
    }
}
