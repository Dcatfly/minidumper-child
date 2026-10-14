//! Chooses where the app process puts the socket.
//!
//! Inside an MSIX package on Windows, connecting to a socket in the user's temporary
//! directory can fail with `WSAEINVAL` because of file system virtualization, depending on
//! the account. The package's own `TempState` directory works in all cases, so the socket
//! goes there when the process has package identity. Everywhere else the socket stays in
//! the system temporary directory.
//!
//! The decision is made by [`choose_socket_dir`], which only works on facts gathered
//! beforehand so it can be tested on every platform. The system calls live in [`sys`].
//!
//! This module is not part of the public API.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use crate::OwnedSocketName;

#[cfg(windows)]
pub mod sys;

/// The longest socket path in bytes, excluding the terminating NUL.
///
/// `sun_path` is 108 bytes and `minidumper` rejects paths that don't leave room for the NUL.
pub const MAX_SOCKET_PATH_LEN: usize = 107;

/// The prefix of the private directories created for sockets.
pub const PRIVATE_DIR_PREFIX: &str = "mdc-";

/// The number of hex digits used in short socket file and directory names.
const SHORT_ID_LEN: usize = 8;

/// The facts about a packaged process needed to choose the socket directory.
#[derive(Clone, Debug, Default)]
pub struct PackageDirs {
    /// The package's `TempState` directory as returned by the system, if it exists
    pub temp_state_long: Option<PathBuf>,
    /// The 8.3 short form of `temp_state_long`, if available
    pub temp_state_short: Option<PathBuf>,
    /// The path of a private directory that could be created for the socket
    pub private_dir: Option<PathBuf>,
}

/// Where to put the socket file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketDir {
    /// An existing directory
    Existing(PathBuf),
    /// A private directory that has to be created first
    CreatePrivate(PathBuf),
    /// The system temporary directory, with the original socket file name
    SystemTemp,
}

/// Returns whether a socket path fits into `sun_path`.
///
/// Like `minidumper` on Windows this counts UTF-8 bytes, so paths that aren't valid
/// UTF-8 never fit.
pub fn fits(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|path| path.len() <= MAX_SOCKET_PATH_LEN)
}

/// Chooses the socket directory.
///
/// `package` is `None` for processes without package identity, which always use the system
/// temporary directory. Packaged processes use the first of these where the full socket path,
/// with `file_name`, fits:
///
/// 1. The `TempState` directory
/// 2. Its short form
/// 3. A new private directory
///
/// If none of them fit, the system temporary directory is used.
pub fn choose_socket_dir(package: Option<&PackageDirs>, file_name: &str) -> SocketDir {
    let Some(package) = package else {
        return SocketDir::SystemTemp;
    };

    let dir_fits = |dir: &Path| fits(&dir.join(file_name));

    if let Some(long) = &package.temp_state_long {
        if dir_fits(long) {
            return SocketDir::Existing(long.clone());
        }

        if let Some(short) = &package.temp_state_short {
            if dir_fits(short) {
                return SocketDir::Existing(short.clone());
            }
        }
    }

    match &package.private_dir {
        Some(private_dir) if dir_fits(private_dir) => SocketDir::CreatePrivate(private_dir.clone()),
        _ => SocketDir::SystemTemp,
    }
}

fn short_id(id: uuid::Uuid) -> String {
    let mut id = id.simple().to_string();
    id.truncate(SHORT_ID_LEN);
    id
}

/// Returns the socket file name used by packaged processes.
///
/// This is shorter than the original name so that it fits into `TempState`.
pub fn packaged_socket_file_name(id: uuid::Uuid) -> String {
    format!("s-{}", short_id(id))
}

/// Returns the name for a private socket directory.
pub fn private_dir_name(id: uuid::Uuid) -> String {
    format!("{PRIVATE_DIR_PREFIX}{}", short_id(id))
}

/// Returns whether `name` is the name of a private socket directory.
pub fn is_private_dir_name(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix(PRIVATE_DIR_PREFIX))
        .is_some_and(|id| {
            id.len() == SHORT_ID_LEN
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Returns the SDDL for a private socket directory owned by `sid`.
///
/// Only the owner and `SYSTEM` get access, and nothing is inherited from the parent. The
/// owner is set explicitly because directories created with an elevated administrator
/// token are owned by `BUILTIN\Administrators` by default.
pub fn private_dir_sddl(sid: &str) -> String {
    format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
}

/// Compares two paths component by component, ignoring case like Windows file systems do
/// (approximately).
fn paths_equal_ignoring_case(a: &Path, b: &Path) -> bool {
    let mut a = a.components();
    let mut b = b.components();
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) => {
                let (Some(a), Some(b)) = (a.as_os_str().to_str(), b.as_os_str().to_str()) else {
                    return false;
                };
                if a != b && a.to_lowercase() != b.to_lowercase() {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// Returns whether `dir` is a private socket directory, i.e. it has a private directory
/// name and lives directly in `private_dir_parent`.
pub fn is_private_socket_dir(dir: &Path, private_dir_parent: &Path) -> bool {
    let (Some(name), Some(parent)) = (dir.file_name(), dir.parent()) else {
        return false;
    };
    is_private_dir_name(name) && paths_equal_ignoring_case(parent, private_dir_parent)
}

/// Returns the directory of a socket if it is a private directory created for it.
///
/// Private directories are only created on Windows, so this is always `None` elsewhere.
pub fn private_socket_dir(socket_name: &OwnedSocketName) -> Option<&Path> {
    #[cfg(windows)]
    {
        let OwnedSocketName::Path(path) = socket_name;
        let dir = path.parent()?;
        let private_dir_parent = sys::private_dir_parent().ok()?;
        is_private_socket_dir(dir, &private_dir_parent).then_some(dir)
    }

    #[cfg(not(windows))]
    {
        let _ = socket_name;
        None
    }
}

/// Removes the directory of a socket if it is an empty private directory created for it.
///
/// This is best effort and only ever removes an empty directory. It does nothing outside of
/// Windows.
pub fn remove_private_socket_dir(socket_name: &OwnedSocketName) {
    if let Some(dir) = private_socket_dir(socket_name) {
        let _ = fs::remove_dir(dir);
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    const FILE_NAME: &str = "s-0123abcd";

    /// Returns a directory whose socket path with `FILE_NAME` is exactly `len` bytes long.
    fn dir_for_socket_len(len: usize) -> PathBuf {
        // The separator and the file name
        let dir_len = len - 1 - FILE_NAME.len();
        let dir = format!("/{}", "d".repeat(dir_len - 1));
        assert_eq!(Path::new(&dir).join(FILE_NAME).to_str().unwrap().len(), len);
        PathBuf::from(dir)
    }

    fn package(long: Option<usize>, short: Option<usize>, private: Option<usize>) -> PackageDirs {
        PackageDirs {
            temp_state_long: long.map(dir_for_socket_len),
            temp_state_short: short.map(dir_for_socket_len),
            private_dir: private.map(dir_for_socket_len),
        }
    }

    #[test]
    fn unpackaged_uses_system_temp() {
        assert_eq!(choose_socket_dir(None, FILE_NAME), SocketDir::SystemTemp);
    }

    #[test]
    fn packaged_uses_temp_state_when_it_fits() {
        let package = package(Some(60), Some(40), Some(30));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::Existing(package.temp_state_long.clone().unwrap())
        );
    }

    #[test]
    fn packaged_uses_short_temp_state_when_long_does_not_fit() {
        let package = package(Some(110), Some(60), Some(30));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::Existing(package.temp_state_short.clone().unwrap())
        );
    }

    #[test]
    fn packaged_uses_private_dir_when_temp_state_does_not_fit() {
        let package = package(Some(150), Some(120), Some(40));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::CreatePrivate(package.private_dir.clone().unwrap())
        );
    }

    #[test]
    fn packaged_uses_private_dir_without_temp_state() {
        let package = package(None, None, Some(40));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::CreatePrivate(package.private_dir.clone().unwrap())
        );
    }

    #[test]
    fn packaged_uses_system_temp_when_nothing_fits() {
        let package = package(Some(150), Some(120), Some(110));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::SystemTemp
        );
    }

    #[test]
    fn packaged_uses_system_temp_without_any_candidate() {
        let package = package(Some(150), Some(120), None);
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::SystemTemp
        );
        assert_eq!(
            choose_socket_dir(Some(&PackageDirs::default()), FILE_NAME),
            SocketDir::SystemTemp
        );
    }

    #[test]
    fn socket_path_of_107_bytes_fits_and_108_does_not() {
        assert!(fits(&dir_for_socket_len(107).join(FILE_NAME)));
        assert!(!fits(&dir_for_socket_len(108).join(FILE_NAME)));

        let at_limit = PackageDirs {
            temp_state_long: Some(dir_for_socket_len(107)),
            ..PackageDirs::default()
        };
        assert_eq!(
            choose_socket_dir(Some(&at_limit), FILE_NAME),
            SocketDir::Existing(dir_for_socket_len(107))
        );

        let over_limit = PackageDirs {
            temp_state_long: Some(dir_for_socket_len(108)),
            temp_state_short: Some(dir_for_socket_len(107)),
            ..PackageDirs::default()
        };
        assert_eq!(
            choose_socket_dir(Some(&over_limit), FILE_NAME),
            SocketDir::Existing(dir_for_socket_len(107))
        );

        let private_over_limit = PackageDirs {
            private_dir: Some(dir_for_socket_len(108)),
            ..PackageDirs::default()
        };
        assert_eq!(
            choose_socket_dir(Some(&private_over_limit), FILE_NAME),
            SocketDir::SystemTemp
        );
    }

    #[test]
    fn length_counts_utf8_bytes() {
        // 30 characters, but 90 bytes
        let dir = PathBuf::from(format!("/{}", "\u{4e2d}".repeat(30)));
        assert!(fits(&dir.join(FILE_NAME)));

        let dir = PathBuf::from(format!("/{}", "\u{4e2d}".repeat(32)));
        assert!(!fits(&dir.join(FILE_NAME)));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_does_not_fit() {
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(std::ffi::OsStr::from_bytes(&[b'/', 0x80, b'x']));
        assert!(!fits(path));
    }

    #[test]
    fn packaged_socket_file_name_is_short() {
        let name = packaged_socket_file_name(uuid::Uuid::new_v4());
        let id = name.strip_prefix("s-").expect("should start with s-");
        assert_eq!(id.len(), 8);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn private_dir_names_are_recognised() {
        let name = private_dir_name(uuid::Uuid::new_v4());
        assert!(is_private_dir_name(name.as_ref()));

        for name in [
            "mdc-0123abc",
            "mdc-0123abcde",
            "mdc-0123ABCD",
            "mdc-0123abcg",
            "mdct-conn-1",
            "xmdc-0123abcd",
            "temp-socket-0123abcd",
        ] {
            assert!(!is_private_dir_name(name.as_ref()), "{name}");
        }
    }

    #[test]
    fn private_dir_sddl_grants_owner_and_system_only() {
        assert_eq!(
            private_dir_sddl("S-1-5-21-1-2-3-1001"),
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;OICI;FA;;;SY)"
        );
    }

    #[test]
    fn private_socket_dir_requires_private_name_and_parent() {
        let parent = Path::new("/Windows/Temp");

        assert!(is_private_socket_dir(&parent.join("mdc-0123abcd"), parent));
        // Windows paths are case insensitive
        assert!(is_private_socket_dir(
            Path::new("/WINDOWS/temp/mdc-0123abcd"),
            parent
        ));

        // Wrong name
        assert!(!is_private_socket_dir(&parent.join("mdc-0123"), parent));
        assert!(!is_private_socket_dir(&parent.join("temp-socket"), parent));
        // Wrong parent
        assert!(!is_private_socket_dir(
            Path::new("/tmp/mdc-0123abcd"),
            parent
        ));
        assert!(!is_private_socket_dir(
            Path::new("/Windows/Temp/x/mdc-0123abcd"),
            parent
        ));
        assert!(!is_private_socket_dir(
            Path::new("/Windows/mdc-0123abcd"),
            parent
        ));
        assert!(!is_private_socket_dir(Path::new("mdc-0123abcd"), parent));
    }

    /// Outside of Windows nothing is ever removed, even if it is named like a private
    /// directory, so behaviour is the same as before private directories existed.
    #[cfg(not(windows))]
    #[test]
    fn private_socket_dirs_are_never_removed_outside_windows() {
        let base = std::env::temp_dir().join(format!("mdct-keep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let dir = base.join(private_dir_name(uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let socket_name = OwnedSocketName::Path(dir.join("s"));
        let found = private_socket_dir(&socket_name);
        remove_private_socket_dir(&socket_name);
        let kept = dir.is_dir();
        fs::remove_dir_all(&base).unwrap();

        assert_eq!(found, None);
        assert!(kept, "{dir:?} was removed");
    }

    #[cfg(windows)]
    #[test]
    fn remove_private_socket_dir_only_removes_empty_private_dirs() {
        let parent = sys::private_dir_parent().unwrap();
        let private = sys::create_private_dir(&parent).unwrap();

        // Named like a private directory, but not in the private directory parent
        let base = std::env::temp_dir().join(format!("mdct-rm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let elsewhere = base.join(private_dir_name(uuid::Uuid::new_v4()));
        fs::create_dir_all(&elsewhere).unwrap();

        remove_private_socket_dir(&OwnedSocketName::Path(elsewhere.join("s")));
        let elsewhere_kept = elsewhere.is_dir();

        // Not empty
        fs::write(private.join("keep"), b"").unwrap();
        remove_private_socket_dir(&OwnedSocketName::Path(private.join("s")));
        let non_empty_kept = private.is_dir();

        fs::remove_file(private.join("keep")).unwrap();
        remove_private_socket_dir(&OwnedSocketName::Path(private.join("s")));
        let removed = !private.exists();

        let _ = fs::remove_dir(&private);
        let _ = fs::remove_dir_all(&base);

        assert!(elsewhere_kept);
        assert!(non_empty_kept);
        assert!(removed);
    }
}
