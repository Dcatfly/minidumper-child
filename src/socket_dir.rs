//! Chooses where the app process puts the socket.
//!
//! Inside an MSIX package on Windows, connecting to a socket in the user's temporary
//! directory can fail with `WSAEINVAL` because of file system virtualization, depending on
//! the account. The package's own `TempState` directory works in all cases, so the socket
//! goes there when the process has package identity. Everywhere else the socket stays in
//! the system temporary directory.
//!
//! The decision is made by [`choose_socket_dir`], which only works on facts gathered
//! beforehand so it can be tested on every platform. The system calls live in `sys`.
//!
//! This module is not part of the public API.

use std::path::{Path, PathBuf};

#[cfg(windows)]
pub mod sys;

/// The longest socket path in bytes, excluding the terminating NUL.
///
/// `sun_path` is 108 bytes and `minidumper` rejects paths that don't leave room for the NUL.
pub const MAX_SOCKET_PATH_LEN: usize = 107;

/// The number of hex digits in the socket file name of packaged processes.
const SHORT_ID_LEN: usize = 8;

/// The facts about a packaged process needed to choose the socket directory.
#[derive(Clone, Debug, Default)]
pub struct PackageDirs {
    /// The package's `TempState` directory as returned by the system, if it exists
    pub temp_state_long: Option<PathBuf>,
    /// The 8.3 short form of `temp_state_long`, if available
    pub temp_state_short: Option<PathBuf>,
}

/// Where to put the socket file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketDir {
    /// An existing directory
    Existing(PathBuf),
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
///
/// If neither fits, the system temporary directory is used.
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

    SocketDir::SystemTemp
}

/// Returns the socket file name used by packaged processes.
///
/// This is shorter than the original name so that it fits into `TempState`.
pub fn packaged_socket_file_name(id: uuid::Uuid) -> String {
    let mut id = id.simple().to_string();
    id.truncate(SHORT_ID_LEN);
    format!("s-{id}")
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

    fn package(long: Option<usize>, short: Option<usize>) -> PackageDirs {
        PackageDirs {
            temp_state_long: long.map(dir_for_socket_len),
            temp_state_short: short.map(dir_for_socket_len),
        }
    }

    #[test]
    fn unpackaged_uses_system_temp() {
        assert_eq!(choose_socket_dir(None, FILE_NAME), SocketDir::SystemTemp);
    }

    #[test]
    fn packaged_uses_temp_state_when_it_fits() {
        let package = package(Some(60), Some(40));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::Existing(package.temp_state_long.clone().unwrap())
        );
    }

    #[test]
    fn packaged_uses_short_temp_state_when_long_does_not_fit() {
        let package = package(Some(110), Some(60));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::Existing(package.temp_state_short.clone().unwrap())
        );
    }

    #[test]
    fn packaged_uses_system_temp_when_neither_fits() {
        let package = package(Some(150), Some(120));
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::SystemTemp
        );

        // Without a short form
        let package = PackageDirs {
            temp_state_short: None,
            ..package
        };
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::SystemTemp
        );
    }

    #[test]
    fn packaged_uses_system_temp_without_temp_state() {
        assert_eq!(
            choose_socket_dir(Some(&PackageDirs::default()), FILE_NAME),
            SocketDir::SystemTemp
        );
    }

    #[test]
    fn socket_path_of_107_bytes_fits_and_108_does_not() {
        assert!(fits(&dir_for_socket_len(107).join(FILE_NAME)));
        assert!(!fits(&dir_for_socket_len(108).join(FILE_NAME)));

        let long_at_limit = package(Some(107), None);
        assert_eq!(
            choose_socket_dir(Some(&long_at_limit), FILE_NAME),
            SocketDir::Existing(dir_for_socket_len(107))
        );

        let short_at_limit = package(Some(108), Some(107));
        assert_eq!(
            choose_socket_dir(Some(&short_at_limit), FILE_NAME),
            SocketDir::Existing(dir_for_socket_len(107))
        );

        let both_over_limit = package(Some(108), Some(108));
        assert_eq!(
            choose_socket_dir(Some(&both_over_limit), FILE_NAME),
            SocketDir::SystemTemp
        );
    }

    #[test]
    fn length_counts_utf8_bytes() {
        // 30 characters, but 90 bytes, so the socket path is 102 bytes
        let fitting = PathBuf::from(format!("/{}", "\u{4e2d}".repeat(30)));
        // 32 characters, 96 bytes, so the socket path is 108 bytes
        let too_long = PathBuf::from(format!("/{}", "\u{4e2d}".repeat(32)));

        assert!(fits(&fitting.join(FILE_NAME)));
        assert!(!fits(&too_long.join(FILE_NAME)));

        let package = PackageDirs {
            temp_state_long: Some(too_long),
            temp_state_short: Some(fitting.clone()),
        };
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::Existing(fitting)
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_does_not_fit() {
        use std::os::unix::ffi::OsStrExt;

        let non_utf8 = PathBuf::from(std::ffi::OsStr::from_bytes(&[b'/', 0x80, b'x']));
        assert!(!fits(&non_utf8.join(FILE_NAME)));

        let package = PackageDirs {
            temp_state_long: Some(non_utf8),
            temp_state_short: None,
        };
        assert_eq!(
            choose_socket_dir(Some(&package), FILE_NAME),
            SocketDir::SystemTemp
        );
    }

    #[test]
    fn packaged_socket_file_name_is_short() {
        let name = packaged_socket_file_name(uuid::Uuid::new_v4());
        let id = name.strip_prefix("s-").expect("should start with s-");
        assert_eq!(id.len(), 8);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
