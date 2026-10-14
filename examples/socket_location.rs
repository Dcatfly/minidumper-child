//! Prints where the app process would put the crash reporter socket, and why.
//!
//! Used to check the socket location inside and outside of an MSIX package on Windows.
use minidumper_child::{app_socket_name, OwnedSocketName};

fn print_socket_name(socket_name: &OwnedSocketName) {
    match socket_name {
        OwnedSocketName::Path(path) => {
            let bytes = path.to_str().map(str::len);
            println!("socket path: {}", path.display());
            println!("socket path bytes (UTF-8): {bytes:?}");
        }
        #[allow(unreachable_patterns)]
        other => println!("socket name: {other:?}"),
    }
}

#[cfg(windows)]
fn main() {
    use minidumper_child::socket_dir::sys;

    match sys::package_family_name() {
        Ok(Some(name)) => {
            println!("package identity: yes");
            println!("package family name: {name}");
        }
        Ok(None) => println!("package identity: no"),
        Err(err) => println!("package identity: error: {err}"),
    }

    match sys::local_app_data_dir() {
        Ok(dir) => println!("LocalAppData: {}", dir.display()),
        Err(err) => println!("LocalAppData: error: {err}"),
    }

    if let Ok(Some(name)) = sys::package_family_name() {
        let dirs = sys::package_dirs(&name);
        match &dirs.temp_state_long {
            Some(dir) => println!(
                "TempState long: {} ({} bytes)",
                dir.display(),
                dir.as_os_str().len()
            ),
            None => println!("TempState long: missing"),
        }
        match &dirs.temp_state_short {
            Some(dir) => println!(
                "TempState short: {} ({} bytes)",
                dir.display(),
                dir.as_os_str().len()
            ),
            None => println!("TempState short: unavailable"),
        }
    }

    print_socket_name(&app_socket_name());
}

#[cfg(not(windows))]
fn main() {
    println!("package identity: not Windows");
    print_socket_name(&app_socket_name());
}
