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
    use minidumper_child::socket_dir::{private_socket_dir, remove_private_socket_dir, sys};

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

    let socket_name = app_socket_name();
    print_socket_name(&socket_name);
    if let Some(dir) = private_socket_dir(&socket_name) {
        println!("socket dir is a new private directory: {}", dir.display());
        remove_private_socket_dir(&socket_name);
        println!("removed private socket dir: {}", !dir.exists());
    }

    match sys::private_dir_parent().and_then(|parent| sys::create_private_dir(&parent)) {
        Ok(dir) => {
            println!("private dir: {}", dir.display());
            match sys::owner_and_dacl_sddl(&dir) {
                Ok(sddl) => println!("private dir SDDL: {sddl}"),
                Err(err) => println!("private dir SDDL: error: {err}"),
            }
            match sys::current_user_sid() {
                Ok(sid) => println!("current user SID: {sid}"),
                Err(err) => println!("current user SID: error: {err}"),
            }
            let removed = std::fs::remove_dir(&dir);
            println!("private dir removed: {removed:?}, exists: {}", dir.exists());
        }
        Err(err) => println!("private dir: error: {err}"),
    }
}

#[cfg(not(windows))]
fn main() {
    println!("package identity: not Windows");
    print_socket_name(&app_socket_name());
}
