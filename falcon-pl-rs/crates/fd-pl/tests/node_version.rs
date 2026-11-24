//! `falcon-pl-node --version` must print exactly `fd-pl <version>` on stdout:
//! build-portable.sh, the installer and auto-upgrade read the last word.
use std::process::Command;

#[test]
fn node_version_stdout_is_only_the_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_falcon-pl-node"))
        .arg("--version")
        .env_remove("RUST_LOG")
        .output()
        .expect("run falcon-pl-node --version");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.trim_end(), format!("fd-pl {}", env!("CARGO_PKG_VERSION")));
}
