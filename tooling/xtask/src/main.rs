use std::process::Command;

fn main() {
    let status = Command::new("watchexec")
        .args(["-r", "--exts", "rs", "--", "cargo", "run"])
        .status()
        .expect("failed to run watchexec — is it installed? (brew install watchexec)");

    std::process::exit(status.code().unwrap_or(1));
}
