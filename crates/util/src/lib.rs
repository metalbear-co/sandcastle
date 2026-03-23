use std::io::{self, BufRead, Write};

use anyhow::Result;

pub fn generate_token() -> String {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("cannot open /dev/urandom");
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf).expect("cannot read /dev/urandom");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn prompt(msg: &str) -> Result<String> {
    eprint!("{msg}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .trim()
        .to_string())
}
