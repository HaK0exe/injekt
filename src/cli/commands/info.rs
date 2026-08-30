#![deny(unsafe_code)]

pub fn run() {
    println!(
        "injekt v{} — modern SQLi detection (zero persistence, OPSEC by design)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Techniques: boolean, time, error");
    println!("DBMS: mysql, postgres, mssql, oracle");
    println!("Docs: docs/OPSEC.md (JA3, jitter, proxy socks5h)");
}
