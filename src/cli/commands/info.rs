#![deny(unsafe_code)]

pub fn run() {
    println!(
        "injekt v{} — modern SQLi detection (zero persistence, OPSEC by design)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Techniques: boolean, time, error, union, stacked, oob");
    println!(
        "Tampers: {}",
        crate::techniques::tamper::Tamper::all_names().join(", ")
    );
    println!("OOB: opt-in via --oob-domain <collaborator> [--oob-poll-url <url> with {{token}}]");
    println!(
        "Request tampers: --hpp (duplicate ?id=1&id=PAYLOAD), --chunked (Transfer-Encoding: chunked body)"
    );
    println!("DBMS: mysql, postgres, mssql, oracle");
    println!("Docs: docs/OPSEC.md (JA3, jitter, proxy socks5h)");
}
