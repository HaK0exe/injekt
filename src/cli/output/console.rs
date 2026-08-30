#![deny(unsafe_code)]
pub fn banner() {
    println!("injekt — {}", env!("CARGO_PKG_VERSION"));
}
