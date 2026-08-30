#![deny(unsafe_code)]

#[must_use]
pub fn format_duration_ms(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{ms:.0}ms")
    } else {
        format!("{:.2}s", ms / 1000.0)
    }
}
