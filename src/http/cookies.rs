#![deny(unsafe_code)]

use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-memory cookie jar, zeroized on drop. No disk persistence.
#[derive(Debug, Default)]
pub struct CookieJar {
    cookies: HashMap<String, SecretString>,
}

impl CookieJar {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: impl Into<String>, value: SecretString) {
        self.cookies.insert(name.into(), value);
    }

    pub fn set_raw(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.cookies
            .insert(name.into(), SecretString::from(value.into()));
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SecretString> {
        self.cookies.get(name)
    }

    #[must_use]
    pub fn header_value(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        let parts: Vec<String> = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={}", v.expose_secret()))
            .collect();
        Some(parts.join("; "))
    }

    pub fn parse_set_cookie(&mut self, header: &str) {
        if let Some((pair, _)) = header.split_once(';')
            && let Some((k, v)) = pair.split_once('=')
        {
            self.set_raw(k.trim(), v.trim());
        }
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }
}

impl Zeroize for CookieJar {
    fn zeroize(&mut self) {
        self.cookies.clear();
    }
}
impl Drop for CookieJar {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for CookieJar {}
