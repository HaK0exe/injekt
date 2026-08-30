#![deny(unsafe_code)]

use rand::seq::IndexedRandom;

/// Realistic UA rotation with Sec-CH-UA aligned headers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Identity {
    pub user_agent: String,
    pub sec_ch_ua: String,
    pub accept: String,
    pub accept_language: String,
}

impl Identity {
    const POOL: &'static [(&'static str, &'static str)] = &[
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "\"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "\"Chromium\";v=\"125\", \"Google Chrome\";v=\"125\"",
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "\"Firefox\";v=\"128\"",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "\"Firefox\";v=\"128\"",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "\"Safari\";v=\"17\"",
        ),
    ];

    #[must_use]
    pub fn random() -> Self {
        let mut rng = rand::rng();
        let (ua, ch) = Self::POOL.choose(&mut rng).unwrap_or(&Self::POOL[0]);
        Self {
            user_agent: (*ua).to_owned(),
            sec_ch_ua: (*ch).to_owned(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_owned(),
            accept_language: "en-US,en;q=0.9".to_owned(),
        }
    }

    #[must_use]
    pub fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![
            ("User-Agent".to_owned(), self.user_agent.clone()),
            ("Accept".to_owned(), self.accept.clone()),
            ("Accept-Language".to_owned(), self.accept_language.clone()),
        ];
        if self.sec_ch_ua.contains("Chromium") || self.sec_ch_ua.contains("Chrome") {
            h.push(("Sec-Ch-Ua".to_owned(), self.sec_ch_ua.clone()));
            h.push(("Sec-Ch-Ua-Mobile".to_owned(), "?0".to_owned()));
            h.push(("Sec-Ch-Ua-Platform".to_owned(), "\"Windows\"".to_owned()));
        }
        h
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::random()
    }
}
