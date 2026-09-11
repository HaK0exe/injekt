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

    /// OS-random UA pick; seeded runs must use [`Self::random_with_rng`].
    /// Routed through `make_rng(None)` so the seeded entry point stays unique.
    #[must_use]
    pub fn random() -> Self {
        let mut rng = crate::seeded_rng::make_rng(None);
        Self::random_with_rng(&mut rng)
    }

    /// Seeded UA pick: draws from `rng` so the same `--seed` yields the same
    /// identity. Pass `&mut crate::seeded_rng::make_rng(seed)`.
    #[must_use]
    pub fn random_with_rng(rng: &mut impl rand::Rng) -> Self {
        let (ua, ch) = Self::POOL.choose(&mut *rng).unwrap_or(&Self::POOL[0]);
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

    /// Same headers as [`Self::headers`], pre-built as a `HeaderMap` so
    /// callers can `extend` a request's default headers without a per-build
    /// String-to-HeaderName/Value re-parse.
    #[must_use]
    pub fn header_map(&self) -> reqwest::header::HeaderMap {
        let mut map = reqwest::header::HeaderMap::new();
        for (k, v) in self.headers() {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(&v),
            ) {
                map.insert(name, value);
            }
        }
        map
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::random()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::seeded_rng::make_rng;

    #[test]
    fn same_seed_same_identity() {
        let mut a = make_rng(Some(99));
        let mut b = make_rng(Some(99));
        let ia = Identity::random_with_rng(&mut a);
        let ib = Identity::random_with_rng(&mut b);
        assert_eq!(ia.user_agent, ib.user_agent);
        assert_eq!(ia.sec_ch_ua, ib.sec_ch_ua);
    }

    #[test]
    fn different_seeds_likely_differ_over_sequence() {
        let mut a = make_rng(Some(1));
        let mut b = make_rng(Some(2));
        let xs: Vec<String> = (0..10)
            .map(|_| Identity::random_with_rng(&mut a).user_agent)
            .collect();
        let ys: Vec<String> = (0..10)
            .map(|_| Identity::random_with_rng(&mut b).user_agent)
            .collect();
        assert_ne!(xs, ys);
    }

    #[test]
    fn none_path_produces_known_pool_ua() {
        let mut rng = make_rng(None);
        let id = Identity::random_with_rng(&mut rng);
        assert!(!id.user_agent.is_empty());
        assert!(!id.headers().is_empty());
        // OS-random wrapper stays usable.
        assert!(!Identity::random().user_agent.is_empty());
    }
}
