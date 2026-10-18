use std::time::Duration;

#[derive(Debug, Default)]
pub(super) struct RobotsRules {
    pub(super) disallow: Vec<String>,
    pub(super) allow: Vec<String>,
    pub(super) crawl_delay: Option<Duration>,
}

impl RobotsRules {
    pub(super) fn parse(body: &str) -> Self {
        let mut rules = Self::default();
        let mut applies = false;
        for raw_line in body.lines() {
            let line = raw_line.split('#').next().unwrap_or_default().trim();
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("user-agent") {
                applies = value == "*" || value.eq_ignore_ascii_case("injekt");
            } else if applies && name.eq_ignore_ascii_case("disallow") && !value.is_empty() {
                rules.disallow.push(value.to_owned());
            } else if applies && name.eq_ignore_ascii_case("allow") && !value.is_empty() {
                rules.allow.push(value.to_owned());
            } else if applies && name.eq_ignore_ascii_case("crawl-delay") {
                rules.crawl_delay = value
                    .parse::<f64>()
                    .ok()
                    .map(|seconds| Duration::from_secs_f64(seconds.max(0.0)));
            }
        }
        rules
    }

    pub(super) fn allows(&self, path: &str) -> bool {
        let allowed_len = self
            .allow
            .iter()
            .filter(|rule| path.starts_with(rule.as_str()))
            .map(String::len)
            .max()
            .unwrap_or(0);
        let denied_len = self
            .disallow
            .iter()
            .filter(|rule| path.starts_with(rule.as_str()))
            .map(String::len)
            .max()
            .unwrap_or(0);
        denied_len == 0 || allowed_len >= denied_len
    }
}
