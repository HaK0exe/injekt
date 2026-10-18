use serde::Deserialize;

/// Parameters for the scan tool (mirrors the CLI flags).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScanParams {
    /// Target URL to scan (e.g. <https://example.com/?id=1>)
    pub target: String,
    /// Number of concurrent threads (default: 5)
    pub threads: Option<usize>,
    /// Techniques to use: boolean, time, error, union, stacked, oob, json, nosql, all (default: all)
    pub techniques: Option<Vec<String>>,
    /// Test only these parameters (e.g. `["id"]` or `["body:user"]`)
    pub params: Option<Vec<String>>,
    /// POST body to test (e.g. "id=1&user=admin")
    pub data: Option<String>,
    /// Payload prefix prepended after tampers (e.g. "')")
    pub prefix: Option<String>,
    /// Payload suffix appended after tampers (e.g. "-- -")
    pub suffix: Option<String>,
    /// Extra chars exempted from percent-encoding (e.g. "(),")
    pub safe_chars: Option<String>,
    /// Send payloads without URL-encoding (use with care)
    pub skip_urlencode: Option<bool>,
    /// Response body must contain this substring, otherwise veto finding
    pub string: Option<String>,
    /// Response body must NOT contain this substring, otherwise veto finding
    pub not_string: Option<String>,
    /// Response status must equal this code, otherwise veto finding
    pub code: Option<u16>,
    /// Strip HTML tags/entities before matching and detection
    pub text_only: Option<bool>,
    /// Force fetch oracle: direct, boolean or time
    pub fetch_using: Option<String>,
    /// WAF tamper scripts: space2comment, randomcase, versionedcomment, versionedmorekeywords, charencode, doubleurlencode, hexencode, unicodeencode, overlongutf8, space2tab, space2newline, space2randomblank, space2dash, space2mssqlblank, betweencomment, randomcomments, equaltolike, space2paren, versionedfuzz, jsonunicodeescape, numericobfuscate, linecomment, base64encode (opt-in: breaks boolean differentials). Presets: cloudflare-generic (=randomcase,space2comment,versionedmorekeywords), aggressive (=randomcase,space2paren,versionedfuzz,equaltolike)
    pub tamper: Option<Vec<String>>,
    /// Proxy URL (use socks5h:// for remote DNS, socks5:// is rejected)
    pub proxy: Option<String>,
    /// Request rate limit (requests per second)
    pub rate_limit: Option<f64>,
    /// Jitter as "mean,std" (e.g. "0.1,0.05")
    pub jitter: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout: Option<u64>,
    /// Global detection time budget in seconds (OPT-IN, None = unlimited):
    /// detection stops cooperatively once exceeded (Inconclusive without findings, no error)
    pub max_duration: Option<u64>,
    /// Global request budget (OPT-IN calibration, None = unlimited):
    /// detection stops cooperatively once total `request_count` reaches N
    pub request_budget: Option<usize>,
    /// Max retries for failed requests (default: 3)
    pub retries: Option<usize>,
    /// Base retry delay in milliseconds (default: 500)
    pub delay: Option<u64>,
    /// Custom headers as ["Name: value", ...]
    pub headers: Option<Vec<String>>,
    /// Cookie header value
    pub cookies: Option<String>,
    /// Force specific DBMS: mysql, postgres, mssql, oracle, sqlite
    pub dbms: Option<String>,
    /// Enable data extraction (opt-in)
    pub extract: Option<bool>,
    /// Enumerate databases
    pub dbs: Option<bool>,
    /// Enumerate tables
    pub tables: Option<bool>,
    /// Enumerate columns
    pub columns: Option<bool>,
    /// Dump table data
    pub dump: Option<bool>,
    /// Retrieve DBMS banner/version (identity enumeration)
    pub banner: Option<bool>,
    /// Retrieve current database user (identity enumeration)
    pub current_user: Option<bool>,
    /// Retrieve current database name (identity enumeration)
    pub current_db: Option<bool>,
    /// Retrieve server hostname (identity enumeration)
    pub hostname: Option<bool>,
    /// Specific database name
    pub db: Option<String>,
    /// Specific table name
    pub table: Option<String>,
    /// Specific column name
    pub column: Option<String>,
    /// Start row offset for dumping
    pub start: Option<usize>,
    /// Stop row offset for dumping
    pub stop: Option<usize>,
    /// Only count rows
    pub count: Option<bool>,
    /// Write JSON report to this file path (opt-in disk write, MCP-only:
    /// relative path without '..', 0o600 on Unix)
    pub output: Option<String>,
    /// Encrypted session export path — NOT supported in MCP mode, will error
    pub export_encrypted: Option<String>,
    /// OOB collaborator base domain (opt-in, requires operator infra)
    pub oob_domain: Option<String>,
    /// Collaborator poll URL (may contain {token}); without it OOB probes are never auto-confirmed
    pub oob_poll_url: Option<String>,
    /// Seconds to wait for the async DB-side OOB query (default: 5)
    pub oob_wait_secs: Option<u64>,
    /// HTTP Parameter Pollution: duplicate param (?id=1&id=PAYLOAD)
    pub hpp: Option<bool>,
    /// Chunked transfer-encoding for body injections
    pub chunked: Option<bool>,
    /// Allow private/loopback targets (lab only, default: false)
    pub allow_private: Option<bool>,
    /// Max redirects followed per request (default: 5, 0 = do not follow)
    pub max_redirects: Option<u8>,
    /// Disable redaction in output (local debugging only)
    pub no_redact: Option<bool>,
}

/// Parameters for the `recon_crawl` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReconCrawlParams {
    /// Target URL or bare host to crawl
    pub target: String,
    /// Crawl depth (default: 2, max: 16)
    pub depth: Option<usize>,
    /// Maximum pages to crawl (default: 100, max: 100000)
    pub max_pages: Option<usize>,
    /// Max pages fetched per page template — path shape + query param names
    /// (default: 3), caps pagination/listing/calendar crawl traps
    pub max_per_template: Option<usize>,
    /// Max discovered parameters kept (default: 500), redundant sink shapes
    /// dropped first
    pub max_candidates: Option<usize>,
    /// Include subdomains
    pub include_subdomains: Option<bool>,
    /// Ignore robots.txt
    pub ignore_robots: Option<bool>,
    /// Number of concurrent threads (default: 5)
    pub threads: Option<usize>,
    /// Proxy URL (use socks5h:// for remote DNS)
    pub proxy: Option<String>,
    /// Request rate limit (requests per second)
    pub rate_limit: Option<f64>,
    /// Jitter as "mean,std"
    pub jitter: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout: Option<u64>,
    /// Max retries for failed requests (default: 3)
    pub retries: Option<usize>,
    /// Base retry delay in milliseconds (default: 500)
    pub delay: Option<u64>,
    /// Custom headers as ["Name: value", ...]
    pub headers: Option<Vec<String>>,
    /// Cookie header value
    pub cookies: Option<String>,
    /// Allow private/loopback targets (lab only, default: false)
    pub allow_private: Option<bool>,
    /// Max redirects followed per request (default: 5, 0 = do not follow)
    pub max_redirects: Option<u8>,
    /// Enable parameter discovery fuzzing after crawl completes.
    pub discover_params: Option<bool>,
    /// Maximum number of discovery fuzzing rounds
    pub max_discover: Option<usize>,
}

/// Parameters for the `recon_scan` tool (crawl + test discovered parameters).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReconScanParams {
    /// Target URL or bare host to crawl and scan
    pub target: String,
    /// Crawl depth (default: 2, max: 16)
    pub depth: Option<usize>,
    /// Maximum pages to crawl (default: 100, max: 100000)
    pub max_pages: Option<usize>,
    /// Max pages fetched per page template — path shape + query param names
    /// (default: 3), caps pagination/listing/calendar crawl traps
    pub max_per_template: Option<usize>,
    /// Max discovered parameters kept (default: 500), redundant sink shapes
    /// dropped first
    pub max_candidates: Option<usize>,
    /// Include subdomains
    pub include_subdomains: Option<bool>,
    /// Ignore robots.txt
    pub ignore_robots: Option<bool>,
    /// Auto-enumerate databases/tables after finding injection
    pub auto_enumerate: Option<bool>,
    /// Number of concurrent threads (default: 5)
    pub threads: Option<usize>,
    /// Techniques to use: boolean, time, error, union, stacked, oob, json, nosql, all
    pub techniques: Option<Vec<String>>,
    /// Test only these parameters
    pub params: Option<Vec<String>>,
    /// POST body to test
    pub data: Option<String>,
    /// Payload prefix prepended after tampers
    pub prefix: Option<String>,
    /// Payload suffix appended after tampers
    pub suffix: Option<String>,
    /// Extra chars exempted from percent-encoding
    pub safe_chars: Option<String>,
    /// Send payloads without URL-encoding
    pub skip_urlencode: Option<bool>,
    /// Response body must contain this substring, otherwise veto finding
    pub string: Option<String>,
    /// Response body must NOT contain this substring, otherwise veto finding
    pub not_string: Option<String>,
    /// Response status must equal this code, otherwise veto finding
    pub code: Option<u16>,
    /// Strip HTML tags/entities before matching and detection
    pub text_only: Option<bool>,
    /// Force fetch oracle: direct, boolean or time
    pub fetch_using: Option<String>,
    /// WAF tamper scripts (presets: cloudflare-generic, aggressive)
    pub tamper: Option<Vec<String>>,
    /// Proxy URL (use socks5h:// for remote DNS)
    pub proxy: Option<String>,
    /// Request rate limit (requests per second)
    pub rate_limit: Option<f64>,
    /// Jitter as "mean,std"
    pub jitter: Option<String>,
    /// Request timeout in seconds (default: 30)
    pub timeout: Option<u64>,
    /// Global detection time budget in seconds (OPT-IN, None = unlimited)
    pub max_duration: Option<u64>,
    /// Global request budget (OPT-IN calibration, None = unlimited)
    pub request_budget: Option<usize>,
    /// Max retries for failed requests (default: 3)
    pub retries: Option<usize>,
    /// Base retry delay in milliseconds (default: 500)
    pub delay: Option<u64>,
    /// Custom headers as ["Name: value", ...]
    pub headers: Option<Vec<String>>,
    /// Cookie header value
    pub cookies: Option<String>,
    /// Force specific DBMS: mysql, postgres, mssql, oracle, sqlite
    pub dbms: Option<String>,
    /// Enable data extraction (opt-in)
    pub extract: Option<bool>,
    /// Enumerate databases
    pub dbs: Option<bool>,
    /// Enumerate tables
    pub tables: Option<bool>,
    /// Enumerate columns
    pub columns: Option<bool>,
    /// Dump table data
    pub dump: Option<bool>,
    /// Retrieve DBMS banner/version (identity enumeration)
    pub banner: Option<bool>,
    /// Retrieve current database user (identity enumeration)
    pub current_user: Option<bool>,
    /// Retrieve current database name (identity enumeration)
    pub current_db: Option<bool>,
    /// Retrieve server hostname (identity enumeration)
    pub hostname: Option<bool>,
    /// Specific database name
    pub db: Option<String>,
    /// Specific table name
    pub table: Option<String>,
    /// Specific column name
    pub column: Option<String>,
    /// Start row offset for dumping
    pub start: Option<usize>,
    /// Stop row offset for dumping
    pub stop: Option<usize>,
    /// Only count rows
    pub count: Option<bool>,
    /// Write JSON report to this file path (opt-in disk write, MCP-only:
    /// relative path without '..', 0o600 on Unix)
    pub output: Option<String>,
    /// Encrypted session export path — NOT supported in MCP mode, will error
    pub export_encrypted: Option<String>,
    /// OOB collaborator base domain (opt-in)
    pub oob_domain: Option<String>,
    /// Collaborator poll URL (may contain {token})
    pub oob_poll_url: Option<String>,
    /// Seconds to wait for the async DB-side OOB query (default: 5)
    pub oob_wait_secs: Option<u64>,
    /// HTTP Parameter Pollution
    pub hpp: Option<bool>,
    /// Chunked transfer-encoding for body injections
    pub chunked: Option<bool>,
    /// Allow private/loopback targets (lab only, default: false)
    pub allow_private: Option<bool>,
    /// Max redirects followed per request (default: 5, 0 = do not follow)
    pub max_redirects: Option<u8>,
    /// Enable parameter discovery fuzzing after crawl completes.
    pub discover_params: Option<bool>,
    /// Maximum number of discovery fuzzing rounds
    pub max_discover: Option<usize>,
    /// Disable redaction in output (local debugging only)
    pub no_redact: Option<bool>,
}

/// Parameters for the info tool (no parameters).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InfoParams {}

/// Parameters for the `plan` tool (C11 offline dry-run, 0 requests).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PlanParams {
    /// Target URL to plan (e.g. <https://example.com/?id=1>)
    pub target: String,
    /// Techniques to plan: boolean, time, error, union, stacked, oob, json, nosql, all
    pub techniques: Option<Vec<String>>,
    /// Test only these parameters (e.g. `["id"]` or `["body:user"]`)
    pub params: Option<Vec<String>>,
    /// POST body to test (e.g. "id=1&user=admin")
    pub data: Option<String>,
    /// Force specific DBMS: mysql, postgres, mssql, oracle, sqlite
    pub dbms: Option<String>,
    /// Deterministic run seed (same seed => same plan order)
    pub seed: Option<u64>,
    /// Aggressiveness level 1-5
    pub level: Option<u8>,
    /// Concurrency (plan display only)
    pub threads: Option<usize>,
    /// Custom headers as ["Name: value", ...] (names only in output, never values)
    pub headers: Option<Vec<String>>,
    /// Cookie header value (never echoed in output)
    pub cookies: Option<String>,
    /// Allow private/loopback targets (lab only, default: false)
    pub allow_private: Option<bool>,
    /// Disable redaction in output (local debugging only)
    pub no_redact: Option<bool>,
}

/// Parameters for the `explain` tool (C11 offline, 0 requests).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExplainParams {
    /// Finding parameter key (e.g. "id@query")
    pub param: String,
    /// Evidence string (e.g. `boolean` `true_sim=0.91` `false_sim=0.22` `trials=3/3`)
    pub evidence: Option<String>,
    /// Detector confidence in [0.0, 1.0]
    pub confidence: Option<f64>,
    /// Total run requests to report
    pub requests: Option<u64>,
    /// Effective run seed
    pub seed: Option<u64>,
    /// Decrypted export snapshot JSON (findings + `request_count` + seed);
    /// when it contains `param`, its evidence/confidence win over the direct fields
    pub export_json: Option<String>,
    /// Disable redaction in output (local debugging only)
    pub no_redact: Option<bool>,
}
