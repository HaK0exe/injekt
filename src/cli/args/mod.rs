#![deny(unsafe_code)]

pub mod detection;
pub mod enumeration;
pub mod evasion;
pub mod http;
pub mod output;
pub mod root;
pub mod target;

pub use detection::{DetectionOpts, MAX_DURATION_SECS, MAX_REQUEST_BUDGET, TechniqueOpt};
pub use enumeration::EnumOpts;
pub use evasion::EvasionOpts;
pub use http::HttpOpts;
pub use output::{OutputOpts, ReportFormat};
pub use root::{
    AutoArgs, Cli, Commands, CompletionsArgs, InfoArgs, InitArgs, ManArgs, McpArgs, ReconArgs,
    ReconCommands, ReconCrawlArgs, ReconImportArgs, ReconScanArgs, ReplayArgs, ScanArgs,
};
pub use target::TargetOpts;
