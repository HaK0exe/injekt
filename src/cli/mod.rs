#![deny(unsafe_code)]
pub mod args;
pub mod commands;
pub mod output;
pub use args::{Cli, Commands};
