//! CLI options for the `netuser` binary.
//!
//! This module contains the `Cli` struct used for parsing command line arguments
//! with `clap`.

use clap::Parser;

/// Simple CLI for querying Windows user information.
#[derive(Parser)]
#[command(name = "netuser")]
#[command(author, version, about = "Query Windows user information", long_about = None)]
pub struct CmdLineOptions {
    /// Username to look up
    pub username: String,

    /// Show brief details. Mutually exclusive with --extended-details.
    #[arg(short = 'd', long = "details", conflicts_with = "extended_details")]
    pub details: bool,

    /// Show extended details. Mutually exclusive with --details.
    #[arg(short = 'e', long = "extended-details", conflicts_with = "details")]
    pub extended_details: bool,

    /// Show groups the user is a member of
    #[arg(short = 'g', long = "groups")]
    pub groups: bool,

    /// Explicit server/DC to query (e.g. "\\DCNAME" or servername). Accepted formats:
    /// - plain name: `DC01`
    /// - with leading backslashes: `\\DC01` (both `\\DC01` and `DC01` will be normalized)
    /// If omitted the tool will attempt to discover a domain controller automatically and
    /// fall back to local queries if none is found. When used the value is normalized to a
    /// form accepted by the Net* APIs (leading `\\`).
    #[arg(short = 's', long = "server", value_name = "SERVER")]
    pub server: Option<String>,

    /// Skip automatic domain controller discovery and use the local machine unless --server is provided.
    /// This is equivalent to explicitly passing an empty server (i.e. do not attempt to call NetGetDCName).
    #[arg(long = "no-discover")]
    pub no_discover: bool,

    /// Output requested details as JSON
    #[arg(short = 'j', long = "json")]
    pub json: bool,
}
