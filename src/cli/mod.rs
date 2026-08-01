// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Command-line surface: parsing and dispatch.
//!
//! Parsing is kept separate from execution: `dispatch` resolves the parsed
//! command to a single call, so implementing a subcommand means filling in one
//! function rather than rewiring argument handling.

mod commands;
pub mod output;

use clap::{Parser, Subcommand};

use crate::error::{Error, Result};
use output::OutputFormat;

/// Native XDP profiler for Linux.
#[derive(Debug, Parser)]
#[command(name = "xprof", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Emit machine-readable JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase logging detail; repeat for more.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List interfaces with an XDP program attached.
    List,

    /// Show details about the XDP program on one interface.
    Info {
        /// Interface to inspect, e.g. `eth0`.
        iface: String,
    },
}

/// Run the parsed command.
pub fn dispatch(cli: Cli) -> Result<()> {
    let _format = OutputFormat::from_json_flag(cli.json);

    match cli.command {
        Command::List => Err(Error::NotImplemented("list")),
        Command::Info { iface: _ } => Err(Error::NotImplemented("info")),
    }
}
