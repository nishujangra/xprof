// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! xprof — native XDP profiler for Linux.

mod cli;
mod error;

use clap::Parser;

use error::Result;

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    cli::dispatch(cli::Cli::parse())
}
