// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Harness scaffolding shared by the integration test modules.
//!
//! These tests drive the real `xprof` binary with `assert_cmd` rather than
//! calling into the library directly: the thing under test here is the CLI
//! surface itself — argument parsing, exit codes, and what gets printed
//! where — which only exists once `main` is involved.

mod cli;

use assert_cmd::Command;

/// A `Command` for the `xprof` binary, built fresh for each assertion so
/// tests cannot see state left behind by an earlier one.
pub fn xprof() -> Command {
    Command::cargo_bin("xprof").expect("xprof binary must build before integration tests run")
}
