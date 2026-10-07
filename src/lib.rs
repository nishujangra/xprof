// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! xprof — native XDP profiler for Linux.
//!
//! The engine lives here, not in `main.rs`, so it can be driven directly —
//! by integration tests, or eventually by other tools — without spawning the
//! `xprof` binary as a subprocess.

pub mod cli;
pub mod discovery;
pub mod error;
pub mod metadata;
pub mod perms;
pub mod render;
