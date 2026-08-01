// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! How a command renders its result.
//!
//! Derived once from the global `--json` flag and threaded to commands, so no
//! command has to reach back for the raw flag.

/// Rendering mode for command output.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text for a terminal.
    Text,
    /// Machine-readable JSON.
    Json,
}

impl OutputFormat {
    /// Pick a format from the global `--json` flag.
    pub fn from_json_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}
