// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Entry point cargo actually compiles as a test binary.
//!
//! Everything else lives under `tests/integration/` so the harness and the
//! per-area test modules stay in their own files instead of one growing one.

#[path = "integration/mod.rs"]
mod integration;
