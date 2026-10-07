// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Render — turning data into output.
//!
//! This layer depends on data; data never depends on it. `discovery` and
//! `metadata` know nothing of tables or JSON, and nothing here reaches back
//! into either to fetch what it did not receive as arguments.

pub mod json;
pub mod table;
