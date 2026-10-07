// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! `xprof list` — every interface with an XDP program attached.
//!
//! Deliberately permissive: generic and offload rows are shown too, with the
//! mode named. Refusing to list a generic program would leave the user
//! unable to discover why `info` later rejects it. Enforcement belongs in
//! `info` and in profiling, not here.

use crate::discovery::{link, mode};
use crate::error::Result;
use crate::metadata::prog_info;
use crate::render::table;

/// Run `xprof list`.
pub fn run(_fmt: crate::cli::output::OutputFormat) -> Result<()> {
    let rows: Vec<Vec<String>> = link::list_links()?
        .into_iter()
        .filter_map(|l| mode::detect(&l).ok().flatten().map(|attach| (l, attach)))
        .map(|(l, attach)| {
            // A program can vanish between enumeration and lookup — a real
            // race, not a bug — so fall back to a placeholder rather than
            // aborting the whole listing over one row.
            let name = prog_info::info_for_id(attach.prog_id)
                .map(|info| info.name)
                .unwrap_or_else(|_| "?".to_string());

            vec![
                l.name,
                attach.mode.to_string(),
                name,
                attach.prog_id.to_string(),
            ]
        })
        .collect();

    if rows.is_empty() {
        // Not an error: a host with no XDP programs attached is an entirely
        // normal state, and `list` exits 0 for it.
        println!("No XDP programs attached.");
        return Ok(());
    }

    print!(
        "{}",
        table::write_table(&["Interface", "Mode", "Program", "ID"], &rows)
    );

    Ok(())
}
