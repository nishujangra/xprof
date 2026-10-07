// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! `xprof info <iface>` — details about the XDP program on one interface.
//!
//! Discovery is fully exhausted before metadata is touched: resolve the
//! interface, read its attach state, and enforce native mode, all without a
//! BPF syscall. Only once that cheap path has passed does a `bpf()` call
//! happen at all, so a generic-mode program is rejected without ever
//! touching the privileged path.

use crate::cli::output::OutputFormat;
use crate::discovery::{link, mode};
use crate::error::{Error, Result};
use crate::metadata::prog_info;
use crate::render::table;

/// Run `xprof info <iface>`.
pub fn run(iface: &str, _fmt: OutputFormat) -> Result<()> {
    let links = link::list_links()?;
    let l = links
        .iter()
        .find(|l| l.name == iface)
        .ok_or_else(|| Error::InterfaceNotFound(iface.to_string()))?;

    let attach = mode::detect(l)?.ok_or_else(|| Error::NoXdpProgram(iface.to_string()))?;
    mode::ensure_native(iface, attach.mode)?;

    let info = prog_info::info_for_id(attach.prog_id)?;
    prog_info::ensure_xdp(&info)?;

    let line_info = if info.has_line_info() {
        "available"
    } else {
        "unavailable"
    };

    print!(
        "{}",
        table::write_fields(&[
            ("Interface:", iface.to_string()),
            ("Mode:", attach.mode.to_string()),
            ("Program:", info.name.clone()),
            ("ID:", info.id.to_string()),
            ("Type:", info.type_name().to_string()),
            ("BTF ID:", info.btf_id_display()),
            ("Func info:", info.func_info_display()),
            ("Line info:", line_info.to_string()),
        ])
    );

    Ok(())
}
