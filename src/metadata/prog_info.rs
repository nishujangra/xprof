// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! What a loaded BPF program is made of.
//!
//! [`info_for_id`] is the only way in: give it a program id and it does the
//! `BPF_PROG_GET_FD_BY_ID` / `BPF_OBJ_GET_INFO_BY_FD` round-trip, returning
//! owned data so no fd outlives the call.

use std::os::fd::{AsFd, AsRawFd};
use std::time::SystemTime;

use aya::programs::ProgramInfo;
use aya_obj::generated::bpf_prog_type;

use crate::error::{Error, Result};

/// A loaded BPF program, as the kernel describes it.
///
/// One `bpf_prog_info` read, kept as owned data so callers never hold a program
/// fd open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgInfo {
    /// Kernel program id, stable while the program stays loaded.
    pub id: u32,

    /// Program name, truncated by the kernel to 15 bytes.
    pub name: String,

    /// What kind of program this is. xprof wants `BPF_PROG_TYPE_XDP`.
    pub prog_type: bpf_prog_type,

    /// BTF id, if the program was loaded with BTF. `None` means no source-level
    /// information is available at all.
    pub btf_id: Option<u32>,

    /// When the program was loaded. `None` on kernels that do not report it.
    pub load_time: Option<SystemTime>,

    /// Size of the JIT-compiled machine code, in bytes. Zero when the JIT is
    /// disabled.
    pub jited_len: u32,

    /// Number of BTF function records.
    pub nr_func_info: u32,

    /// Number of BTF line records. Non-zero is what makes source-line output
    /// possible in Phase 1.
    pub nr_line_info: u32,
}

impl ProgInfo {
    /// Whether the program carries BTF line records.
    ///
    /// A BTF id alone is not enough — a program can have BTF with no line
    /// information, so both have to hold.
    pub fn has_line_info(&self) -> bool {
        self.btf_id.is_some() && self.nr_line_info > 0
    }

    /// Whether the program carries BTF function records.
    pub fn has_func_info(&self) -> bool {
        self.btf_id.is_some() && self.nr_func_info > 0
    }

    /// BTF id for output, or `-` when the program was loaded without BTF.
    pub fn btf_id_display(&self) -> String {
        match self.btf_id {
            Some(id) => id.to_string(),
            None => "-".to_string(),
        }
    }

    /// Function-record count for output, e.g. `4 records`.
    pub fn func_info_display(&self) -> String {
        record_count(self.has_func_info(), self.nr_func_info)
    }

    /// Line-record count for output.
    ///
    /// Phase 0 reports presence and count only; decoding the records is
    /// Phase 1's job.
    pub fn line_info_display(&self) -> String {
        record_count(self.has_line_info(), self.nr_line_info)
    }

    /// Program type as it should appear in output.
    ///
    /// The generated enum's `Debug` is the kernel's constant name, which is
    /// the wrong register for a terminal table.
    pub fn type_name(&self) -> &'static str {
        match self.prog_type {
            bpf_prog_type::BPF_PROG_TYPE_XDP => "XDP",
            bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS => "TC (classifier)",
            bpf_prog_type::BPF_PROG_TYPE_SCHED_ACT => "TC (action)",
            bpf_prog_type::BPF_PROG_TYPE_KPROBE => "kprobe",
            bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT => "tracepoint",
            bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT => "perf event",
            bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER => "socket filter",
            bpf_prog_type::BPF_PROG_TYPE_TRACING => "tracing",
            _ => "other",
        }
    }
}

/// Render a BTF record count the way `xprof info` prints it.
///
/// "unavailable" rather than "0 records": if there is no BTF at all the count is
/// meaningless, and the user needs to know source-level output is impossible
/// rather than that some number happened to be zero.
fn record_count(present: bool, n: u32) -> String {
    if !present {
        return "unavailable".to_string();
    }

    match n {
        1 => "1 record".to_string(),
        _ => format!("{n} records"),
    }
}

/// Look up a loaded program by id.
///
/// Fails with [`Error::Bpf`] if no program has that id — which includes the
/// program being unloaded between discovery and this call.
pub fn info_for_id(id: u32) -> Result<ProgInfo> {
    // `loaded_programs` because aya's `ProgramInfo::new_from_fd` is private and
    // there is no `from_id`. Linear in the number of loaded programs; fine for
    // one lookup, but do not call this per row in a loop.
    let info = aya::programs::loaded_programs()
        .filter_map(std::result::Result::ok)
        .find(|p| p.id() == id)
        .ok_or_else(|| Error::Bpf(format!("no BPF program with id {id}")))?;

    let (nr_func_info, nr_line_info) = btf_record_counts(&info)?;

    Ok(ProgInfo {
        id: info.id(),
        // The kernel truncates names to 15 bytes and may hand back non-UTF-8.
        name: info
            .name_as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("prog{id}")),
        prog_type: info.program_type(),
        btf_id: info.btf_id(),
        load_time: info.loaded_at(),
        jited_len: info.size_jitted(),
        nr_func_info,
        nr_line_info,
    })
}

/// Fail unless `info` is a `BPF_PROG_TYPE_XDP` program.
///
/// A metadata fact: what the program *is*, independent of how it is attached.
/// Callers decide whether this is fatal; `list` does not want it to be.
pub fn ensure_xdp(info: &ProgInfo) -> Result<()> {
    if info.prog_type == bpf_prog_type::BPF_PROG_TYPE_XDP {
        return Ok(());
    }

    Err(Error::NotXdpProgType {
        prog_id: info.id,
        found: info.type_name().to_string(),
    })
}

/// Read `nr_func_info` and `nr_line_info` straight from `bpf_prog_info`.
///
/// aya wraps that struct with a private field and exposes no accessor for these
/// two, so this repeats the `BPF_OBJ_GET_INFO_BY_FD` call on aya's own fd. Delete
/// this the day aya adds them.
fn btf_record_counts(info: &ProgramInfo) -> Result<(u32, u32)> {
    use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_prog_info};

    let fd = info
        .fd()
        .map_err(|e| Error::Bpf(format!("cannot open fd for program {}: {e}", info.id())))?;

    // SAFETY: `bpf_prog_info` and `bpf_attr` are plain repr(C) kernel structs
    // with no invalid bit patterns, so zeroed is a valid starting value. The
    // kernel reads `info_len` bytes at `info` and writes no further, and `raw`
    // outlives the call.
    let mut raw = unsafe { std::mem::zeroed::<bpf_prog_info>() };
    let mut attr = unsafe { std::mem::zeroed::<bpf_attr>() };

    attr.info.bpf_fd = fd.as_fd().as_raw_fd() as u32;
    attr.info.info_len = std::mem::size_of::<bpf_prog_info>() as u32;
    // `*mut`, not `*const` — the kernel writes the struct through this pointer.
    attr.info.info = &mut raw as *mut _ as u64;

    let attr_len = std::mem::size_of::<bpf_attr>();
    // SAFETY: `attr` is a valid `bpf_attr` and `attr_len` is its real size.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
            &mut attr,
            attr_len,
        )
    };

    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(match errno.raw_os_error() {
            Some(libc::EPERM) | Some(libc::EACCES) => {
                Error::permission_denied("reading BPF program info")
            }
            _ => Error::Bpf(format!(
                "BPF_OBJ_GET_INFO_BY_FD failed for program {}: {errno}",
                info.id()
            )),
        });
    }

    Ok((raw.nr_func_info, raw.nr_line_info))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xdp_prog() -> ProgInfo {
        ProgInfo {
            id: 142,
            name: "xdp_cidr".to_string(),
            prog_type: bpf_prog_type::BPF_PROG_TYPE_XDP,
            btf_id: Some(37),
            load_time: None,
            jited_len: 512,
            nr_func_info: 4,
            nr_line_info: 12,
        }
    }

    #[test]
    fn xdp_type_renders_for_output() {
        assert_eq!(xdp_prog().type_name(), "XDP");
    }

    #[test]
    fn record_counts_render_for_output() {
        let p = xdp_prog();

        assert_eq!(p.btf_id_display(), "37");
        assert_eq!(p.func_info_display(), "4 records");
        assert_eq!(p.line_info_display(), "12 records");
    }

    #[test]
    fn one_record_is_singular() {
        let p = ProgInfo {
            nr_func_info: 1,
            ..xdp_prog()
        };

        assert_eq!(p.func_info_display(), "1 record");
    }

    /// Without BTF the counts are meaningless, so say so rather than print `0`.
    #[test]
    fn no_btf_reports_unavailable_not_zero() {
        let p = ProgInfo {
            btf_id: None,
            nr_func_info: 0,
            nr_line_info: 0,
            ..xdp_prog()
        };

        assert_eq!(p.btf_id_display(), "-");
        assert_eq!(p.func_info_display(), "unavailable");
        assert_eq!(p.line_info_display(), "unavailable");
    }

    /// BTF present but no line records — a real case for programs built without
    /// debug info.
    #[test]
    fn btf_without_line_records_is_unavailable() {
        let p = ProgInfo {
            nr_line_info: 0,
            ..xdp_prog()
        };

        assert_eq!(p.btf_id_display(), "37", "the BTF id still exists");
        assert_eq!(p.line_info_display(), "unavailable");
        assert_eq!(
            p.func_info_display(),
            "4 records",
            "func records unaffected"
        );
    }

    #[test]
    fn ensure_xdp_accepts_xdp_program() {
        assert!(ensure_xdp(&xdp_prog()).is_ok());
    }

    #[test]
    fn ensure_xdp_rejects_other_types() {
        let p = ProgInfo {
            prog_type: bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS,
            ..xdp_prog()
        };

        let err = ensure_xdp(&p).expect_err("non-XDP program must be rejected");
        assert!(matches!(err, Error::NotXdpProgType { prog_id, .. } if prog_id == p.id));
    }

    #[test]
    fn missing_id_is_an_error_not_a_panic() {
        // u32::MAX is not a plausible live program id.
        assert!(info_for_id(u32::MAX).is_err());
    }

    /// Needs root and at least one loaded BPF program, so it cannot run in CI.
    ///
    ///     cargo test -- --ignored
    #[test]
    #[ignore = "requires root and a loaded BPF program"]
    fn reads_a_real_program() {
        let id = aya::programs::loaded_programs()
            .filter_map(std::result::Result::ok)
            .map(|p| p.id())
            .next()
            .expect("host must have at least one loaded BPF program");

        let info = info_for_id(id).expect("reading a live program should succeed");

        assert_eq!(info.id, id);
        assert!(!info.name.is_empty(), "name must not be empty");
        // Compare against `bpftool prog list` for ground truth.
        println!("{info:#?}");
    }

    #[test]
    fn line_info_needs_both_btf_and_records() {
        assert!(xdp_prog().has_line_info());

        let no_btf = ProgInfo {
            btf_id: None,
            ..xdp_prog()
        };
        assert!(!no_btf.has_line_info(), "no BTF means no line info");

        let btf_but_no_lines = ProgInfo {
            nr_line_info: 0,
            ..xdp_prog()
        };
        assert!(
            !btf_but_no_lines.has_line_info(),
            "BTF alone does not imply line records"
        );
    }
}
