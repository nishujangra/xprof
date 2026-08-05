// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! What a loaded BPF program is made of.

use std::time::SystemTime;

use aya_obj::generated::bpf_prog_type;

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
