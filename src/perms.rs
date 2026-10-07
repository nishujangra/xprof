// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Why a permission check failed.
//!
//! Crate-root, not `discovery` or `metadata`: both layers hit `EPERM` from
//! different syscalls (netlink, bpf), so filing this under either would be a
//! sideways dependency across the layer graph. It sits next to `error.rs`,
//! where anything may depend on it.
//!
//! [`diagnose`] runs only after an operation has already failed with
//! `EPERM`/`EACCES`. xprof never pre-flight checks capabilities and refuses
//! to start — that goes stale across kernel versions (capability names and
//! defaults change) and produces false refusals on systems that would
//! otherwise have worked. Attempt first, explain on failure.

use std::fs;

/// Bit position of `CAP_PERFMON` in the kernel's capability bitmask.
const CAP_PERFMON: u64 = 38;
/// Bit position of `CAP_BPF`.
const CAP_BPF: u64 = 39;

/// Build a human hint for why a privileged operation just failed.
///
/// Checks effective uid, `CAP_BPF`/`CAP_PERFMON` in `CapEff`, and the two
/// sysctls that gate unprivileged BPF and perf-event use. Returns `None` only
/// if every check is read-only-filesystem-unavailable, in which case the
/// caller's own error text is all there is to show.
pub fn diagnose() -> Option<String> {
    let mut lines = Vec::new();

    if is_root() {
        lines.push(
            "running as root but the operation was still denied — check LSM policy (SELinux/AppArmor/seccomp)."
                .to_string(),
        );
    } else if !has_effective_cap(CAP_BPF) {
        lines.push("xprof needs CAP_BPF (or root) to query BPF programs.".to_string());
    } else if !has_effective_cap(CAP_PERFMON) {
        lines.push("xprof needs CAP_PERFMON (or root) to read program statistics.".to_string());
    }

    if let Some(paranoid) = read_sysctl_int("/proc/sys/kernel/perf_event_paranoid") {
        if paranoid > 1 {
            lines.push(format!("  kernel.perf_event_paranoid = {paranoid}"));
        }
    }

    if let Some(disabled) = read_sysctl_int("/proc/sys/kernel/unprivileged_bpf_disabled") {
        if disabled != 0 {
            lines.push(format!("  kernel.unprivileged_bpf_disabled = {disabled}"));
        }
    }

    if lines.is_empty() {
        return None;
    }

    lines.push(String::new());
    lines.push("Try:".to_string());
    lines.push("  sudo xprof ...".to_string());

    Some(lines.join("\n"))
}

/// Whether the process's effective uid is 0.
fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Whether `CapEff` in `/proc/self/status` has the given capability bit set.
///
/// Absence of the file, or of the line, means "cannot tell" rather than "no"
/// — callers only use this to skip a hint that would otherwise be wrong, not
/// to grant access.
fn has_effective_cap(bit: u64) -> bool {
    let Some(mask) = read_cap_eff() else {
        return true;
    };

    mask & (1u64 << bit) != 0
}

fn read_cap_eff() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;

    status.lines().find_map(|line| {
        let hex = line.strip_prefix("CapEff:")?.trim();
        u64::from_str_radix(hex, 16).ok()
    })
}

/// Read a one-line integer sysctl, e.g. under `/proc/sys/kernel/`.
///
/// `None` on any read or parse failure — an unreadable or absent sysctl is
/// not itself diagnostic, just a hint that cannot be shown.
fn read_sysctl_int(path: &str) -> Option<i64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_bit_matches_mask() {
        let mask = 1u64 << CAP_BPF;
        assert_ne!(mask & (1u64 << CAP_BPF), 0);
        assert_eq!(mask & (1u64 << CAP_PERFMON), 0);
    }

    /// Exercises the real `/proc` files on whatever host runs the test suite;
    /// the only contract worth asserting generically is "does not panic".
    #[test]
    fn diagnose_does_not_panic() {
        let _ = diagnose();
    }

    #[test]
    fn missing_sysctl_is_none_not_a_panic() {
        assert_eq!(read_sysctl_int("/proc/does/not/exist"), None);
    }
}
