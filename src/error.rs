// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Single Error enum for every fallible path in xprof returns.
//!
//! This can be used in any functional code so that nothings is ever written against `unwrap()`

use crate::discovery::XdpMode;
use crate::perms;

/// Convenience alias so callers write `Result<T>` rather than repeating the
/// error type.
pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Link enumeration or another netlink exchange failed.
    #[error("netlink error: {0}")]
    Netlink(String),

    /// A `bpf()` syscall failed.
    #[error("bpf error: {0}")]
    Bpf(String),

    #[error("permission denied {hint}")]
    PermissionDenied { hint: String },

    /// No interface by that name exists on this host.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// The interface exists but has no XDP program attached in any mode.
    #[error("no XDP program attached to {0}")]
    NoXdpProgram(String),

    /// The program is attached, but in generic (SKB) or offload mode.
    #[error(
        "xprof currently supports native XDP only.\n\n\
         Interface:\n  {iface}\n\n\
         Detected mode:\n  {mode}\n\n\
         Native XDP is required."
    )]
    NotNativeXdp { iface: String, mode: XdpMode },

    /// The subcommand parses, but its implementation is not written yet.
    #[error("`{0}` is not implemented yet")]
    NotImplemented(&'static str),

    /// Something is attached, but it is not a `BPF_PROG_TYPE_XDP` program.
    #[error("program {prog_id} is not an XDP program (found {found})")]
    NotXdpProgType { prog_id: u32, found: String },
}

impl Error {
    /// Build a [`Error::PermissionDenied`] for an operation that just failed
    /// with `EPERM`/`EACCES`.
    ///
    /// `operation` says what xprof was trying to do ("reading BPF program
    /// info"); [`perms::diagnose`] is appended underneath to say why it
    /// probably failed on this host. Diagnosis never replaces the operation
    /// description — a wrong or unavailable diagnosis still leaves the user
    /// knowing which call failed.
    pub fn permission_denied(operation: &str) -> Error {
        let hint = match perms::diagnose() {
            Some(diagnosis) => format!("{operation}.\n\n{diagnosis}"),
            None => format!("{operation}."),
        };

        Error::PermissionDenied { hint }
    }

    /// Process exit code for this error.
    ///
    /// `0` is reserved for success and is never returned here — only
    /// [`crate::cli::dispatch`] returning `Ok` produces it. The remaining two
    /// codes split on who is responsible for the failure: `1` when the user
    /// or the host environment caused it (wrong interface, wrong mode,
    /// missing permissions) and `2` when xprof itself hit a bug or a gap —
    /// a malformed netlink exchange, an unexpected `bpf()` failure, or a
    /// subcommand that parses but has no implementation yet. The user can
    /// fix a `1`; a `2` is ours to fix.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::PermissionDenied { .. }
            | Error::InterfaceNotFound(_)
            | Error::NoXdpProgram(_)
            | Error::NotNativeXdp { .. }
            | Error::NotXdpProgType { .. } => 1,

            Error::Netlink(_) | Error::Bpf(_) | Error::NotImplemented(_) => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_native_names_the_detected_mode() {
        let err = Error::NotNativeXdp {
            iface: "eth0".to_string(),
            mode: XdpMode::Generic,
        };

        assert!(err.to_string().contains("generic"), "{err}");
    }

    #[test]
    fn not_native_names_the_interface() {
        let err = Error::NotNativeXdp {
            iface: "eth0".to_string(),
            mode: XdpMode::Offload,
        };

        assert!(err.to_string().contains("eth0"), "{err}");
    }

    #[test]
    fn permission_denied_names_the_operation() {
        let err = Error::permission_denied("reading BPF program info");
        assert!(
            err.to_string().contains("reading BPF program info"),
            "{err}"
        );
    }

    #[test]
    fn user_facing_errors_exit_one() {
        assert_eq!(Error::InterfaceNotFound("eth0".to_string()).exit_code(), 1);
        assert_eq!(Error::NoXdpProgram("eth0".to_string()).exit_code(), 1);
        assert_eq!(
            Error::permission_denied("reading BPF program info").exit_code(),
            1
        );
        assert_eq!(
            Error::NotNativeXdp {
                iface: "eth0".to_string(),
                mode: XdpMode::Generic,
            }
            .exit_code(),
            1
        );
        assert_eq!(
            Error::NotXdpProgType {
                prog_id: 1,
                found: "tracing".to_string(),
            }
            .exit_code(),
            1
        );
    }

    #[test]
    fn internal_errors_exit_two() {
        assert_eq!(Error::Netlink("boom".to_string()).exit_code(), 2);
        assert_eq!(Error::Bpf("boom".to_string()).exit_code(), 2);
        assert_eq!(Error::NotImplemented("top").exit_code(), 2);
    }
}
