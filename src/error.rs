// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Single Error enum for every fallible path in xprof returns.
//!
//! This can be used in any functional code so that nothings is ever written against `unwrap()`

use crate::discovery::XdpMode;

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

    #[error("permission denied: {hint}")]
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
}
