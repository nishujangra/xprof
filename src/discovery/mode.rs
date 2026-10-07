// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! How an XDP program is attached.
//!
//! Three places a program can run, and the difference matters: native is in
//! the driver, generic is in the network stack after an `skb` already exists,
//! offload is on the NIC itself. xprof profiles native only — the others are
//! reported so the user learns why, rather than being handed numbers that
//! measure the wrong thing.
//!
//! The kernel reports this in the `IFLA_XDP` block of a link dump. Each mode
//! has its own program id attribute, and more than one can be set at a time —
//! an interface can carry a native and a generic program together.
//!
//! When that happens, [`detect`] reports native, then offload, then generic.
//! Native first because it is the only mode xprof can profile; generic last
//! because it is the fallback the kernel itself treats as least specific.
//!
//! `IFLA_XDP_ATTACHED` is not used to pick the mode. It reports
//! `XDP_ATTACHED_MULTI` for the multi-mode case, which names no single mode,
//! so the per-mode ids are the only reliable source.

use netlink_packet_route::link::LinkXdp;

use super::link::Link;
use crate::error::{Error, Result};

/// Where an attached XDP program runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    /// In the driver's receive path, before an `skb` exists. What xprof
    /// profiles.
    Native,

    /// In the network stack, after the kernel has already built an `skb`.
    /// Works on any interface, but the cost profile is not native XDP's.
    Generic,

    /// On the NIC. The host CPU never runs the program, so there is nothing
    /// for a CPU profiler to sample.
    Offload,
}

impl XdpMode {
    /// What to call this mode in output.
    ///
    /// These match the `xdpdrv`/`xdpgeneric`/`xdpoffload` distinction users
    /// already know from `ip link`, in the plainer spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Generic => "generic",
            Self::Offload => "offload",
        }
    }
}

impl std::fmt::Display for XdpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An XDP program attached to an interface.
///
/// Only ever constructed for an interface that has one. "Nothing attached" is
/// `Option::None` at the call site rather than a variant here, so the type
/// system stops anyone reading a `prog_id` that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpAttach {
    /// BPF program id. The handle `metadata` needs to look the program up.
    pub prog_id: u32,

    /// Which of the three attach points it is running at.
    pub mode: XdpMode,
}

/// What is attached to this interface, if anything.
///
/// Native, then offload, then generic, per the module doc.
pub fn detect(link: &Link) -> Result<Option<XdpAttach>> {
    let mut native = None;
    let mut generic = None;
    let mut offload = None;

    for attr in &link.xdp {
        match attr {
            LinkXdp::DrvProgId(id) => native = Some(*id),
            LinkXdp::SkbProgId(id) => generic = Some(*id),
            LinkXdp::HwProgId(id) => offload = Some(*id),
            _ => {}
        }
    }

    // Order here is the precedence.
    let attach = native
        .map(|id| (id, XdpMode::Native))
        .or(offload.map(|id| (id, XdpMode::Offload)))
        .or(generic.map(|id| (id, XdpMode::Generic)))
        .map(|(prog_id, mode)| XdpAttach { prog_id, mode });

    Ok(attach)
}

/// Fail unless `mode` is [`XdpMode::Native`].
///
/// A discovery fact: how the program is attached, independent of what it is.
/// Callers decide whether this is fatal; `list` does not want it to be.
pub fn ensure_native(iface: &str, mode: XdpMode) -> Result<()> {
    if mode == XdpMode::Native {
        return Ok(());
    }

    Err(Error::NotNativeXdp {
        iface: iface.to_string(),
        mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_names_match_output_format() {
        assert_eq!(XdpMode::Native.to_string(), "native");
        assert_eq!(XdpMode::Generic.to_string(), "generic");
        assert_eq!(XdpMode::Offload.to_string(), "offload");
    }

    #[test]
    fn ensure_native_accepts_native_mode() {
        assert!(ensure_native("eth0", XdpMode::Native).is_ok());
    }

    #[test]
    fn ensure_native_rejects_other_modes() {
        let err = ensure_native("eth0", XdpMode::Generic).expect_err("generic must be rejected");
        assert!(matches!(
            err,
            Error::NotNativeXdp {
                mode: XdpMode::Generic,
                ..
            }
        ));
    }
}
