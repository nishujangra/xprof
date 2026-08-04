// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! How an XDP program is attached.
//!
//! Three places a program can run, and the difference matters: native is in
//! the driver, generic is in the network stack after an `skb` already exists,
//! offload is on the NIC itself. xprof profiles native only — the others are
//! reported so the user learns why, rather than being handed numbers that
//! measure the wrong thing.
//!

//! The kernel reports this in the `IFLA_XDP` block of a link dump.

use netlink_packet_route::link::LinkXdp;

use super::link::Link;
use crate::error::Result;

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
/// A program can be attached in more than one mode at once. Native wins, then
/// offload, then generic.
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

    let attach = native
        .map(|id| (id, XdpMode::Native))
        .or(offload.map(|id| (id, XdpMode::Offload)))
        .or(generic.map(|id| (id, XdpMode::Generic)))
        .map(|(prog_id, mode)| XdpAttach { prog_id, mode });

    Ok(attach)
}

#[cfg(test)]
mod tests {
    use netlink_packet_route::link::XdpAttached;

    use super::*;

    #[test]
    fn mode_names_match_output_format() {
        assert_eq!(XdpMode::Native.to_string(), "native");
        assert_eq!(XdpMode::Generic.to_string(), "generic");
        assert_eq!(XdpMode::Offload.to_string(), "offload");
    }

    fn link_with(xdp: Vec<LinkXdp>) -> Link {
        Link {
            index: 1,
            name: "test0".to_string(),
            xdp,
        }
    }

    #[test]
    fn no_xdp_attributes_means_nothing_attached() {
        assert_eq!(detect(&link_with(vec![])).unwrap(), None);
    }

    #[test]
    fn drv_prog_id_is_native() {
        let link = link_with(vec![LinkXdp::DrvProgId(42)]);

        assert_eq!(
            detect(&link).unwrap(),
            Some(XdpAttach {
                prog_id: 42,
                mode: XdpMode::Native
            })
        );
    }

    #[test]
    fn skb_prog_id_is_generic() {
        let link = link_with(vec![LinkXdp::SkbProgId(7)]);

        assert_eq!(detect(&link).unwrap().unwrap().mode, XdpMode::Generic);
    }

    #[test]
    fn hw_prog_id_is_offload() {
        let link = link_with(vec![LinkXdp::HwProgId(9)]);

        assert_eq!(detect(&link).unwrap().unwrap().mode, XdpMode::Offload);
    }

    /// `IFLA_XDP_ATTACHED` alone cannot name a mode, so it must not be treated
    /// as an attachment on its own.
    #[test]
    fn attached_flag_without_prog_id_is_ignored() {
        let link = link_with(vec![LinkXdp::Attached(XdpAttached::Driver)]);

        assert_eq!(detect(&link).unwrap(), None);
    }

    #[test]
    fn native_wins_over_generic() {
        let link = link_with(vec![LinkXdp::SkbProgId(7), LinkXdp::DrvProgId(42)]);
        let got = detect(&link).unwrap().unwrap();

        assert_eq!(got.mode, XdpMode::Native);
        assert_eq!(got.prog_id, 42, "prog_id must match the winning mode");
    }

    #[test]
    fn offload_wins_over_generic() {
        let link = link_with(vec![LinkXdp::SkbProgId(7), LinkXdp::HwProgId(9)]);
        let got = detect(&link).unwrap().unwrap();

        assert_eq!(got.mode, XdpMode::Offload);
        assert_eq!(got.prog_id, 9);
    }
}
