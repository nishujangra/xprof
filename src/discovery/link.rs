// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>


//! Which network interfaces exist.
//!
//! "Link" is netlink's word for a network interface — `eth0`, `lo`, `wlan0`.
//! Not a `bpf_link`.
//!
//! An interface's `index` is what kernel APIs take to identify it, including
//! XDP attach; `name` is for humans and for matching `--iface`. Interpreting
//! the `IFLA_XDP` attribute on the same message belongs to `mode.rs`.

use netlink_packet_route::link::{LinkAttribute, LinkMessage};

use super::netlink;
use crate::error::Result;

/// A network interface, as reported by the kernel
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Kernel interface index (`ifindex`). Non-zero, and unique among live
    /// interfaces but not stable on reboots
    pub index: u32, 
    
    /// interface name eg 'eth0'
    pub name: String, 
}



// List every network on the host, in kernel order
pub fn list_links() -> Result<Vec<Link>> {
    
    // let mut links = Vec::new();
    // for msg in netlink::dump_links()? {
    //     links.push(parse_link(msg));
    // }
    // Ok(links)

    // shorter way
    Ok(netlink::dump_links()?.into_iter().map(parse_link).collect())
}


/// Pull index and name out of one `RTM_NEWLINK` message.
///
/// The index sits in the message's fixed header, so it is a plain field read.
/// The name is one entry in a list of optional attributes, so it has to be
/// searched for. The kernel always sends `IFLA_IFNAME`, but a `Vec` cannot
/// promise that — hence a fallback rather than a panic.
fn parse_link(msg: LinkMessage) -> Link {
    let index = msg.header.index;

    let name = msg
        .attributes
        .into_iter()
        .find_map(|attr| match attr {
            LinkAttribute::IfName(name) => Some(name),
            _ => None,
        })
        .unwrap_or_else(|| format!("if{index}"));

    Link { index, name }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Every Linux host has `lo`, so this is not environment-dependent.
    #[test]
    fn lists_loopback() {
        let links = list_links().expect("RTM_GETLINK dump should succeed");

        let lo = links
            .iter()
            .find(|l| l.name == "lo")
            .expect("host must have a loopback interface");

        // lo is conventionally 1, but the real invariant is non-zero.
        assert!(lo.index > 0, "interface index must be non-zero");
    }

    #[test]
    fn indices_are_unique() {
        let links = list_links().expect("RTM_GETLINK dump should succeed");

        let mut indices: Vec<u32> = links.iter().map(|l| l.index).collect();
        let total = indices.len();
        indices.sort_unstable();
        indices.dedup();

        assert_eq!(
            total,
            indices.len(),
            "ifindex must uniquely identify a link"
        );
    }
}
