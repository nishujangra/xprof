// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Network interface enumeration via `RTM_GETLINK`.
//!
//! Which interfaces exist. `IFLA_XDP` rides along in the same dump, but
//! interpreting it belongs to `mode.rs`.

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkMessage},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::error::{Error, Result};

/// A network interface, as reported by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Kernel interface index (`ifindex`).
    pub index: u32,
    /// Interface name, e.g. `eth0`.
    pub name: String,
}

/// Generous — an undersized buffer truncates messages rather than splitting
/// them across reads.
const RECV_BUF_LEN: usize = 32 * 1024;

/// Enumerate every network interface on the host, in kernel order.
pub fn list_links() -> Result<Vec<Link>> {
    let socket = open_route_socket()?;
    send_dump_request(&socket)?;
    recv_links(&socket)
}

/// Open and bind a blocking `NETLINK_ROUTE` socket.
fn open_route_socket() -> Result<Socket> {
    let mut socket = Socket::new(NETLINK_ROUTE)
        .map_err(|e| Error::Netlink(format!("cannot open NETLINK_ROUTE socket: {e}")))?;

    // Binding is what makes replies routable back to us.
    socket
        .bind_auto()
        .map_err(|e| Error::Netlink(format!("cannot bind netlink socket: {e}")))?;

    Ok(socket)
}

/// Send the `RTM_GETLINK` dump request.
fn send_dump_request(socket: &Socket) -> Result<()> {
    let mut header = NetlinkHeader::default();
    // DUMP asks for every link rather than a single one.
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut request = NetlinkMessage::new(
        header,
        NetlinkPayload::from(RouteNetlinkMessage::GetLink(LinkMessage::default())),
    );
    // Fills in the length field; without it the kernel rejects the message.
    request.finalize();

    let mut buf = vec![0u8; request.buffer_len()];
    request.serialize(&mut buf);

    let kernel = SocketAddr::new(0, 0);
    socket
        .send_to(&buf, &kernel, 0)
        .map_err(|e| Error::Netlink(format!("cannot send RTM_GETLINK: {e}")))?;

    Ok(())
}

/// Read the multipart reply until `NLMSG_DONE`, collecting links.
fn recv_links(socket: &Socket) -> Result<Vec<Link>> {
    let mut links = Vec::new();
    let mut buf = vec![0u8; RECV_BUF_LEN];

    // A dump spans several datagrams, each packing several messages, and ends
    // with NLMSG_DONE — the only correct stop condition on a blocking socket.
    'recv: loop {
        // `recv` takes `&mut impl BufMut`; a fresh slice each iteration keeps
        // the write cursor at the buffer start.
        let mut window = &mut buf[..];
        let n = socket
            .recv(&mut window, 0)
            .map_err(|e| Error::Netlink(format!("cannot read netlink reply: {e}")))?;

        let mut offset = 0;
        while offset < n {
            let bytes = &buf[offset..n];

            let msg = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(bytes)
                .map_err(|e| Error::Netlink(format!("malformed netlink message: {e}")))?;

            let len = msg.header.length as usize;
            // Zero length would spin this loop forever.
            if len == 0 {
                return Err(Error::Netlink(
                    "netlink message declared zero length".to_string(),
                ));
            }

            match msg.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                    links.push(parse_link(link));
                }
                NetlinkPayload::Done(_) => break 'recv,
                NetlinkPayload::Error(err) => return Err(netlink_error(err)),
                // Noop/Overrun, and message types we did not ask for.
                _ => {}
            }

            offset += len;
        }
    }

    Ok(links)
}

/// Pull index and name out of one `RTM_NEWLINK` message.
///
/// The kernel always sends `IFLA_IFNAME`, but attributes are a `Vec`, so the
/// name is optional at the type level — fall back rather than panic.
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

/// Map an `NLMSG_ERROR` payload onto our error type.
///
/// `EPERM`/`EACCES` get their own variant so permission failures stay
/// distinguishable instead of collapsing into a generic netlink string.
fn netlink_error(err: netlink_packet_core::ErrorMessage) -> Error {
    let errno = err.code.map(|c| c.get().unsigned_abs()).unwrap_or(0);

    match errno as i32 {
        libc::EPERM | libc::EACCES => Error::PermissionDenied {
            hint: "reading the interface list requires CAP_NET_ADMIN or root".to_string(),
        },
        _ => Error::Netlink(format!("kernel returned error: {err:?}")),
    }
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
