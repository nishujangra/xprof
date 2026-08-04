// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Netlink transport — talking to the kernel over a socket.
//!
//! Linux has no syscall for "list my interfaces". You open a socket to the
//! kernel, send a request, and read back a stream of binary messages. All of
//! that lives here, so `link` and `mode` can work with meaning instead of
//! bytes.
//!
//! [`dump_links`] returns the kernel's messages unchanged, attributes and all.
//! That way `link` can read the name and `mode` can read the XDP attachment
//! from a single round-trip instead of asking the kernel twice.

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{RouteNetlinkMessage, link::LinkMessage};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::error::{Error, Result};

/// Netlink truncates a message that will not fit rather than continuing it in
/// the next read, so the buffer has to be big enough for the largest reply.
/// 32 KiB is far more than a link dump needs.
const RECV_BUF_LEN: usize = 32 * 1024;

/// Ask the kernel for every interface, one message each.
///
/// Nothing is thrown away here — each message arrives as the kernel wrote it,
/// and callers read whichever attributes they care about.
pub fn dump_links() -> Result<Vec<LinkMessage>> {
    let socket = open_route_socket()?;
    send_getlink_dump(&socket)?;
    collect_links(&socket)
}

/// Open a socket to the kernel's routing subsystem.
///
/// Blocking on purpose: a one-shot dump has nothing else to do while it waits.
fn open_route_socket() -> Result<Socket> {
    let mut socket = Socket::new(NETLINK_ROUTE)
        .map_err(|e| Error::Netlink(format!("cannot open NETLINK_ROUTE socket: {e}")))?;

    // Binding gives us an address. Without one the kernel has nowhere to send
    // the reply.
    socket
        .bind_auto()
        .map_err(|e| Error::Netlink(format!("cannot bind netlink socket: {e}")))?;

    Ok(socket)
}

/// Write the request that starts the dump.
fn send_getlink_dump(socket: &Socket) -> Result<()> {
    let mut header = NetlinkHeader::default();
    // REQUEST means we are asking, DUMP means all of them rather than one.
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut request = NetlinkMessage::new(
        header,
        NetlinkPayload::from(RouteNetlinkMessage::GetLink(LinkMessage::default())),
    );
    // Every netlink message states its own length. `finalize` computes it;
    // forget this call and the kernel drops the message.
    request.finalize();

    let mut buf = vec![0u8; request.buffer_len()];
    request.serialize(&mut buf);

    // Port 0 is the kernel itself.
    let kernel = SocketAddr::new(0, 0);
    socket
        .send_to(&buf, &kernel, 0)
        .map_err(|e| Error::Netlink(format!("cannot send RTM_GETLINK: {e}")))?;

    Ok(())
}

/// Read replies until the kernel says it is finished.
///
/// The reply is packed two levels deep: it arrives as several datagrams, and
/// each datagram holds several messages back to back. Hence two loops — the
/// outer one reads a datagram, the inner one walks the messages inside it.
fn collect_links(socket: &Socket) -> Result<Vec<LinkMessage>> {
    let mut links = Vec::new();
    let mut buf = vec![0u8; RECV_BUF_LEN];

    // Labelled because the "we are done" message shows up inside the inner
    // loop, and that has to break out of both.
    'recv: loop {
        // A fresh slice every time, so each read starts writing at the front
        // of the buffer instead of where the last one stopped.
        let mut window = &mut buf[..];
        let n = socket
            .recv(&mut window, 0)
            .map_err(|e| Error::Netlink(format!("cannot read netlink reply: {e}")))?;

        let mut offset = 0;
        while offset < n {
            let bytes = &buf[offset..n];

            let msg = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(bytes)
                .map_err(|e| Error::Netlink(format!("malformed netlink message: {e}")))?;

            // Each message declares its own size, which is how we find the
            // next one. A zero would leave `offset` where it is and hang here.
            let len = msg.header.length as usize;
            if len == 0 {
                return Err(Error::Netlink(
                    "netlink message declared zero length".to_string(),
                ));
            }

            match msg.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                    links.push(link);
                }
                // Waiting for this is the only safe way to stop. Guessing from
                // a short read would block forever on the next `recv`.
                NetlinkPayload::Done(_) => break 'recv,
                NetlinkPayload::Error(err) => return Err(error_from_kernel(err)),
                // Noop/Overrun, and anything we did not ask for.
                _ => {}
            }

            // Step over the message we just read, onto the next one.
            offset += len;
        }
    }

    Ok(links)
}

/// Turn a kernel error reply into one of ours.
///
/// Permission errors get their own variant rather than a generic message,
/// because "you need root" is worth telling the user directly.
fn error_from_kernel(err: netlink_packet_core::ErrorMessage) -> Error {
    let errno = err.code.map(|c| c.get().unsigned_abs()).unwrap_or(0);

    match errno as i32 {
        libc::EPERM | libc::EACCES => Error::PermissionDenied {
            hint: "reading the interface list requires CAP_NET_ADMIN or root".to_string(),
        },
        _ => Error::Netlink(format!("kernel returned error: {err:?}")),
    }
}
