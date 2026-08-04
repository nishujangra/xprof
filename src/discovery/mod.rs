// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Discovery — what program is attached, and how.
//!
//! Netlink only; no `bpf()` syscalls. What a program is made of is
//! `metadata`'s job.
//!
//! We read `IFLA_XDP` from `RTM_GETLINK` rather than parsing `ip`/`bpftool`
//! output: no external binary dependency, and no format that shifts between
//! iproute2 versions.
//!
//! Sync by choice — `rtnetlink` would be more convenient but defaults to a
//! tokio socket, and a one-shot read-only dump does not need a runtime.

// Built ahead of its first caller. Remove once a command calls into it.
#![allow(dead_code)]

pub mod link;
pub mod mode;
mod netlink;
