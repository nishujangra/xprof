// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Metadata — what a program is made of.
//!
//! BPF syscalls and BTF. No netlink: how a program is attached is
//! `discovery`'s job.
//!
//! Phase 0 reports whether BTF exists and how many func/line records it holds.
//! Reading the BTF itself is Phase 1.

// Built ahead of its first caller. Remove once a command calls into it.
#![allow(dead_code)]

pub mod prog_info;
