// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! CLI-level behavior: exit codes and the messages tied to them.
//!
//! Exit code discipline, held to everywhere in xprof:
//!   0   success, including "nothing attached"
//!   1   user/environment error (no such iface, wrong mode, permissions)
//!   2   internal error

use predicates::prelude::*;

use super::xprof;

/// A name no real interface will ever have, so this is not
/// environment-dependent.
const MISSING_IFACE: &str = "xprof-test-missing-iface";

#[test]
fn list_exits_zero_on_a_clean_host() {
    // CI and most dev machines have no XDP program attached anywhere, so
    // `list` hits its empty-state message, not a populated table. Either
    // way the exit code must be 0 — "nothing attached" is not an error.
    xprof().arg("list").assert().success();
}

#[test]
fn list_reports_nothing_attached_in_plain_language() {
    xprof().arg("list").assert().success().stdout(
        predicate::str::contains("No XDP programs attached").or(
            predicate::str::contains("Interface"), // a populated table instead, on a host with XDP attached
        ),
    );
}

#[test]
fn info_on_missing_interface_exits_one_with_the_right_message() {
    xprof()
        .args(["info", MISSING_IFACE])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("interface not found"))
        .stderr(predicate::str::contains(MISSING_IFACE));
}

#[test]
fn info_on_unattached_interface_exits_one_with_a_distinct_message() {
    // `lo` always exists but never carries an XDP program, so this takes a
    // different path through the same command than the missing-interface
    // case above — the two must not share a message.
    xprof()
        .args(["info", "lo"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no XDP program attached"));
}
