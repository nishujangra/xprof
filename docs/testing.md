# Manual testing: a real XDP program on a real interface

Automated tests cannot attach XDP to a NIC — CI runners have no interface
worth profiling, and attaching to `lo` is unsupported by the kernel's
driver model. Everything here must be exercised by hand against each PR
that touches interface discovery (`discovery::link`, `discovery::mode`) or
reads live program metadata (`metadata::prog_info`), and against `list` and
`info` themselves.

This procedure does not run in CI. Treat it as a checklist, run it locally
before merging a PR that touches netlink or BPF syscalls, and paste the
output into the PR description.

## 1. Set up a veth pair

A `veth` pair gives you two real interfaces without touching physical
hardware. Native XDP attaches to either end exactly as it would to a NIC.

```bash
sudo ip link add xprof-a type veth peer name xprof-b
sudo ip link set xprof-a up
sudo ip link set xprof-b up
```

Confirm both sides exist and have no XDP program yet:

```bash
ip link show xprof-a
ip link show xprof-b
```

Neither should show an `xdp` or `xdpgeneric` line.

## 2. Build a minimal XDP program

A pass-through program is enough — Phase 0 never inspects program
behavior, only its metadata and attach mode.

`xdp_pass.bpf.c`:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

```bash
clang -O2 -g -target bpf -c xdp_pass.bpf.c -o xdp_pass.bpf.o
```

`-g` matters: without it the program carries no BTF, and `nr_func_info` /
`nr_line_info` will read `unavailable` no matter what `xprof info` is
asked to show. Verifying the "no BTF" path and the "has BTF" path both
need a build of this file, one with `-g` and one without.

## 3. Attach it, one mode at a time

**Native** (what xprof profiles):

```bash
sudo ip link set dev xprof-a xdp obj xdp_pass.bpf.o sec xdp
```

**Generic** (SKB path — xprof must detect and refuse this):

```bash
sudo ip link set dev xprof-b xdpgeneric obj xdp_pass.bpf.o sec xdp
```

Confirm the kernel agrees before asking xprof anything:

```bash
ip -d link show xprof-a   # should show "xdp" with a prog id
ip -d link show xprof-b   # should show "xdpgeneric" with a prog id
bpftool prog list | grep xdp_pass
```

## 4. Run xprof against it

```bash
sudo xprof list
```

Expect one row for `xprof-a` (`native`) and one for `xprof-b` (`generic`),
both naming `xdp_pass` and a program id matching `bpftool prog list`.

```bash
sudo xprof info xprof-a
```

Expect a full report: id, type `XDP`, BTF id present, func/line info
counts matching what `-g` produced.

```bash
sudo xprof info xprof-b
```

Expect the native-only refusal (`NotNativeXdp`), naming `xprof-b` and
`generic`, exit code `1`.

## 5. Detach and clean up

```bash
sudo ip link set dev xprof-a xdp off
sudo ip link set dev xprof-b xdpgeneric off
sudo ip link delete xprof-a
```

Deleting one side of a veth pair removes both. Confirm with
`ip link show xprof-a` returning "does not exist".

## What this does and does not cover

Covers, by hand, on every PR that touches `discovery` or `metadata`:

- native vs. generic mode detection (`discovery::mode::detect`)
- `xprof list` against a host with programs actually attached
- `xprof info` against both a native (accepted) and a generic (rejected)
  attach
- the BTF-present and no-BTF `info` output paths

Does not cover, here or anywhere yet:

- offload mode (needs hardware that supports it — no software
  equivalent exists)
- permission-denied paths (`docs/testing.md` assumes you have the
  capabilities; dropping them to test the diagnosis in `perms.rs` is a
  separate, even more manual exercise — see `perms::diagnose`'s own unit
  tests for what is covered automatically instead)

A green CI run never implies any of this was exercised. CI runs the unit
and integration test suites only; this checklist is what stands in for
end-to-end coverage until Phase 0 earns automated veth-based tests of its
own (gated behind `#[ignore]` or an `XPROF_E2E=1` guard, not yet added).
