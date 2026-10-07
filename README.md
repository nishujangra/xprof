# xprof

**Native XDP profiler for Linux**

⚠️ **Experimental — Phase 0 (discovery) only. No sampling yet.**

Samples where CPU time goes inside a native-mode XDP program — down to BPF
functions and instructions. Native XDP only, by design.

```bash
cargo build
```

## Phase 0 — XDP discovery

Pure read-only introspection: what's attached, where, and what it is. No
perf events, no sampling, no BPF program of our own loaded.

- [x] `xprof list` lists every interface with an XDP program attached
- [x] each row shows: interface, mode (native/generic/offload), program
      name, program ID
- [ ] `xprof info eth0` prints prog id, name, type, load time, BTF id
      presence — load time is tracked internally (`ProgInfo.load_time`)
      but not yet surfaced in output
- [x] non-XDP program types are rejected with a clear error
- [x] generic-mode XDP is reported, not silently profiled
- [x] missing CAP_BPF / permissions produce an actionable error, not a
      panic
- [x] runs on a machine with zero XDP programs attached without erroring

### Usage

On a host with nothing attached:

```console
$ xprof list
No XDP programs attached.

$ xprof info lo
ERROR: no XDP program attached to lo
$ echo $?
1

$ xprof info doesnotexist
ERROR: interface not found: doesnotexist
$ echo $?
1
```

With a native XDP program attached (see
[docs/testing.md](docs/testing.md) for how to set one up with a `veth`
pair):

```console
$ xprof list
Interface   Mode      Program       ID
------------------------------------------------
eth0        native    xdp_cidr      142

$ xprof info eth0
Interface:    eth0
Mode:         native
Program:      xdp_cidr
ID:           142
Type:         XDP
BTF ID:       37
Func info:    4 records
Line info:    available
```

A generic-mode attach is listed but rejected by `info`:

```console
$ xprof info eth1
ERROR: xprof currently supports native XDP only.

Interface:
  eth1

Detected mode:
  generic

Native XDP is required.
$ echo $?
1
```

## Privileges

Reading BPF program metadata and netlink's interface list both need
elevated privileges. Run as root, or grant the two capabilities directly:

```bash
sudo xprof list
# or
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep target/release/xprof
```

`CAP_NET_ADMIN` is for the netlink interface dump, `CAP_BPF` and
`CAP_PERFMON` are for reading `bpf_prog_info`. Two sysctls can also block
access even with the right capabilities:

- `kernel.perf_event_paranoid` — above `1` restricts perf-event-adjacent
  BPF info to privileged users
- `kernel.unprivileged_bpf_disabled` — non-zero disables unprivileged BPF
  syscalls outright

xprof does not pre-flight check any of this. It attempts the operation and,
on `EPERM`/`EACCES`, reports which capability or sysctl is most likely the
cause.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success — including "nothing attached", which is a normal state, not an error |
| `1`  | User or environment error: no such interface, non-native XDP mode, missing permissions |
| `2`  | Internal error: xprof hit a bug or an unfinished code path |

A `1` is yours to fix (wrong interface name, wrong host, missing
capability); a `2` is ours — please file an issue.

GPL-2.0-or-later. See [LICENSE](LICENSE).
