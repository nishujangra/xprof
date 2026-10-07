# xprof

**Native XDP profiler for Linux**

⚠️ **Experimental — nothing works yet.**

Samples where CPU time goes inside a native-mode XDP program — down to BPF
functions and instructions. Native XDP only, by design.

```bash
cargo build
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
