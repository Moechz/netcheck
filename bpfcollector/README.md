# NetCheck Go/eBPF traffic collector

`netcheck-bpf` is a static Go service that loads an eBPF socket filter and
attaches it to one `AF_PACKET` socket per network interface. The BPF program
updates RX/TX byte and packet counters in a kernel hash map keyed by interface
index, then returns zero so Linux discards the packet copy without waking Go.

The Go process polls the map once per second, converts byte deltas to bits per
second, and exposes JSON at `/snapshot` over `/run/netcheck/bpf-traffic.sock`.
The Python main backend calls that endpoint for `/api/realtime` and falls back
to `/proc/net/dev` when BPF is unavailable.

## Build

```bash
cd netcheck
tools/build_bpf_collector.sh x86_64   # or aarch64
```

Dependencies are vendored. The compiled BPF object is committed as
`_bpf/traffic.bpf.o`; regenerate it on Linux with clang/libbpf only after
changing `_bpf/traffic.bpf.c`.

Header files under `_headers/` originate from the cilium/ebpf examples and are
covered by `LICENSE.BSD-2-Clause`.

## Public source mirror (review V6)

The source of the shipped `bin/netcheck-bpf` ELF is published for audit at
https://github.com/Moechz/netcheck under `bpfcollector/` (and as the release
asset `netcheck_<version>_bpf-src.tar.gz`, pinned to each version).

The mirror excludes `vendor/` (size only): run `go mod vendor` — module
versions are pinned by the committed `go.sum` — then
`CGO_ENABLED=0 go build` for the architecture you target, or use the project
`tools/build_bpf_collector.sh`. `_bpf/traffic.bpf.o` is committed so the Go
build needs no clang; regenerate it on Linux with clang/libbpf only after
editing `_bpf/traffic.bpf.c`.
