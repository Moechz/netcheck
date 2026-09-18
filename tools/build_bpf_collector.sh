#!/bin/bash
# Build the Go/eBPF collector for a target Debian architecture.
set -euo pipefail

ARCH="${1:-x86_64}"
case "$ARCH" in
  x86_64) GOARCH=amd64 ;;
  aarch64) GOARCH=arm64 ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/bpfcollector"

if [ ! -s _bpf/traffic.bpf.o ]; then
    echo "BPF object is missing; compile traffic.bpf.c on a Linux host with clang/libbpf" >&2
    exit 1
fi

if command -v go >/dev/null 2>&1; then
    GO=go
elif [ -n "${NETCHECK_GO:-}" ] && [ -x "${NETCHECK_GO}" ]; then
    GO="${NETCHECK_GO}"
else
    echo "Go toolchain not found; set NETCHECK_GO=/path/to/go" >&2
    exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" "$GO" build \
    -trimpath -ldflags='-s -w -buildid=' \
    -o "$ROOT/bin/netcheck-bpf" .
file "$ROOT/bin/netcheck-bpf"
