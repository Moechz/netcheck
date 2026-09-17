//go:build !linux

package main

import (
	"errors"
	"io"

	"github.com/cilium/ebpf"
)

func attachPacketFilters(_ *ebpf.Program) ([]io.Closer, error) {
	return nil, errors.New("BPF collector can only run on Linux")
}
