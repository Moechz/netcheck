//go:build linux

package main

import (
	"fmt"
	"io"
	"net"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type packetFilterSocket struct {
	fd int
}

func (socket packetFilterSocket) Close() error {
	return unix.Close(socket.fd)
}

func attachPacketFilters(program *ebpf.Program) ([]io.Closer, error) {
	if program == nil {
		return nil, fmt.Errorf("count_packet program is missing")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var result []io.Closer
	for _, iface := range interfaces {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			closeAll(result)
			return nil, fmt.Errorf("open AF_PACKET for %s: %w", iface.Name, err)
		}
		address := &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  iface.Index,
		}
		if err := unix.Bind(fd, address); err != nil {
			_ = unix.Close(fd)
			closeAll(result)
			return nil, fmt.Errorf("bind AF_PACKET to %s: %w", iface.Name, err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, program.FD()); err != nil {
			_ = unix.Close(fd)
			closeAll(result)
			return nil, fmt.Errorf("attach BPF socket filter to %s: %w", iface.Name, err)
		}
		// The filter returns 0 and discards each packet after updating the map.
		// Keep descriptors non-blocking; Go never reads packet payloads.
		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fd)
			closeAll(result)
			return nil, fmt.Errorf("make AF_PACKET for %s non-blocking: %w", iface.Name, err)
		}
		result = append(result, packetFilterSocket{fd: fd})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no network interfaces")
	}
	return result, nil
}

func htons(value uint16) uint16 {
	return value>>8 | value<<8
}

func closeAll(items []io.Closer) {
	for _, item := range items {
		_ = item.Close()
	}
}
