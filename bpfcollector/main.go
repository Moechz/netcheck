package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"github.com/Moechz/netcheck/bpfcollector/internal/collector"
)

//go:embed _bpf/traffic.bpf.o
var bpfObjects embed.FS

const defaultSocket = "/run/netcheck/bpf-traffic.sock"

func loadTrafficCollector() (*ebpf.Collection, []io.Closer, error) {
	object, err := bpfObjects.ReadFile("_bpf/traffic.bpf.o")
	if err != nil {
		return nil, nil, fmt.Errorf("read embedded BPF object: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, nil, fmt.Errorf("parse BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("load BPF collection: %w", err)
	}

	socketFilters, err := attachPacketFilters(coll.Programs["count_packet"])
	if err != nil {
		coll.Close()
		return nil, nil, fmt.Errorf("attach socket filter: %w", err)
	}
	return coll, socketFilters, nil
}

func listenUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("empty unix socket path")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on unix socket: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		listener.Close()
		return nil, fmt.Errorf("set socket permissions: %w", err)
	}
	return listener, nil
}

func main() {
	socketPath := flag.String("socket", defaultSocket, "Unix JSON socket path")
	interval := flag.Duration("interval", time.Second, "counter sampling interval")
	flag.Parse()

	coll, attachments, err := loadTrafficCollector()
	if err != nil {
		log.Fatalf("BPF: %v", err)
	}
	defer func() {
		for _, item := range attachments {
			item.Close()
		}
		coll.Close()
	}()

	traffic := collector.New(coll.Maps["traffic"], *interval)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go traffic.Run(ctx)

	listener, err := listenUnix(*socketPath)
	if err != nil {
		log.Fatalf("socket: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"source":   "bpf",
			"attached": len(attachments) > 0,
		})
	})
	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, traffic.Snapshot())
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("NetCheck BPF collector listening on %s", *socketPath)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
