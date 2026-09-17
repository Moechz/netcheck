package collector

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

const source = "bpf"

type Counters struct {
	RxBytes   uint64  `json:"rx_bytes"`
	RxPackets uint64  `json:"rx_packets"`
	TxBytes   uint64  `json:"tx_bytes"`
	TxPackets uint64  `json:"tx_packets"`
	RxBps     float64 `json:"rx_bps"`
	TxBps     float64 `json:"tx_bps"`
}

type rawCounters struct {
	RxBytes   uint64
	RxPackets uint64
	TxBytes   uint64
	TxPackets uint64
}

type Snapshot struct {
	Source     string              `json:"source"`
	Available  bool                `json:"available"`
	Timestamp  string              `json:"ts"`
	Interfaces map[string]Counters `json:"interfaces"`
}

type sample struct {
	counters Counters
	taken    time.Time
}

type Collector struct {
	mapObj   *ebpf.Map
	interval time.Duration
	mu       sync.RWMutex
	current  map[uint32]sample
	last     map[uint32]Counters
	lastAt   time.Time
}

func New(mapObj *ebpf.Map, interval time.Duration) *Collector {
	if interval <= 0 {
		interval = time.Second
	}
	return &Collector{
		mapObj:   mapObj,
		interval: interval,
		current:  make(map[uint32]sample),
		last:     make(map[uint32]Counters),
	}
}

func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	c.Poll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Poll()
		}
	}
}

func (c *Collector) Poll() map[uint32]Counters {
	raw := make(map[uint32]Counters)
	if c.mapObj != nil {
		var key uint32
		var value rawCounters
		iter := c.mapObj.Iterate()
		for iter.Next(&key, &value) {
			raw[key] = Counters{
				RxBytes:   value.RxBytes,
				RxPackets: value.RxPackets,
				TxBytes:   value.TxBytes,
				TxPackets: value.TxPackets,
			}
		}
	}
	now := time.Now()

	c.mu.Lock()
	c.current = make(map[uint32]sample, len(raw))
	for key, counters := range raw {
		previous, hadPrevious := c.last[key]
		withRate := counters
		if hadPrevious && now.After(c.lastAt) {
			seconds := now.Sub(c.lastAt).Seconds()
			withRate.RxBps = rate(counters.RxBytes, previous.RxBytes, seconds)
			withRate.TxBps = rate(counters.TxBytes, previous.TxBytes, seconds)
		}
		c.current[key] = sample{counters: withRate, taken: now}
	}
	c.last = raw
	c.lastAt = now
	c.mu.Unlock()
	return raw
}

func (c *Collector) Snapshot() Snapshot {
	names := interfaceNames()
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]Counters, len(c.current))
	keys := make([]uint32, 0, len(c.current))
	for key := range c.current {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		name, ok := names[key]
		if !ok {
			name = fmt.Sprintf("ifindex-%d", key)
		}
		result[name] = c.current[key].counters
	}
	return Snapshot{
		Source:     source,
		Available:  true,
		Timestamp:  time.Now().Format(time.RFC3339Nano),
		Interfaces: result,
	}
}

func rate(current, previous uint64, seconds float64) float64 {
	if seconds <= 0 || current < previous {
		return 0
	}
	return float64(current-previous) * 8 / seconds
}

func interfaceNames() map[uint32]string {
	result := make(map[uint32]string)
	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, item := range interfaces {
		result[uint32(item.Index)] = item.Name
	}
	return result
}
