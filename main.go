package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target native diskhealth bpf/diskhealth.bpf.c -- -I./bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const histSlots = 24

// Must match struct dev_stats in the BPF program.
type devStats struct {
	Ios     uint64
	Errors  uint64
	TotalNs uint64
	Slow    uint64
	Hist    [histSlots]uint64
}

// Must match struct event in the BPF program.
type event struct {
	Ts       uint64
	LatNs    uint64
	Sector   uint64
	Dev      uint32
	Error    int32
	NrSector uint32
	Kind     uint32
}

type thresholds struct {
	warnLat    time.Duration
	critLat    time.Duration
	critErrors uint64
}

type report struct {
	Time   string  `json:"ts"`
	Device string  `json:"device"`
	Status string  `json:"status"`
	Reason string  `json:"reason,omitempty"`
	IOs    uint64  `json:"ios"`
	Errors uint64  `json:"errors"`
	Slow   uint64  `json:"slow_ios"`
	AvgMs  float64 `json:"avg_ms"`
	P99Ms  float64 `json:"p99_ms"`
}

var nameCache = map[uint32]string{}

// Kernel dev_t encoding: major = dev >> 20, minor = dev & 0xfffff.
func devName(dev uint32) string {
	if n, ok := nameCache[dev]; ok {
		return n
	}
	major, minor := dev>>20, dev&0xfffff
	name := fmt.Sprintf("%d:%d", major, minor)
	if t, err := os.Readlink(fmt.Sprintf("/sys/dev/block/%d:%d", major, minor)); err == nil {
		name = filepath.Base(t)
	}
	nameCache[dev] = name
	return name
}

func (a devStats) sub(b devStats) devStats {
	d := devStats{
		Ios:     a.Ios - b.Ios,
		Errors:  a.Errors - b.Errors,
		TotalNs: a.TotalNs - b.TotalNs,
		Slow:    a.Slow - b.Slow,
	}
	for i := range d.Hist {
		d.Hist[i] = a.Hist[i] - b.Hist[i]
	}
	return d
}

// snapshot sums the per-CPU values for every device.
func snapshot(m *ebpf.Map) (map[uint32]devStats, error) {
	out := map[uint32]devStats{}
	var k uint32
	var vals []devStats
	it := m.Iterate()
	for it.Next(&k, &vals) {
		var agg devStats
		for _, v := range vals {
			agg.Ios += v.Ios
			agg.Errors += v.Errors
			agg.TotalNs += v.TotalNs
			agg.Slow += v.Slow
			for i := range agg.Hist {
				agg.Hist[i] += v.Hist[i]
			}
		}
		out[k] = agg
	}
	return out, it.Err()
}

// p99 returns the upper bound (ms) of the histogram bucket holding the 99th percentile.
func p99ms(h [histSlots]uint64) float64 {
	var total uint64
	for _, c := range h {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := uint64(math.Ceil(float64(total) * 0.99))
	var seen uint64
	for i, c := range h {
		seen += c
		if seen >= target {
			return math.Pow(2, float64(i+1)) / 1000.0 // bucket i covers [2^i, 2^(i+1)) us
		}
	}
	return 0
}

func classify(d devStats, p99 float64, th thresholds) (string, string) {
	switch {
	case d.Errors >= th.critErrors:
		return "CRIT", fmt.Sprintf("%d I/O errors in window", d.Errors)
	case p99 >= float64(th.critLat.Milliseconds()):
		return "CRIT", fmt.Sprintf("p99 latency %.0fms", p99)
	case d.Errors > 0:
		return "WARN", fmt.Sprintf("%d I/O error(s) in window", d.Errors)
	case p99 >= float64(th.warnLat.Milliseconds()):
		return "WARN", fmt.Sprintf("p99 latency %.0fms", p99)
	}
	return "OK", ""
}

func main() {
	interval := flag.Duration("interval", 5*time.Second, "reporting window")
	warnLat := flag.Duration("warn-latency", 100*time.Millisecond, "p99 latency for WARN")
	critLat := flag.Duration("crit-latency", time.Second, "p99 latency for CRIT")
	critErrors := flag.Uint64("crit-errors", 5, "I/O errors per window for CRIT")
	maxEvents := flag.Int("max-events-per-sec", 20, "rate limit for per-I/O event log lines")
	flag.Parse()
	th := thresholds{*warnLat, *critLat, *critErrors}

	// Needed on kernels < 5.11; harmless otherwise.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	var objs diskhealthObjects
	if err := loadDiskhealthObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects (needs kernel BTF, CAP_BPF, CAP_PERFMON): %v", err)
	}
	defer objs.Close()

	l1, err := link.Tracepoint("block", "block_rq_issue", objs.HandleIssue, nil)
	if err != nil {
		log.Fatalf("attach issue: %v", err)
	}
	defer l1.Close()
	l2, err := link.Tracepoint("block", "block_rq_complete", objs.HandleComplete, nil)
	if err != nil {
		log.Fatalf("attach complete: %v", err)
	}
	defer l2.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enc := json.NewEncoder(os.Stdout)

	// Per-I/O error/slow events (rate limited, best-effort).
	go func() {
		windowStart, count := time.Now(), 0
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			if time.Since(windowStart) >= time.Second {
				windowStart, count = time.Now(), 0
			}
			if count++; count > *maxEvents {
				continue
			}
			var ev event
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
				continue
			}
			kind := "slow_io"
			if ev.Kind == 1 {
				kind = "io_error"
			}
			_ = enc.Encode(map[string]any{
				"ts":      time.Now().UTC().Format(time.RFC3339),
				"event":   kind,
				"device":  devName(ev.Dev),
				"sector":  ev.Sector,
				"sectors": ev.NrSector,
				"lat_ms":  float64(ev.LatNs) / 1e6,
				"errno":   ev.Error,
			})
		}
	}()

	prev, _ := snapshot(objs.Stats)
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	log.Printf("diskhealth running (window=%s)", *interval)

	for {
		select {
		case <-ctx.Done():
			log.Print("shutting down")
			return
		case <-tick.C:
			cur, err := snapshot(objs.Stats)
			if err != nil {
				log.Printf("snapshot: %v", err)
				continue
			}
			devs := make([]uint32, 0, len(cur))
			for d := range cur {
				devs = append(devs, d)
			}
			sort.Slice(devs, func(i, j int) bool { return devs[i] < devs[j] })

			for _, dev := range devs {
				d := cur[dev].sub(prev[dev])
				if d.Ios == 0 {
					continue
				}
				p99 := p99ms(d.Hist)
				status, reason := classify(d, p99, th)
				_ = enc.Encode(report{
					Time:   time.Now().UTC().Format(time.RFC3339),
					Device: devName(dev),
					Status: status,
					Reason: reason,
					IOs:    d.Ios,
					Errors: d.Errors,
					Slow:   d.Slow,
					AvgMs:  float64(d.TotalNs) / float64(d.Ios) / 1e6,
					P99Ms:  p99,
				})
			}
			prev = cur
		}
	}
}
