// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// diskhealth: passive, read-only block-layer health probe.
//
// Safety properties:
//  - Attaches only to two stable block tracepoints (no kprobes, no raw memory reads).
//  - Never writes to kernel or user memory outside its own maps.
//  - All maps are fixed-size; the in-flight map is an LRU so it cannot fill up or leak.
//  - Ring buffer is best-effort: if full, events are dropped, never blocked.
//  - All loops are statically bounded (verifier-checked).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_INFLIGHT 32768
#define MAX_DEVS     256
#define HIST_SLOTS   24                 /* log2(microseconds), slot 23 ~ >8s */
#define SLOW_NS      500000000ULL       /* I/O slower than 500ms emits an event */

#define EV_ERROR 1
#define EV_SLOW  2

struct req_key {
	u32 dev;
	u32 pad;                        /* explicit padding, always zeroed */
	u64 sector;
};

struct dev_stats {
	u64 ios;
	u64 errors;
	u64 total_ns;
	u64 slow;
	u64 hist[HIST_SLOTS];
};

struct event {
	u64 ts;
	u64 lat_ns;
	u64 sector;
	u32 dev;
	s32 error;
	u32 nr_sector;
	u32 kind;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_INFLIGHT);
	__type(key, struct req_key);
	__type(value, u64);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_DEVS);
	__type(key, u32);
	__type(value, struct dev_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/block/block_rq_issue")
int handle_issue(struct trace_event_raw_block_rq *ctx)
{
	struct req_key k = {};
	u64 ts = bpf_ktime_get_ns();

	k.dev = ctx->dev;
	k.sector = ctx->sector;
	bpf_map_update_elem(&inflight, &k, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int handle_complete(struct trace_event_raw_block_rq_completion *ctx)
{
	struct req_key k = {};
	u32 dev = ctx->dev;
	s32 err = ctx->error;

	k.dev = dev;
	k.sector = ctx->sector;

	u64 *tsp = bpf_map_lookup_elem(&inflight, &k);
	if (!tsp)
		return 0;

	u64 lat = bpf_ktime_get_ns() - *tsp;
	bpf_map_delete_elem(&inflight, &k);

	struct dev_stats *s = bpf_map_lookup_elem(&stats, &dev);
	if (!s) {
		struct dev_stats zero = {};
		bpf_map_update_elem(&stats, &dev, &zero, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&stats, &dev);
		if (!s)
			return 0;       /* map full: drop silently */
	}

	/* per-CPU entry: no atomics needed */
	s->ios++;
	s->total_ns += lat;
	if (err)
		s->errors++;
	if (lat >= SLOW_NS)
		s->slow++;

	u64 us = lat / 1000;
	u32 slot = 0;
#pragma unroll
	for (int i = 0; i < HIST_SLOTS - 1; i++) {
		if (us > 1) {
			us >>= 1;
			slot++;
		}
	}
	s->hist[slot]++;

	if (err || lat >= SLOW_NS) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->ts = bpf_ktime_get_ns();
			e->lat_ns = lat;
			e->sector = ctx->sector;
			e->dev = dev;
			e->error = err;
			e->nr_sector = ctx->nr_sector;
			e->kind = err ? EV_ERROR : EV_SLOW;
			bpf_ringbuf_submit(e, 0);
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
