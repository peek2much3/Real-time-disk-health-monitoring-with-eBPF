# Real-time-disk-health-monitoring-with-eBPF
What it does

An eBPF program on the block_rq_issue and block_rq_complete tracepoints times every block I/O. Per device, it tracks:

I/O count
error count
average latency
a log2 latency histogram, from which p99 is derived
count of I/Os slower than 500ms

A Go service reads that every 5 seconds and prints one JSON line per active device with a status of OK, WARN or CRIT. Individual failed or very slow I/Os are also logged right away, rate-limited, through a ring buffer.

Default thresholds (all flags):

Status	Condition
WARN	any I/O error in the window, or p99 ≥ 100ms
CRIT	≥ 5 errors in the window, or p99 ≥ 1s
Why it’s safe
Passive only: it uses just two tracepoints, with no kprobes, no raw memory reads and no writes outside its own maps.
Bounded memory: the in-flight map is an LRU, so it can’t fill up or leak, even when partial completions leave orphaned entries. The stats map is capped at 256 devices and the ring buffer at 256 KB. If the ring buffer fills, events are dropped rather than blocking.
Verifier-checked: loops are statically bounded, and the per-CPU stats avoid atomics and contention on the I/O path.
Least privilege: the systemd unit grants only CAP_BPF and CAP_PERFMON. It also sets NoNewPrivileges, a syscall filter, no network, and memory and CPU caps (128M, 10%).
Build and run

Requirements are Linux 5.8+ with BTF (/sys/kernel/btf/vmlinux), plus clang, bpftool and Go 1.21+.

bash
cd diskhealth
go mod init diskhealth && go get github.com/cilium/ebpf@latest && go mod tidy
make                      # generates vmlinux.h, compiles BPF, builds ./diskhealth
sudo ./diskhealth         # quick test
sudo make install && sudo systemctl enable --now diskhealth
journalctl -u diskhealth -f
Limitations
It sees I/O symptoms, not SMART data. It catches the failures that matter in practice (error bursts, latency spikes, timeouts), but it can’t see reallocated sectors, wear level or temperature. Run it alongside smartd or nvme smart-log for the full picture.
Thresholds need tuning. Spun-down HDDs and busy RAID rebuilds will trip the latency thresholds, so adjust the flags to your hardware.
SLOW_NS is compile-time. Edit the constant in the .bpf.c file to change the slow-I/O cutoff.
If the service can’t attach, check the kernel version and BTF first. Tracefs permissions are the next place to look.
