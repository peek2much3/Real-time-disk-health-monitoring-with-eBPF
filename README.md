# Real-time-disk-health-monitoring-with-eBPF
An eBPF program on the block_rq_issue and block_rq_complete tracepoints times every block I/O. Per device, it tracks:  I/O count error count average latency a log2 latency histogram, from which p99 is derived count of I/Os slower than 500ms
