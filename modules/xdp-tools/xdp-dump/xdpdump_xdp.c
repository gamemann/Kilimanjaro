// SPDX-License-Identifier: GPL-2.0

/*****************************************************************************
 * Include files
 *****************************************************************************/
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_trace_helpers.h>
#include "xdpdump.h"

/*****************************************************************************
 * Macros
 *****************************************************************************/
#define min(x, y) ((x) < (y) ? x : y)


/*****************************************************************************
 * Local definitions and global variables
 *****************************************************************************/
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, int);
	__type(value, __u32);
} xdpdump_perf_map SEC(".maps");


/*****************************************************************************
 * .data section value storing the capture configuration
 *****************************************************************************/
struct trace_configuration trace_cfg SEC(".data");


/*****************************************************************************
 * XDP trace program
 *****************************************************************************/
SEC("xdpdump_xdp")
int xdpdump(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct pkt_trace_metadata metadata;

	if (data >= data_end ||
	    trace_cfg.capture_if_ifindex != xdp->ingress_ifindex)
		return XDP_PASS;

	metadata.prog_index = trace_cfg.capture_prog_index;
	metadata.ifindex = xdp->ingress_ifindex;
	metadata.rx_queue = xdp->rx_queue_index;
	metadata.pkt_len = (__u16)(data_end - data);
	metadata.cap_len = min(metadata.pkt_len, trace_cfg.capture_snaplen);
	metadata.action = 0;
	metadata.flags = 0;

	bpf_perf_event_output(xdp, &xdpdump_perf_map,
			      ((__u64) metadata.cap_len << 32) |
			      BPF_F_CURRENT_CPU,
			      &metadata, sizeof(metadata));

	return XDP_PASS;
}


/*****************************************************************************
 * License
 *****************************************************************************/
char _license[] SEC("license") = "GPL";
