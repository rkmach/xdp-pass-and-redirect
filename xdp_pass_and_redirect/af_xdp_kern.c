/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "af_xdp_kern_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_AF_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct perf_event_struct {
	__u16 a;
	__u16 b;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} my_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__type(key, __u32);
// 	__type(value, __u32);
// 	__uint(max_entries, 64);
// } counter_map SEC(".maps");

 //struct {
 //    __uint(type, BPF_MAP_TYPE_ARRAY);
 //    __uint(max_entries, 1);
 //    __type(key, __u32);
 //    __type(value, __u32);
 //} counter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 	__type(key, __u32);
    __type(value, __u64);
 	__uint(max_entries, 1);
  //	__uint(pinning, LIBBPF_PIN_BY_NAME);
} counter_map SEC(".maps");

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    __u32 k = 0;
	__u64* rec = bpf_map_lookup_elem(&counter_map, &k);
    //v = bpf_map_lookup_elem(&counter_map, &k);
    if (rec) {
        //__sync_fetch_and_add(v, 1);
        //bpf_map_update_elem(&counter_map, &k, v, BPF_ANY);
		*rec = *rec + 1;
        //bpf_map_update_elem(&counter_map, &k, rec, BPF_ANY);
        //bpf_printk("cont = %d\n", rec->rx_packets);
    }

    int index = ctx->rx_queue_index;

    if (bpf_map_lookup_elem(&xsks_map, &index)){
		return bpf_redirect_map(&xsks_map, index, 0);
        //return 0xdeadbeef;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
