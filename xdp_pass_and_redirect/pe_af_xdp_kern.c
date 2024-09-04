/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct perf_event_struct {
	__u16 a;
	__u16 b;
	__u16 pkt_len;    /* total lenght of the packet */
	__u8 pkt_data[4];  /* pointer to the packet data */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} perf_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} counter_map SEC(".maps");

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    __u32 k = 0, *v;
    v = bpf_map_lookup_elem(&counter_map, &k);
    if (v) {
        __sync_fetch_and_add(v, 1);
        bpf_map_update_elem(&counter_map, &k, v, BPF_ANY);
    }

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	if (data < data_end) {
		/* The XDP perf_event_output handler will use the upper 32 bits
		 * of the flags argument as a number of bytes to include of the
		 * packet payload in the event data. If the size is too big, the
		 * call to bpf_perf_event_output will fail and return -EFAULT.
		 *
		 * See bpf_xdp_event_output in net/core/filter.c.
		 *
		 * The BPF_F_CURRENT_CPU flag means that the event output fd
		 * will be indexed by the CPU number in the event map.
		 */
		__u64 flags = BPF_F_CURRENT_CPU;
		__u16 sample_size = (__u16)(data_end - data);
		int ret;
		struct perf_event_struct metadata;
		__builtin_memset(&metadata, 0, sizeof(metadata));

		metadata.a = 0xdead;
		metadata.b = sample_size;
		metadata.pkt_len = sample_size;

		flags |= (__u64)sample_size << 32;

		ret = bpf_perf_event_output(ctx, &perf_event_map, flags, &metadata, sizeof(metadata));
		if (ret)
			bpf_printk("perf_event_output failed: %d\n", ret);
		bpf_printk("Já enviei o evento e ainda tô aqui!!!: %d\n", ret);
	}

	return XDP_PASS;

	
}

char _license[] SEC("license") = "GPL";
