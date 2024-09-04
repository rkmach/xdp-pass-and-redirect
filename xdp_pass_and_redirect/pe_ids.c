#define _GNU_SOURCE  /* Needed by sched_getcpu */
#include <sched.h>

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>

#include <linux/socket.h>

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif


#include <bpf/btf.h> /* provided by libbpf */

#include <linux/perf_event.h>


#include "common_params.h"
#include "common_user_bpf_xdp.h"


#define NUM_FRAMES         4096 /* Frames per queue */
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE /* 4096 */
#define FRAME_SIZE_MASK    (FRAME_SIZE - 1)
#define RX_BATCH_SIZE      2048
#define FQ_REFILL_MAX      (RX_BATCH_SIZE * 2)
#define INVALID_UMEM_FRAME UINT64_MAX

#define DEFAULT_INTERVAL	1000000

static const struct option_wrapper long_options[] = {

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure number of queues to be used for AF_XDP"},
	
	{{"progsec",	 required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static bool global_exit;

int contador = 0;

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

struct perf_event_sample { 
		__u16 a;
		__u16 b;
		__u16 pkt_len;    /* total lenght of the packet */
		__u8 pkt_data[4];  /* pointer to the packet data */
};

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	struct perf_event_sample* s = data;

	uint8_t* pkt = s->pkt_data;
	int offset = 54;
	uint32_t len = s->pkt_len;

	char* begin;
    begin = (char*) (pkt + offset + 4);
    if(!begin || len <= offset){
		printf("ERROR: offset bigger than packet!\n");
		return;
	}

	char payload[2048];
	int j = 0;
	for (int i = offset+4; i < len+5; i++){
		payload[j] = pkt[i];
		j++;
	}

	printf("payload = %s\n\n", payload);
}

int main(int argc, char **argv)
{
	int map_fd;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.do_unload = false,
		.filename = "pe_af_xdp_kern.o",
		.progsec = "xdp",
		.xsk_wakeup_mode = true,
		.interval = DEFAULT_INTERVAL,
		.batch_pkts = BATCH_PKTS_DEFAULT,
		.tail_call_map_name = "tail_call_map",
	};
    struct bpf_object *bpf_obj = NULL;
	struct bpf_map *map;

    /* Global shutdown handler */
	signal(SIGINT, exit_application);

    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    bpf_obj = load_bpf_and_xdp_attach(&cfg);
    if (!bpf_obj) {
        /* Error handling done in load_bpf_and_xdp_attach() */
        exit(EXIT_FAILURE);
    }

    const char* pin_basedir = "/sys/fs/bpf";
    char pin_dir[1024];
    size_t len = snprintf(pin_dir, 1024, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	printf("\nmap dir: %s\n\n", pin_dir);
    strcpy(cfg.pin_dir, pin_dir);
    
    pin_maps_in_bpf_object(bpf_obj, &cfg, pin_basedir);

	int err;

	if (cfg.tail_call_map_entry_count > 0){
		err = set_tail_call_map(bpf_obj, &cfg);
		if (err) {
			fprintf(stderr, "ERR: setting tail call map\n");
			return err;
		}
	}

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(bpf_obj, "perf_event_map");
    map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: no perf event map found: %s\n",
            strerror(map_fd));
        exit(EXIT_FAILURE);
    }

	int ret;
    int perf_event_map_fd = open_bpf_map_file(pin_dir, "perf_event_map", NULL);
	/* Create perf_buffer to regular patterns map */
	struct perf_buffer *pb;
	pb = perf_buffer__new(perf_event_map_fd, 8, print_bpf_output, NULL, NULL, NULL);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}

	while ((ret = perf_buffer__poll(pb, 1000)) >= 0) {
	}


	map = bpf_object__find_map_by_name(bpf_obj, "counter_map");
	__u32 valor = 0;
	__u32 k = 0, *v = &valor;
	err = bpf_map__lookup_elem(map, &k, sizeof(__u32), v, sizeof(__u32), 0);
	if (err < 0){
		//printf("Não peguei número de pacotes. Desconsiderar número abaixo\n");
		fprintf(stderr, "ERROR: Cannot get number os processed packets \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	printf("pkts = %d\n", *v);
	printf("contador = %d\n", contador);
    return 0;
}
