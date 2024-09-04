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

#include "common_params.h"
#include "common_user_bpf_xdp.h"
// #include "common_libbpf.h"
#include "af_xdp_kern_shared.h"
#include "xsk_socket.h"


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

void process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len){
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
	char* begin, *end;

    	begin = (char*) (pkt + 54);
	end = (char*) (pkt + len);

	char payload[2048];
	int i;

	//for(i = 0; i < len; i++){
	//	printf("%x\n", pkt[i]);
	//}
	//printf("\n");

	i = 0;
	while(begin != end){
		payload[i] = *begin;
		i++;
		begin++;
	}
	payload[i] = '\0';
	//printf("payload do pacote = %s\n", payload);
}

void handle_receive_packets(struct xsk_socket_info* xsk_info){
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;
    int ret;
    unsigned int frames_received, stock_frames;

    // recvfrom(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);

    // ver se no RX tem alguma coisa
    frames_received = xsk_ring_cons__peek(&xsk_info->rx, 4096, &idx_rx);  // prenche a var idx_rx
	contador += frames_received;

	// contador += frames_received;
    // se não recebeu nada, volta pro loop de pool
    if(!frames_received)
        return;
    
    // se chegou aqui, recebi pelo menos um pacote nesse socket

    // stock frames é o número de frames recebidos!
    stock_frames = xsk_prod_nb_free(&xsk_info->umem->fq, xsk_info->umem_frame_free);
	// contador += stock_frames;

    if(stock_frames > 0){
        // reserva stock_frames slots no ring fill da UMEM
        ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, stock_frames, &idx_fq);

        /* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, frames_received, &idx_fq);

        for(int i = 0; i < stock_frames; i++){
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) = xsk_alloc_umem_frame(xsk_info);
        }
        xsk_ring_prod__submit(&xsk_info->umem->fq, stock_frames);
    }

    // só agora que vou tratar os pacotes recebidos (!!!!!!!!!)

    uint64_t addr;
    uint32_t len;

    for(int i = 0; i < frames_received; i++){
        // lê o descritor armazenado em idx_rx
        addr = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->addr;
        len = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->len;
        idx_rx++;

        // função que termina de verificar om pacote (AAAAAAAAAAAAAAAAAAAAAA)
        // process_packet(xsk_info, addr, len);
        //printf("pacote len = %d\n", len);
        //process_packet(xsk_info, addr, len);

        // adiciona o endereço à lista de endereços disponíveis do fill ring da UMEM
        xsk_free_umem_frame(xsk_info, addr);
    }

    // libera os frames recebidos do RX (indica pro kernel que eu já li essas posições)
    xsk_ring_cons__release(&xsk_info->rx, frames_received);


    // complete_tx(xsk_info);
}

void rx_and_process(struct config* config, struct xsk_socket_info** xsk_sockets, int n_queues){
    struct pollfd fds[n_queues];  // essa estrutura é entendida pela syscall poll(), que é usada para verificar se há novos eventos no socket
    memset(fds, 0, sizeof(fds));
    int i_queue;

    for(i_queue = 0; i_queue < n_queues; i_queue++){
        fds[i_queue].fd = xsk_socket__fd(xsk_sockets[i_queue]->xsk);
        fds[i_queue].events = POLLIN;  // POLLIN = "there is data to read"
    }

    int ret;
    // fica nesse loop por toda a execução da IDS
    while(!global_exit){
        //printf("loop\n");

        // ret é o número de socket com algum evento (infelizmente não retorna quais os sockets :( 
        ret = poll(fds, n_queues, -1);  // timeout = -1. Sinifica que vai ficar bloqueado até que um evento ocorra.

        if(ret <= 0){
            continue;  // nenhum evento em nenhum socket
        }
        for(i_queue = 0; i_queue < n_queues; i_queue++){
            if(fds[i_queue].revents & POLLIN){
                //printf("recebi na fila %d\n", i_queue);
                handle_receive_packets(xsk_sockets[i_queue]);
            }
        }
    }
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	int xsks_map_fd;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.do_unload = false,
		.filename = "af_xdp_kern.o",
		.progsec = "xdp",
		.xsk_wakeup_mode = true,
		.interval = DEFAULT_INTERVAL,
		.batch_pkts = BATCH_PKTS_DEFAULT,
		.tail_call_map_name = "tail_call_map",
	};
	struct xsk_umem_info **umems;
	struct xsk_socket_info **xsk_sockets;

    cfg.xsk_bind_flags = XDP_COPY;

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
    map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    // xsks_map_fd = open_bpf_map_file(pin_dir, "xsks_map", NULL);
    xsks_map_fd = bpf_map__fd(map);
    if (xsks_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsks_map_fd));
        exit(EXIT_FAILURE);
    }

    /* Configure and initialize AF_XDP sockets  (vetor de ponteiros!!) */
    int n_queues = cfg.xsk_if_queue;
	printf("Número de filas: %d\n\n", n_queues);

	umems = (struct xsk_umem_info **)
			malloc(sizeof(struct xsk_umem_info *) * n_queues);
	xsk_sockets = (struct xsk_socket_info **)
				  malloc(sizeof(struct xsk_socket_info *) * n_queues);
    if(!umems || !xsk_sockets){
        printf("Não consegui alocar o vetor de UMEMS ou o vetor de sockets!\n");
    }

    // this function configures UMEMs and XSKs
    if(!af_xdp_init(umems, xsk_sockets, n_queues, &cfg)){
        printf("Tudo certo!!\n");
    }
    //for (int i_queue = 0; i_queue < n_queues; i_queue++) {
    //    printf("%llx\n", umems[i_queue]->buffer);
    //}

    /* fill xsks map */
    enter_xsks_into_map(xsks_map_fd, xsk_sockets, n_queues);

	/* -- XSKS sockets properly configurated. Go wait for packets --*/

    rx_and_process(&cfg, xsk_sockets, n_queues);

    /* Cleanup */
	for (int i_queue = 0; i_queue < n_queues; i_queue++) {
		xsk_socket__delete(xsk_sockets[i_queue]->xsk);
		xsk_umem__delete(umems[i_queue]->umem);
	}
    free(umems);
    free(xsk_sockets);
    //xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	/*
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
	*/

	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];
	__u64 sum_pkts = 0;
	int i;
	__u32 key = 0;
	//map = bpf_object__find_map_by_name(bpf_obj, "counter_map");
	int fd = open_bpf_map_file(pin_dir, "counter_map", NULL);

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return -1;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		printf("values[%d] = %d\n", i, values[i]);
		sum_pkts += values[i];
	}
	printf("\npackets = %lld\n\n", sum_pkts);
	printf("\ncontador = %d\n", contador);
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
    return 0;
}
