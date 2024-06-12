#include "xsk_socket.h"

struct xsk_umem_info* configure_umem(void* packet_buffer, size_t packet_buffer_size){ //**
    struct xsk_umem_info* umem;
    umem = calloc(1, sizeof(*umem));
    if (!umem){
        printf("Problema no calloc para configurar UMEM\n");
        return NULL;
    }

    struct xsk_umem_config xsk_umem_cfg = {
		/* We recommend that you set the fill ring size >= HW RX ring size +
		 * AF_XDP RX ring size. Make sure you fill up the fill ring
		 * with buffers at regular intervals, and you will with this setting
		 * avoid allocation failures in the driver. These are usually quite
		 * expensive since drivers have not been written to assume that
		 * allocation failures are common. For regular sockets, kernel
		 * allocated memory is used that only runs out in OOM situations
		 * that should be rare.
		 */
//		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS, /* Fix later */
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = FRAME_SIZE,
		/* Notice XSK_UMEM__DEFAULT_FRAME_HEADROOM is zero */
		.frame_headroom = 256,
		//.frame_headroom = 0,
		.flags = 0
	};

    // UMEM está sendo criada com a configuração padrão (último parâmetro = NULL)
    int ret = xsk_umem__create(&umem->umem, packet_buffer, packet_buffer_size, &umem->fq, &umem->cq, &xsk_umem_cfg);
    if (ret){
        printf("problema para criar a UMEM usando libxdp\n");
        return NULL;
    }
    umem->buffer = packet_buffer;
    return umem;
}

uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk_info){ //**
    uint64_t frame;
    if(xsk_info->umem_frame_free == 0){
        printf("Não dá pra alocar mais frames!\n LIMITE MÀXIMO ATINGIDO");
        return INVALID_UMEM_FRAME;
    }
    frame = xsk_info->umem_frame_addr[xsk_info->umem_frame_free-1];
    xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = INVALID_UMEM_FRAME;
    xsk_info->umem_frame_free--;
    return frame;
}

struct xsk_socket_info* configure_socket(struct config *cfg, int i_queue, struct xsk_umem_info* umem){  //**
    struct xsk_socket_config xsk_config;
    struct xsk_socket_info* xsk_info;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if(!xsk_info){
        printf("Falha no calloc da xsk info\n");
        return NULL;
    }

    xsk_info->umem = umem;
    xsk_info->queue_id = i_queue;

    xsk_config.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;  // 2048
    xsk_config.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;  // 2048

    xsk_config.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

    xsk_config.xdp_flags = cfg->xdp_flags;
    xsk_config.bind_flags = cfg->xsk_bind_flags;

    int ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname, i_queue, umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_config);

    if (ret != 0){
        printf("Erro na chamada de socket_create, dentro de configure_socket\n");
        errno = -ret;
        return NULL;
    }
    uint32_t prog_id = 0;
    ret = bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id);  // tá PREENCHENDO a variável prog_id
    if (ret){
        printf("Erro ao query id");
    }

    // alocação de frames na UMEM !!!

    for(int i = 0; i < NUM_FRAMES; i++){
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;  // o endereço do frame i é i*4096
    }
    xsk_info->umem_frame_free = NUM_FRAMES;  // significa que os 4096 frames estão livres 

    uint32_t idx;
    // reserva os slots do fill ring
    // acho que isso significa passar o fill ring para o kernel, para que ele possa ver onde colocar os pacotes de RX
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);  // PREENCHE a var idx

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS){
        printf("Erro ao reservar os descritores que serão colocados os endereços no ring FILL\n");
        return NULL;
    }

    // agora sim eu vou colocar os endereços da UMEM no fill ring (!!!!!!!!!)
    for(int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++){
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx) = xsk_alloc_umem_frame(xsk_info);
        idx++;
    }
    
    // submetendo os slot do fill ring para os quais foram colocados endereços (todos, nesse caso)
    // significa que o kernel já pode ler e começar a preencher a UMEM com o que receber
    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    // apply_setsockopt(xsk_info, cfg->opt_busy_poll, RX_BATCH_SIZE);

    return xsk_info;
}

void enter_xsks_into_map(int xsks_map, struct xsk_socket_info **sockets, size_t len_sockets)
{//**
	int i;

	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < len_sockets; i++) {
		int fd = xsk_socket__fd(sockets[i]->xsk);
		int key, ret;

		key = i;
		/* When entering XSK socket into map redirect have effect */
		ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
			exit(EXIT_FAILURE);
		}
		if (debug)
			printf("%s() enable redir for xsks_map_fd:%d Key:%d fd:%d\n",
			       __func__, xsks_map, key, fd);

	}
}

int af_xdp_init(struct xsk_umem_info **umems, struct xsk_socket_info **xsk_sockets, int n_queues, struct config* cfg){
    void *packet_buffer = NULL;
	size_t packet_buffer_size;
    struct xsk_umem_info* umem;
    struct xsk_socket_info* xsk_socket;

    packet_buffer_size = 4096 * 4096;  // NUM_FRAMES * FRAME_SIZE; número de packet buffers * tamanho de cada packet buffer  

    for(int i_queue = 0; i_queue < n_queues; i_queue++){
        if(posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)){
            printf("Problema ao alocar memória do buffer da UMEM!");
        }
        
        umem = configure_umem(packet_buffer, packet_buffer_size);
        if (umem == NULL){
            printf("Não configurei UMEM corretamente!\n");
            return -1;
        }

        xsk_socket = configure_socket(cfg, i_queue, umem);
        if (xsk_socket == NULL) {
			fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
				strerror(errno));
			return EXIT_FAILURE;
		}

        umems[i_queue] = umem;
        xsk_sockets[i_queue] = xsk_socket;
    }

    return 0;
}

void xsk_free_umem_frame(struct xsk_socket_info* xsk_info, uint64_t frame){//**
    xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = frame;
    xsk_info->umem_frame_free++;
}
