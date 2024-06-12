#ifndef XSK_SOCKET_H
#define XSK_SOCKET_H

#include <errno.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include "common_defines.h"
#include <stdlib.h>
#include <unistd.h>

#define NUM_FRAMES         4096 /* Frames per queue */
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE /* 4096 */
#define FRAME_SIZE_MASK    (FRAME_SIZE - 1)
#define RX_BATCH_SIZE      2048
#define FQ_REFILL_MAX      (RX_BATCH_SIZE * 2)
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
	struct xsk_ring_prod fq;  // fill queue
	struct xsk_ring_cons cq;  // completion queue
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

    uint32_t queue_id;
};

struct xsk_umem_info* configure_umem(void* packet_buffer, size_t packet_buffer_size);
uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk_info);
struct xsk_socket_info* configure_socket(struct config *cfg, int i_queue, struct xsk_umem_info* umem);
void enter_xsks_into_map(int xsks_map, struct xsk_socket_info **sockets, size_t len_sockets);
int af_xdp_init(struct xsk_umem_info **umems, struct xsk_socket_info **xsk_sockets, int n_queues, struct config* cfg);
void xsk_free_umem_frame(struct xsk_socket_info* xsk_info, uint64_t frame);

#endif
