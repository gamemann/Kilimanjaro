#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <linux/types.h>
#include <poll.h>
#include <sys/sysinfo.h>

#include <net/if.h>

#include <sys/socket.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <pthread.h>

#include "config.h"
#include "utils.h"
#include "xdp_prog.h"

#include "define_libxdp.h"

#include "csum.h"

#include <xdp/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX
//#define DEBUG
//#define SEC_A2S_DEBUG

struct xsk_umem_info 
{
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket 
{
    struct xsk_ring_cons *rx;
    struct xsk_ring_prod *tx;
    __u64 outstanding_tx;
    struct xsk_ctx *ctx;
    struct xsk_socket_config config;
    int fd;
};

struct xsk_socket_info
{
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    __u64 umem_frame_addr[NUM_FRAMES];
    __u32 umem_frame_free;

    __u32 outstanding_tx;
};

typedef struct thread_info
{
    config_t *cfg;
    xdp_maps_t *xdp_maps;
    int thread_id;
    struct xsk_socket_info *xsk;
} thread_info_t;

int af_xdp_send_packet(struct xsk_socket_info *xsk, void *pckt, u16 length, int new, u64 addr);
u64 af_xdp_get_umem_addr(struct xsk_socket_info *xsk, int idx);
void *af_xdp_get_umem_loc(struct xsk_socket_info *xsk, u64 addr);
void af_xdp_setup_variables(config_t *cfg);
int af_xdp_setup_umem(int index);
void af_xdp_setup_sockets(config_t *cfg, xdp_maps_t *xdp_maps);
int af_xdp_setup_socket(config_t *cfg, xdp_maps_t *xdp_maps, int index);
void af_xdp_cleanup_socket(struct xsk_socket_info *xsk);