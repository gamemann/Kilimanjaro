#include "af_xdp.h"

/* Global variables */
// The XDP flags to load the AF_XDP/XSK sockets with.
u32 xdp_flags = XDP_FLAGS_DRV_MODE;
u32 bind_flags = 0;
u16 batch_size = RX_BATCH_SIZE;
unsigned int static_queue_id;
unsigned int queue_id;

// For shared UMEM.
static unsigned int global_frame_idx = 0;

// Pointers to the umem and XSK sockets for each thread.
struct xsk_umem_info *umem[MAX_CPUS];
struct xsk_socket_info *xsk_socket[MAX_CPUS];

const char a2s_request[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00};

/**
 * Returns the maximum number of free frames.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * 
 * @return Number of maximum free frames.
**/
static u64 xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

/**
 * Allocates UMEM frame.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * 
 * @return Address to free UMEM frame it allocated.
**/
static u64 xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    u64 frame;

    if (xsk->umem_frame_free == 0)
    {
        return INVALID_UMEM_FRAME;
    }

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

/**
 * Frees a UMEM frame.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * @param frame The frame action to free.
 * 
 * @return Void
**/
static void xsk_free_umem_frame(struct xsk_socket_info *xsk, u64 frame)
{
    if (xsk->umem_frame_free >= NUM_FRAMES)
    {
        fprintf(stderr, "Number of free frames exceed max (%u).\n", xsk->umem_frame_free);

        return;
    }

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

/**
 * Completes the TX call via a syscall and also checks if we need to free the TX buffer.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * 
 * @return Void
**/
static void complete_tx(struct xsk_socket_info *xsk)
{
    // Initiate starting variables (completed amount and completion ring index).
    unsigned int completed;
    u32 idx_cq;

    // If outstanding is below 1, it means we have no packets to TX.
    if (!xsk->outstanding_tx)
    {
        return;
    }

    // If we need to wakeup, execute syscall to wake up socket.
    if (!(bind_flags & XDP_USE_NEED_WAKEUP) || xsk_ring_prod__needs_wakeup(&xsk->tx))
    {
        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    // Try to free a bunch of frames on the completion ring.
    completed = xsk_ring_cons__peek(&xsk->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

    if (completed > 0) 
    {
        // Free frames and comp.
        for (int i = 0; i < completed; i++)
        {
            xsk_free_umem_frame(xsk, *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));
        }  

        // Release "completed" frames.
        xsk_ring_cons__release(&xsk->umem->cq, completed);

        xsk->outstanding_tx -= completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
    }
}

/**
 * Each AF_XDP's socket thread handler.
 * 
 * @param data A pointer to thread_info structure.
 * 
 * @return Void
**/
void *socket_thread(void *data)
{
    thread_info_t *t_info = NULL;
    t_info = (thread_info_t *)data;

    struct xsk_socket_info *xsk = xsk_socket[t_info->thread_id];

    if (xsk == NULL)
    {
        fprintf(stderr, "XSK pointer NULL somehow?\n");

        pthread_exit(NULL);
    }

    struct sysinfo *info = calloc(1, sizeof(struct sysinfo));
    memset(info, 0, sizeof(struct sysinfo));

    struct pollfd fds[2];
    int ret, nfds = 1;

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk->xsk);
    fds[0].events = POLLIN;

#ifdef DEBUG
        fprintf(stdout, "[XSK] Starting to poll for FD %d (%d)...\n", t_info->xsk->xsk->fd, fds[0].fd);
#endif

    while (1)
    {
        ret = poll(fds, nfds, -1);

        if (ret != 1)
        {
            continue;
        }

        __u32 idx_rx = 0, idx_fq = 0;
        unsigned int rcvd = 0;

        rcvd = xsk_ring_cons__peek(&xsk->rx, batch_size, &idx_rx);

        if (!rcvd)
        {
            continue;
        }

        int stock_frames = 0;

        stock_frames = xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

        if (stock_frames > 0)
        {
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

            while (ret != stock_frames)
            {
                ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
            }

            for (int j = 0; j < stock_frames; j++)
            {
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = xsk_alloc_umem_frame(xsk);
            }

            xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
        }

        for (int j = 0; j < rcvd; j++)
        {
            __u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
            __u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

            void *pckt = xsk_umem__get_data(xsk->umem->buffer, addr);

            if (pckt == NULL)
            {
#ifdef DEBUG
                fprintf(stdout, "[XSK] Packet not true; freeing frame.\n");
#endif

                xsk_free_umem_frame(xsk, addr);

                continue;
            }

            // Create IP header (inner) pointer.
            struct iphdr *iph = pckt + sizeof(struct ethhdr);

            // Receive payload length.
            u16 pl_len = len - sizeof(struct ethhdr) - (iph->ihl * 4) - sizeof(struct udphdr) - 5;

            // Make sure we don't go past buffer.
            if (pl_len > MAX_A2S_SIZE)
            {
#ifdef DEBUG
                fprintf(stdout, "[A2S] A2S_INFO response exceeded buffer size (%d > %d).\n", pl_len, MAX_A2S_SIZE);
#endif

                xsk_free_umem_frame(xsk, addr);

                continue;
            }

            u8 request = 0;

            // Create UDP header.
            struct udphdr *udph = pckt + sizeof(struct ethhdr) + (iph->ihl * 4);

            // We need to check the A2S_INFO headers.
            unsigned char *hdr_data = pckt + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr);
            
            // Request (we must send A2S_INFO request if expired).
            if (*(hdr_data + 4) == 0x55)
            {
                request = 1;

                // 0x55 actually represents a request for expired, but now we want to send a response.
                *(hdr_data + 4) = 0x49;
                udph->check = 0;
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(udph->len), IPPROTO_UDP, csum_partial(udph, ntohs(udph->len), 0));

#ifdef DEBUG

                fprintf(stdout, "[A2S CL] Found A2S_INFO client request.\n");
#endif
            }

            u16 cache_time = DEFAULT_A2S_CACHE_TIME;
            u16 cache_timeout = DEFAULT_A2S_CACHE_TIMEOUT;
            u32 filters = 0;

            struct connection_key ckey = {0};
            ckey.protocol = IPPROTO_UDP;
            ckey.bind.ip = iph->saddr;
            ckey.bind.port = udph->source;

            struct connection_val cval[MAX_CPUS];

            if (bpf_map_lookup_elem(t_info->xdp_maps->connections, &ckey, cval) == 0)
            {
                cache_time = cval[0].cache_settings.A2S_INFO_time;
                cache_timeout = cval[0].cache_settings.A2S_INFO_cache_timeout;
                filters = cval[0].filters;
#ifdef DEBUG
                fprintf(stdout, "[A2S] Using cache time => %u. Cache timeout => %u. Filters => %u\n", cache_time, cache_timeout, filters);
#endif
            }

            // Get edge IP.
            be32 edge_ip_pcpu[MAX_CPUS];
            be32 edge_ip = 0;
            u32 edge_key = 0;

            if (bpf_map_lookup_elem(t_info->xdp_maps->edge_ip, &edge_key, edge_ip_pcpu) != 0)
            {
#ifdef DEBUG
                fprintf(stderr, "[A2S] Edge IP map lookup failure.\n");
#endif

                goto send_pckt;
            }

            edge_ip = edge_ip_pcpu[0];

            // Create key.
            struct flow key = {0};
            key.ip = iph->saddr;
            key.port = udph->source;

            sysinfo(info);

            u64 now = 0;

            now = info->uptime * (u64)1000000000;

            if (request)
            {
                // Get current cache.
                struct a2s_info_val val = {0};

                if (bpf_map_lookup_elem(t_info->xdp_maps->a2s_info, &key, &val) != 0)
                {
#ifdef DEBUG
                    fprintf(stderr, "[A2S CL] Client => A2S_INFO map lookup failure.\n");
#endif

                    goto send_pckt;
                }

                // Check if we've expired for too long (should indicate the server is offline).
                u64 timed_out = val.expires + (cache_timeout * (u64)1000000000);

                if (timed_out < now)
                {
#ifdef DEBUG
                    fprintf(stderr, "[A2S CL] Client => Found cache timeout for %u:%d. %llu < %llu.\n", ntohl(ckey.bind.ip), ntohs(ckey.bind.port), timed_out, now);
#endif
                    // Delete the cache since it hasn't been updated it too long.
                    bpf_map_delete_elem(t_info->xdp_maps->a2s_info, &key);

                    goto send_pckt;
                }

                if (edge_ip == 0)
                {
#ifdef DEBUG
                    fprintf(stderr, "[A2S CL] Client => Edge IP failure.\n");
#endif
                    goto send_pckt;
                }

                // Start packet buffer.
                unsigned char new_pckt_buff[2048];
                memset(new_pckt_buff, 0, sizeof(new_pckt_buff));

                // Length.
                u16 olen = sizeof(struct iphdr) + (iph->ihl * 4) + sizeof(struct udphdr) + sizeof(a2s_request);
                u16 ilen = olen - sizeof(struct iphdr);
                u16 ulen = ilen - (iph->ihl * 4);

                // Create ethernet header and copy.
                struct ethhdr *new_eth = (struct ethhdr *)new_pckt_buff;
                memcpy(new_eth, pckt, sizeof(struct ethhdr));
                
                // Create outer IP header and fill.
                struct iphdr *oiph = (struct iphdr *)(new_pckt_buff + sizeof(struct ethhdr));

                oiph->ihl = 5;
                oiph->version = 4;
                oiph->protocol = IPPROTO_IPIP;
                oiph->id = 0;
                oiph->tos = 0x00;
                oiph->ttl = 64;
                oiph->tot_len = htons(olen);

                oiph->saddr = edge_ip;
                oiph->daddr = cval[0].dest_ip;

                // Fill in inner header.
                struct iphdr *iiph = (struct iphdr *)(new_pckt_buff + sizeof(struct ethhdr) + sizeof(struct iphdr));
                memcpy(iiph, iph, (iph->ihl * 4));

                // Change to edge inner IP.
                be32 dest = iiph->saddr;
                iiph->saddr = edge_ip;
                iiph->daddr = dest;

                // Set inner IP header length.
                iiph->tot_len = htons(ilen);

                // Initiailize and copy UDP header.
                struct udphdr *new_udph = (struct udphdr *)(new_pckt_buff + sizeof(struct ethhdr) + sizeof(struct iphdr) + (iiph->ihl * 4));
                memcpy(new_udph, udph, sizeof(struct udphdr));

                new_udph->source = new_udph->dest;
                new_udph->dest = cval[0].dest_port;

                // Recalculate length.
                new_udph->len = htons(ulen);

                // Initialize and copy payload.
                unsigned char *pl = (unsigned char *)(new_pckt_buff + sizeof(struct ethhdr) + sizeof(struct iphdr) + (iiph->ihl * 4) + sizeof(struct udphdr));
                memcpy(pl, a2s_request, sizeof(a2s_request));

                // Recalculate UDP checksum.
                new_udph->check = 0;
                new_udph->check = csum_tcpudp_magic(iiph->saddr, iiph->daddr, ulen, IPPROTO_UDP, csum_partial((void *)new_udph, ulen, 0));

                // Recalculate outer IP header checksum.
                update_iph_checksum(oiph);

                // Recalculate inner IP header checksum.
                update_iph_checksum(iiph);

                u8 sec = 0;

                // If we have a challenge filter, we must send another a2s_info request with said challenge.
                if (val.challenge_set)
                {
                    sec = 1;
                }
#ifdef DEBUG
                    fprintf(stdout, "[A2S CL] Client => Sending new packet out with %u outer IP header length, %u inner IP header length, %u UDP header lenght, and %lu for total packet length.\n", olen, ilen, ulen, olen + sizeof(struct ethhdr));
                    fprintf(stdout, "[A2S CL] %u => %u :: %u:%d => %u:%d. Src MAC => %x:%x:%x. Dst MAC => %x:%x:%x.\n", ntohl(oiph->saddr), ntohl(oiph->daddr), ntohl(iiph->saddr), ntohs(new_udph->source), ntohl(iiph->daddr), ntohs(new_udph->dest), new_eth->h_source[0], new_eth->h_source[1], new_eth->h_source[2], new_eth->h_dest[0], new_eth->h_dest[1], new_eth->h_dest[2]);
#endif
                // Send packet (copy data to UMEM).
                af_xdp_send_packet(xsk, (void *)new_pckt_buff, olen + sizeof(struct ethhdr), 1, 0);

#ifdef SEC_A2S_DEBUG
                fprintf(stderr, "[S2R][%d][%d] First request sent %u:%d => %u:%d\n", xsk->outstanding_tx, xsk->umem_frame_free, iiph->saddr, ntohs(new_udph->source), iiph->daddr, ntohs(new_udph->dest));
#endif
                if (sec)
                {
                    char second_packet[2048];
                    memcpy(second_packet, new_pckt_buff, olen + sizeof(struct ethhdr));

                    // We just want to add four random bytes at the end of the packet it seems.
                    struct ethhdr *sec_eth = (struct ethhdr *)(second_packet);
                    struct iphdr *sec_oiph = (struct iphdr *)(second_packet + sizeof(struct ethhdr));
                    struct iphdr *sec_iiph = (struct iphdr *)(second_packet + sizeof(struct ethhdr) + (sec_oiph->ihl * 4));
                    struct udphdr *sec_udph = (struct udphdr *)(second_packet + sizeof(struct ethhdr) + (sec_oiph->ihl * 4) + (sec_iiph->ihl * 4));
                    unsigned char *sec_pl = (unsigned char *)(second_packet + sizeof(struct ethhdr) + (sec_oiph->ihl * 4) + (sec_iiph->ihl * 4) + sizeof(struct udphdr));

                    // Set lengths (increase by four bytes).
                    olen += 4;
                    ilen += 4;
                    ulen += 4;

                    // Fill in challenge.
                    memcpy(sec_pl + (sizeof(a2s_request)), &val.challenge, 4);

                    // Set header lengths.
                    sec_oiph->tot_len = htons(olen);
                    sec_iiph->tot_len = htons(ilen);
                    sec_udph->len = htons(ulen);

                    // Recalculate checksums.
                    sec_udph->check = 0;
                    sec_udph->check = csum_tcpudp_magic(sec_iiph->saddr, sec_iiph->daddr, ulen, IPPROTO_UDP, csum_partial((void *)sec_udph, ulen, 0));

                    update_iph_checksum(sec_iiph);
                    update_iph_checksum(sec_oiph);

#ifdef DEBUG
                    fprintf(stdout, "[A2S CL] Client => Sending SECOND new packet (with challenge %x %x %x %x) out with %u outer IP header length, %u inner IP header length, %u UDP header lenght, and %lu for total packet length.\n", val.challenge[0], val.challenge[1], val.challenge[2], val.challenge[3], olen, ilen, ulen, olen + sizeof(struct ethhdr));
                    fprintf(stdout, "[A2S CL] %u => %u :: %u:%d => %u:%d. Src MAC => %x:%x:%x. Dst MAC => %x:%x:%x.\n", ntohl(sec_oiph->saddr), ntohl(sec_oiph->daddr), ntohl(sec_iiph->saddr), ntohs(sec_udph->source), ntohl(sec_iiph->daddr), ntohs(sec_udph->dest), sec_eth->h_source[0], sec_eth->h_source[1], sec_eth->h_source[2], sec_eth->h_dest[0], sec_eth->h_dest[1], sec_eth->h_dest[2]);
#endif

#ifdef SEC_A2S_DEBUG
                    fprintf(stderr, "[S2R][%d][%d] Second request sent %u:%d => %u:%d with challenge %x:%x:%x:%x.\n", xsk->outstanding_tx, xsk->umem_frame_free, sec_iiph->saddr, ntohs(sec_udph->source), sec_iiph->daddr, ntohs(sec_udph->dest), val.challenge[0], val.challenge[1], val.challenge[2], val.challenge[3]);
#endif
                    // Send the second packet.
                    af_xdp_send_packet(xsk, (void *)second_packet, olen + sizeof(struct ethhdr), 1, 0);
                }
            }
            // Response (we must store cache).
            else
            {
                // Create buffer (A2S_INFO value).
                struct a2s_info_val val = {0};
                val.size = pl_len;
                val.expires = now + (cache_time * (u64)1000000000);

#ifdef DEBUG
                fprintf(stdout, "[A2S SV] Sending A2S_INFO response from %u to %u. Expires => %llu.\n", iph->saddr, iph->daddr, val.expires);
                fprintf(stdout, "[A2S SV] Response length (+5) => %d\n", pl_len);
#endif
      
                // Prepare and copy data.
                unsigned char *pl_data = pckt + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr) + 5;

                memcpy(val.data, pl_data, pl_len);

                // Update A2S_INFO map.
                if (bpf_map_update_elem(t_info->xdp_maps->a2s_info, &key, &val, BPF_ANY) != 0)
                {
#ifdef DEBUG
                    fprintf(stdout, "[A2S SV] Failed to update A2S_INFO map (%d)!\n", t_info->xdp_maps->a2s_info);
#endif
                }

#ifdef DEBUG
                // If edge IP equals the IP we're sending back to, log it!
                if (edge_ip == iph->daddr)
                {
                    fprintf(stdout, "[A2S SV/CL] Found A2S_INFO response for edge IP!\n");
                }
#endif

                if (cval[0].cache_settings.A2S_INFO_global_cache)
                {
                    struct in_addr in_addr;
                    in_addr.s_addr = ckey.bind.ip;
                    char *ip = strdup(inet_ntoa(in_addr));

                    if (ip != NULL)
                    {
                        config_parse_and_send_a2s_response(t_info->cfg, ip, ntohs(ckey.bind.port), (const char *)val.data, val.expires);
                    }
                }
            }

            send_pckt:
#ifdef DEBUG
            fprintf(stdout, "[A2S] Sending original packet packet with length of %u.\n", len);
            fprintf(stdout, "%u:%d => %u:%d.\n", ntohl(iph->saddr), ntohs(udph->source), ntohl(iph->daddr), ntohs(udph->dest));
#endif

            // Send packet (response) back out TX.
            if (af_xdp_send_packet(xsk, pckt, len, 0, addr))
            {
#ifdef DEBUG
                fprintf(stderr, "[XSK] Error sending original packet. Dropping.\n");
#endif

                xsk_free_umem_frame(xsk, addr);

                continue;
            }
        }

        xsk_ring_cons__release(&xsk->rx, rcvd);

        complete_tx(xsk);
    }

#ifdef DEBUG
        fprintf(stdout, "[XSK] Exiting poll...\n");
#endif

    // Cleanup XSK and UMEM.
    af_xdp_cleanup_socket(xsk);

    // Free thread info.
    free(t_info);
    free(info);

    // Exit the thread.
    pthread_exit(NULL);
}

/**
 * Configures the UMEM area for our AF_XDP/XSK sockets to use for rings.
 * 
 * @param buffer The blank buffer we allocated in setup_socket().
 * @param size The buffer size.
 * 
 * @return Returns a pointer to the UMEM area instead of the XSK UMEM information structure (struct xsk_umem_info).
**/
static struct xsk_umem_info *configure_xsk_umem(void *buffer, u64 size)
{
    // Create umem pointer and return variable.
    struct xsk_umem_info *umem;
    int ret;

    // Allocate memory space to the umem pointer and check.
    umem = calloc(1, sizeof(*umem));

    if (!umem)
    {
        return NULL;
    }

    // Attempt to create the umem area and check.
    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);

    if (ret) 
    {
        errno = -ret;
        return NULL;
    }

    // Assign the buffer we created in setup_socket() to umem buffer.
    umem->buffer = buffer;

    // Return umem pointer.
    return umem;
}

/**
 * Configures an AF_XDP/XSK socket.
 * 
 * @param umem A pointer to the umem we created in setup_socket().
 * @param queue_id The TX queue ID to use.
 * @param dev The name of the interface we're binding to.
 * 
 * @return Returns a pointer to the AF_XDP/XSK socket inside of a the XSK socket info structure (struct xsk_socket_info).
**/
static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, int queue_id, const char *dev)
{
    // Initialize starting variables.
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    u32 idx;
    int i;
    int ret;

    // Allocate memory space to our XSK socket.
    xsk_info = calloc(1, sizeof(*xsk_info));

    // If it fails, return.
    if (!xsk_info)
    {
        fprintf(stderr, "Failed to allocate memory space to AF_XDP/XSK socket.\n");

        return NULL;
    }

    // Assign AF_XDP/XSK's socket umem area to the umem we allocated before.
    xsk_info->umem = umem;
    
    // Set the RX size.
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;

    // Set the TX size.
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;

    // Make sure we don't load an XDP program via LibBPF.
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

    // Assign our XDP flags.
    xsk_cfg.xdp_flags = xdp_flags;

    // Assign bind flags.
    xsk_cfg.bind_flags = bind_flags;

    // Attempt to create the AF_XDP/XSK socket itself at queue ID (we don't allocate a RX queue for obvious reasons).
    ret = xsk_socket__create(&xsk_info->xsk, dev, queue_id, umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);

    if (ret)
    {
        fprintf(stderr, "Failed to create AF_XDP/XSK socket at creation.\n");

        goto error_exit;
    }

    // Assign each umem frame to an address we'll use later.
    for (i = 0; i < NUM_FRAMES; i++)
    {
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }

    // Assign how many number of frames we can hold.
    xsk_info->umem_frame_free = NUM_FRAMES;

    // Stuff the receive path with buffers, we assume we have enough.
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    {
        fprintf(stderr, "ret != XSK_RING_PROD__DEFAULT_NUM_DESCS :: Error.\n");

        goto error_exit;
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    {
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) = xsk_alloc_umem_frame(xsk_info);
    }

    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    // Return the AF_XDP/XSK socket information itself as a pointer.
    return xsk_info;

    // Handle error and return NULL.
    error_exit:
    errno = -ret;

    return NULL;
}

/**
 * Sends a packet buffer out the AF_XDP socket's TX path.
 * 
 * @param xsk Pointer to xsk_socket_info structure.
 * @param pckt The packet buffer starting at the Ethernet header.
 * @param length The packet buffer's length.
 * @param new If set to one, indicates a new packet that needs to be copied to uMEM.
 * 
 * @return Returns 0 on success and -1 on failure.
**/
int af_xdp_send_packet(struct xsk_socket_info *xsk, void *pckt, u16 length, int new, u64 addr)
{
    // This represents the TX index.
    u32 tx_idx = 0;
    u16 amt;

    // Retrieve the TX index from the TX ring to fill.
    amt = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);

    if (amt != 1)
    {
#ifdef DEBUG
        fprintf(stdout, "[XSK]No TX slots available.\n");
#endif

        return 1;
    }

    unsigned int idx = 0;

    // Retrieve index we want to insert at in UMEM and make sure it isn't equal/above to max number of frames.
    idx = xsk->outstanding_tx;

    // We must retrieve the next available address in the UMEM.
    u64 addrat;

    if (!new)
    {
        addrat = addr;
    }
    else
    {
        // We must retrieve new address space.
        addrat = xsk_alloc_umem_frame(xsk);

        // We must copy our packet data to the UMEM area at the specific index (idx * frame size). We did this earlier.
        memcpy(af_xdp_get_umem_loc(xsk, addrat), pckt, length);
    }

    // Retrieve TX descriptor at index.
    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);

    // Point the TX ring's frame address to what we have in the UMEM.
    tx_desc->addr = addrat;

    // Tell the TX ring the packet length.
    tx_desc->len = length;

    // Submit the TX batch to the producer ring.
    xsk_ring_prod__submit(&xsk->tx, 1);

    // Increase outstanding.
    xsk->outstanding_tx++;

#ifdef DEBUG
    fprintf(stdout, "Sending packet with length %u at location %llu. Outstanding count => %u.\n", length, tx_desc->addr, xsk->outstanding_tx);
#endif

    // Return successful.
    return 0;
}

/**
 * Retrieves UMEM address at index we can fill with packet data.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * @param idx The index we're retrieving (make sure it is below NUM_FRAMES).
 * 
 * @return 64-bit address of location.
**/
u64 af_xdp_get_umem_addr(struct xsk_socket_info *xsk, int idx)
{
    return xsk->umem_frame_addr[idx];
}

/**
 * Retrieves the memory location in the UMEM at address.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * @param addr The address received by af_xdp_get_umem_addr.
 * 
 * @return Pointer to address in memory of UMEM.
**/
void *af_xdp_get_umem_loc(struct xsk_socket_info *xsk, u64 addr)
{
    return xsk_umem__get_data(xsk->umem->buffer, addr);
}

/**
 * Sets global variables from command line.
 * 
 * @param cmd_af_xdp A pointer to the AF_XDP-specific command line variable.
 * @param verbose Whether we should print verbose.
 * 
 * @return Void
**/
void af_xdp_setup_variables(config_t *cfg)
{
    // Check for zero-copy or copy modes.
    if (cfg->zero_copy)
    {
        if (cfg->verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in zero-copy mode.\n");
        }

        bind_flags |= XDP_ZEROCOPY;
    }
    else
    {
        if (cfg->verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in copy mode.\n");
        }

        bind_flags |= XDP_COPY;
    }

    // Check for no wakeup mode.
    if (cfg->need_wakeup)
    {
        if (cfg->verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in no wake-up mode.\n");
        }

        bind_flags |= XDP_USE_NEED_WAKEUP; 
    }

    // Check for a static queue ID.
    if (cfg->queue_is_static)
    {
        static_queue_id = 1;
        queue_id = cfg->queue_id;

        if (cfg->verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets with one queue ID => %d.\n", queue_id);
        }
    }

    // Check for SKB mode.
    if (cfg->force_mode == 1)
    {
        if (cfg->verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in SKB mode.\n");
        }

        xdp_flags = XDP_FLAGS_SKB_MODE;
    }

    // Assign batch size.
    if (cfg->batch_size > 0)
    {
        batch_size = cfg->batch_size;
    }

    if (cfg->verbose)
    {
        fprintf(stdout, "Running AF_XDP sockets with batch size => %d.\n", batch_size);
    }
}

/**
 * Sets up UMEM at specific index.
 * 
 * @param index Sets up UMEM at a specific index.
 * 
 * @return 0 on success and -1 on failure.
**/
int af_xdp_setup_umem(int index)
{
    // This indicates the buffer for frames and frame size for the UMEM area.
    void *frame_buffer;
    u64 frame_buffer_size = NUM_FRAMES * FRAME_SIZE;

    // Allocate blank memory space for the UMEM (aligned in chunks). Check as well.
    if (posix_memalign(&frame_buffer, getpagesize(), frame_buffer_size)) 
    {
        fprintf(stderr, "Could not allocate buffer memory for UMEM index #%d => %s (%d).\n", index, strerror(errno), errno);

        return -1;
    }

    umem[index] = configure_xsk_umem(frame_buffer, frame_buffer_size);

    // Check the UMEM.
    if (umem[index] == NULL) 
    {
        fprintf(stderr, "Could not create UMEM at index %d ::  %s (%d).\n", index, strerror(errno), errno);

        return -1;
    }

    return 0;
}

/**
 * Sets up all XSK (AF_XDP) sockets.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * 
 * @return Void
**/
void af_xdp_setup_sockets(config_t *cfg, xdp_maps_t *xdp_maps)
{
    unsigned int i;
    unsigned int cnt = utils_cpu_cnt();

    if (cfg->socket_count > 0)
    {
        cnt = cfg->socket_count;
    }

    for (i = 0; i < cnt; i++)
    {
        af_xdp_setup_umem(i);
        af_xdp_setup_socket(cfg, xdp_maps, i);
    }
}

/**
 * Sets up XSK (AF_XDP) socket.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param index The index/thread ID.
 * 
 * @return Returns the AF_XDP's socket FD or -1 on failure.
**/
int af_xdp_setup_socket(config_t *cfg, xdp_maps_t *xdp_maps, int index)
{
    // Initialize starting variables.
    int ret;
    int xsks_map_fd;

    // Verbose message.
    if (cfg->verbose)
    {
        fprintf(stdout, "Attempting to setup AF_XDP socket. Dev => %s. Thread ID => %d.\n", cfg->interface, index);
    }

    // Configure and create the AF_XDP/XSK socket.
    struct xsk_umem_info *umem_to_use = umem[index];

    // Although this shouldn't happen, just check here in-case.
    if (umem_to_use == NULL)
    {
        fprintf(stderr, "UMEM at index %d is NULL. Aborting...\n", index);

        return -1;
    }

    xsk_socket[index] = NULL;

    xsk_socket[index] = xsk_configure_socket(umem_to_use, (static_queue_id) ? queue_id : index, (const char *)cfg->interface);

    // Check to make sure it's valid.
    if (xsk_socket[index] == NULL) 
    {
        fprintf(stderr, "Could not setup AF_XDP socket at index %d :: %s (%d).\n", index, strerror(errno), errno);

        return -1;
    }

    // Retrieve the AF_XDP/XSK's socket FD and do a verbose print.
    int fd = xsk_socket__fd(xsk_socket[index]->xsk);

    // Create thread info.
    thread_info_t *t_info = calloc(1, sizeof(thread_info_t));
    memset(t_info, 0, sizeof(thread_info_t));

    t_info->cfg = cfg;
    t_info->thread_id = index;
    t_info->xsk = xsk_socket[index];
    t_info->xdp_maps = xdp_maps;

    pthread_t pid;

    pthread_create(&pid, NULL, socket_thread, (void *)t_info);

    // Insert map into XSKs map.
    if (bpf_map_update_elem(xdp_maps->xsks_map, &index, &fd, BPF_ANY) != 0)
    {
        fprintf(stderr, "WARNING - Failed to update XSKs map at index %d (FD %d).\n", index, fd);
    }

    if (cfg->verbose)
    {
        fprintf(stdout, "Created AF_XDP socket at index %d (FD => %d).\n", index, fd);
    }

    // Return the socket's file descriptor.
    return fd;
}

/**
 * Cleans up a specific AF_XDP/XSK socket.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * 
 * @return Void
**/
void af_xdp_cleanup_socket(struct xsk_socket_info *xsk)
{
    // If the UMEM isn't NULL, delete it.
    if (xsk->umem != NULL)
    {
        xsk_umem__delete(xsk->umem->umem);
    }

    // If the AF_XDP/XSK socket isn't NULL, delete it.
    if (xsk->xsk != NULL)
    {
        xsk_socket__delete(xsk->xsk);
    }
}