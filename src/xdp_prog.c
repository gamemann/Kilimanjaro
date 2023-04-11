#include "xdp_prog.h"
#include "pp_utils.h"

struct bpf_map_def SEC("maps") stats =
{
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct stats_val),
    .max_entries = MAX_CPUS
};

struct bpf_map_def SEC("maps") xdp_conf =
{
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct xdp_config_val),
    .max_entries = MAX_CPUS
};

struct bpf_map_def SEC("maps") edge_ip =
{
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(be32),
    .max_entries = 1
};

struct bpf_map_def SEC("maps") connections =
{
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct connection_key),
    .value_size = sizeof(struct connection_val),
    .max_entries = MAX_CONNECTIONS
};

struct bpf_map_def SEC("maps") connection_stats =
{
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct connection_key),
    .value_size = sizeof(struct connection_stats_val),
    .max_entries = MAX_CONNECTIONS
};

struct bpf_map_def SEC("maps") client_connections =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct client_connection_key),
    .value_size = sizeof(struct client_connection_val),
    .max_entries = 100000
};

struct bpf_map_def SEC("maps") validated_clients =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct client_connection_key),
    .value_size = sizeof(struct client_validated_val),
    .max_entries = 100000
};

struct bpf_map_def SEC("maps") outgoing =
{
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct outgoing_key),
    .value_size = sizeof(u8),
    .max_entries = MAX_CONNECTIONS
};

struct bpf_map_def SEC("maps") white_list =
{
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_trie_key),
    .value_size = sizeof(u64),
    .max_entries = MAX_WHITELIST,
    .map_flags = BPF_F_NO_PREALLOC
};

struct bpf_map_def SEC("maps") black_list =
{
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_trie_key),
    .value_size = sizeof(u64),
    .max_entries = MAX_BLACKLIST,
    .map_flags = BPF_F_NO_PREALLOC
};

struct bpf_map_def SEC("maps") port_punch =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct port_punch_key),
    .value_size = sizeof(struct port_punch_val),
    .max_entries = MAX_CLIENT_CONNECTIONS
};

struct bpf_map_def SEC("maps") block_list =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(be32),
    .value_size = sizeof(u64),
    .max_entries = MAX_CLIENT_CONNECTIONS
};

struct bpf_map_def SEC("maps") a2s_info =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct flow),
    .value_size = sizeof(struct a2s_info_val),
    .max_entries = MAX_CONNECTIONS
};

struct bpf_map_def SEC("maps") xsks_map =
{
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = MAX_CPUS
};

struct 
{
    __uint(priority, 20);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog);

/**
 * Calculates the entire UDP checksum (including payload data) from scratch.
 * 
 * @param iph Pointer to IPv4 header.
 * @param udph Pointer to UDP header.
 * @param data_end Pointer to packet's data end.
 * 
 * @note All credit goes to FedeParola from https://github.com/iovisor/bcc/issues/2463
 * 
 * @return 16-bit UDP checksum.
**/
static __always_inline u16 calc_udp_csum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    u32 csum_buffer = 0;
    u16 *buf = (void *)udph;

    // Compute pseudo-header checksum
    csum_buffer += (u16)iph->saddr;
    csum_buffer += (u16)(iph->saddr >> 16);
    csum_buffer += (u16)iph->daddr;
    csum_buffer += (u16)(iph->daddr >> 16);
    csum_buffer += (u16)iph->protocol << 8;
    csum_buffer += udph->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) 
    {
        if ((void *)(buf + 1) > data_end) 
        {
            break;
        }

        if ((void *)buf <= data_end)
        {
            csum_buffer += *buf;
            buf++;
        }
    }

    if ((void *)buf + 1 <= data_end) 
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(u8 *)buf;
    }

    u16 csum = (u16)csum_buffer + (u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}

/**
 * Swaps ethernet header's source and destination MAC addresses.
 * 
 * @param eth Pointer to Ethernet header.
 * 
 * @return Void
**/
static __always_inline void swap_eth(struct ethhdr *eth)
{
    u8 tmp[ETH_ALEN];
    memcpy(tmp, &eth->h_source, ETH_ALEN);

    memcpy(&eth->h_source, &eth->h_dest, ETH_ALEN);
    memcpy(&eth->h_dest, tmp, ETH_ALEN);
}

/**
 * Swaps IPv4 header's source and destination IP addresses.
 * 
 * @param iph Pointer to IPv4 header.
 * 
 * @return Void
**/
static __always_inline void swap_ip(struct iphdr *iph)
{
    be32 tmp;
    memcpy(&tmp, &iph->saddr, sizeof(be32));

    memcpy(&iph->saddr, &iph->daddr, sizeof(be32));
    memcpy(&iph->daddr, &tmp, sizeof(be32));
}

/**
 * Swaps UDP header's source and destination ports.
 * 
 * @param udph Pointer to UDP header.
 * 
 * @return Void
**/
static __always_inline void swap_udp(struct udphdr *udph)
{
    be16 tmp;
    memcpy(&tmp, &udph->source, sizeof(be16));

    memcpy(&udph->source, &udph->dest, sizeof(be16));
    memcpy(&udph->dest, &tmp, sizeof(be16));
}

/**
 * Swaps TCP header's source and destination ports.
 * 
 * @param tcph Pointer to TCP header.
 * 
 * @return Void
**/
static __always_inline void swap_tcp(struct tcphdr *tcph)
{
    be16 tmp;
    memcpy(&tmp, &tcph->source, sizeof(be16));

    memcpy(&tcph->source, &tcph->dest, sizeof(be16));
    memcpy(&tcph->dest, &tmp, sizeof(be16));
}

/**
 * Checks if A2S_INFO is enabled on a connection.
 * 
 * @param val A pointer to the connection value.
 * 
 * @return 1 on yes and 0 on no.
**/
static __always_inline int a2s_enabled(struct connection_val *val)
{
    if (val->cache_settings.A2S_INFO)
    {
        return 1;
    }

    return 0;
}

static __always_inline void block_client(be32 ip, u64 now, u16 time)
{
    u64 block_time = now + (time * 1000000000);

    bpf_map_update_elem(&block_list, &ip, &block_time, BPF_ANY);
}

static __always_inline int check_rate_limits(struct client_connection_key *ckey, u16 len, u64 now, u64 pps, u64 bps, u16 block_time)
{
    struct client_connection_val *val = bpf_map_lookup_elem(&client_connections, ckey);

    if (!val)
    {
        struct client_connection_val new_val = {0};
        new_val.pps = 1;
        new_val.bps = len;
        new_val.next_update = now + 1000000000;
        new_val.last_seen = now;
        bpf_map_update_elem(&client_connections, ckey, &new_val, BPF_ANY);

        return 0;
    }
    
    if (val->next_update <= now)
    {
        val->pps = 1;
        val->bps = len;
        val->next_update = now + 1000000000;

        return 0;
    }

    val->pps++;
    val->bps += len;

    if ((pps > 0 && val->pps > pps) || (bps > 0 && val->bps > bps))
    {
        block_client(ckey->src.ip, now, block_time);

        return 1;
    }

    return 0;
}

/**
 * Updates stats map.
 * 
 * @param stats_val A pointer to the stats value.
 * @param type Type of stats to update.
 * @param length Length of entire packet.
 * 
 * @return Void
**/
static __always_inline void update_stats(struct stats_val *stats_val, u16 type, u16 length)
{
    if (!stats_val)
    {
        return;
    }

    switch (type)
    {
        case STATS_TYPE_BLACKLIST:
            stats_val->bla_pckts_total++;
            stats_val->bla_bytes_total += length;

            break;

        case STATS_TYPE_WHITELIST:
            stats_val->whi_pckts_total++;
            stats_val->whi_bytes_total += length;

            break;

        case STATS_TYPE_BLOCKLIST:
            stats_val->blo_pckts_total++;
            stats_val->blo_bytes_total += length;

            break;

        case STATS_TYPE_FWD:
            stats_val->fwd_pckts_total++;
            stats_val->fwd_bytes_total += length;

            break;

        case STATS_TYPE_PASS:
            stats_val->pass_pckts_total++;
            stats_val->pass_bytes_total += length;

            break;

        case STATS_TYPE_BAD:
            stats_val->bad_pckts_total++;
            stats_val->bad_bytes_total += length;

            break;

        case STATS_TYPE_A2S_REPLY:
            stats_val->a2s_reply_pckts_total++;
            stats_val->a2s_reply_bytes_total += length;

            break;

        case STATS_TYPE_A2S_RESPONSE:
            stats_val->a2s_response_pckts_total++;
            stats_val->a2s_response_bytes_total += length;

            break;

        case STATS_TYPE_DROP_OTHER:
            stats_val->drop_other_pckts_total++;
            stats_val->drop_other_bytes_total += length;

            break;

        case STATS_TYPE_DROP_CONN:
            stats_val->drop_conn_pckts_total++;
            stats_val->drop_conn_bytes_total += length;

            break;

        case STATS_TYPE_FWD_OUT:
            stats_val->fwd_out_pckts_total++;
            stats_val->fwd_out_bytes_total += length;

            break;
    }
}

/**
 * Copy and swaps from one ethernet header to another while swapping addresses.
 * 
 * @param new_eth The ethernet header to copy to.
 * @param old_eth The ethernet header to copy from.
 * 
 * @return Void
**/
static __always_inline void copy_and_swap_eth(struct ethhdr *new_hdr, struct ethhdr *old_hdr) 
{
    uint16_t *new_p = (uint16_t *)new_hdr;
    uint16_t *old_p = (uint16_t *)old_hdr;

    new_p[0] = old_p[3];
    new_p[1] = old_p[4];
    new_p[2] = old_p[5];
    new_p[3] = old_p[0];
    new_p[4] = old_p[1];
    new_p[5] = old_p[2];
    new_hdr->h_proto = old_hdr->h_proto;
}

/**
 * Adds IPIP outer header, swaps data, and forwards packet to destination machine.
 * 
 * @param ctx Pointer XDP meta data/context.
 * @param cval A pointer to the connection value.
 * @param bind_port The connection's bind port in the case we want to translate to a new port (0 ignores).
 * @param stats Pointer to stats value.
 * @param len Length of original packet.
 * 
 * @return XDP_TX on success or XDP_DROP on failure.
**/
static __always_inline int add_ipip_and_forward(struct xdp_md *ctx, struct connection_val *cval, u16 bind_port, struct stats_val *stats_val, u16 len)
{
    // Add IPIP outer header and ethernet header.
    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr)))
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    // Reinitialize data pointers.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    len = (data_end - data);

    struct ethhdr *new_eth = data;

    if (new_eth + 1 > (struct ethhdr *)data_end)
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    struct ethhdr *old_eth = data + sizeof(struct iphdr);

    if (old_eth + 1 > (struct ethhdr *)data_end)
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    // Copy and swap ethernet addresses.
    copy_and_swap_eth(new_eth, old_eth);

    // Lookup edge IP.
    u32 key = 0;
    u32 *edge_ip_val = bpf_map_lookup_elem(&edge_ip, &key);

    if (!edge_ip_val)
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    // Initialize outer IP header.
    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (iph + 1 > (struct iphdr *)data_end)
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    // Initialize inner IP header.
    struct iphdr *inner_iph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (inner_iph + 1 > (struct iphdr *)data_end)
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    // Fill out outer IP header information.
    iph->version = 4;
    iph->ihl = 5;
    iph->protocol = IPPROTO_IPIP;
    iph->saddr = *edge_ip_val;
    iph->daddr = cval->dest_ip;
    iph->frag_off = 0;
    iph->id = 0;
    iph->tot_len = htons(ntohs(inner_iph->tot_len) + sizeof(struct iphdr));
    iph->tos = inner_iph->tos;
    iph->ttl = 64;

    // Update checksum.
    update_iph_checksum(iph);

    // Check if we want to translate to a new port.
    if (bind_port > 0 && bind_port != cval->dest_port)
    {
        // Initialize layer 4 headers.
        struct udphdr *udph = NULL;
        struct tcphdr *tcph = NULL;

        be16 old = 0;

        switch (inner_iph->protocol)
        {
            case IPPROTO_UDP:
                udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_iph->ihl * 4);

                if (udph + 1 > (struct udphdr *)data_end)
                {
                    update_stats(stats_val, STATS_TYPE_BAD, len);

                    return XDP_DROP;
                }

                old = udph->dest;
                udph->dest = cval->dest_port;

                udph->check = csum_diff4(old, udph->dest, udph->check);

                break;

            case IPPROTO_TCP:
                tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_iph->ihl * 4);

                if (tcph + 1 > (struct tcphdr *)data_end)
                {
                    update_stats(stats_val, STATS_TYPE_BAD, len);

                    return XDP_DROP;
                }

                old = tcph->dest;
                tcph->dest = cval->dest_port;

                tcph->check = csum_diff4(old, tcph->dest, tcph->check);

                break;
        }
    }

    update_stats(stats_val, STATS_TYPE_FWD, len);

    return XDP_TX;
}

SEC("kilimanjaro_xdp")
int xdp_prog(struct xdp_md *ctx)
{
    // Initialize data headers.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Start stats.
    u16 len = (data_end - data);
    u32 stats_key = 0;
    struct stats_val *stats_val = bpf_map_lookup_elem(&stats, &stats_key);

    if (!stats_val)
    {
        struct stats_val new_stats = {0};

        bpf_map_update_elem(&stats, &stats_key, &new_stats, BPF_ANY);

        stats_val = bpf_map_lookup_elem(&stats, &stats_key);
    }

    struct ethhdr *eth = data;

    if (eth + 1 > (struct ethhdr *)data_end)
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    // Pass anything that isn't IPv4.
    if (eth->h_proto != htons(ETH_P_IP))
    {
        update_stats(stats_val, STATS_TYPE_PASS, len);

        return XDP_PASS;
    }

    // Create IPv4 header.
    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (iph + 1 > (struct iphdr *)data_end)
    {
        update_stats(stats_val, STATS_TYPE_BAD, len);

        return XDP_DROP;
    }

    // Make sure we're dealing with a client.
    if (iph->protocol == IPPROTO_IPIP)
    {
        goto outgoing;
    }

    // Create layer-four headers.
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    struct icmphdr *icmph = NULL;

    be16 src_port = 0;
    be16 dst_port = 0;
    be16 l4_len = 0;

    switch (iph->protocol)
    {
        case IPPROTO_UDP:
            udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (udph + 1 > (struct udphdr *)data_end)
            {
                update_stats(stats_val, STATS_TYPE_BAD, len);

                return XDP_DROP;
            }

            src_port = udph->source;
            dst_port = udph->dest;

            l4_len = sizeof(struct udphdr);

            break;

        case IPPROTO_TCP:
            tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (tcph + 1 > (struct tcphdr *)data_end)
            {
                update_stats(stats_val, STATS_TYPE_BAD, len);

                return XDP_DROP;
            }

            src_port = tcph->source;
            dst_port = tcph->dest;

            l4_len = sizeof(struct tcphdr);

            break;

        case IPPROTO_ICMP:
            icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (icmph + 1 > (struct icmphdr *)data_end)
            {
                update_stats(stats_val, STATS_TYPE_BAD, len);

                return XDP_DROP;
            }

            break;
    }

    // We don't support any other type of protocols.
    if (!udph && !tcph && !icmph)
    {
        return XDP_DROP;
    }

    // Get current time.
    u64 now = bpf_ktime_get_ns();

    // Check against block list.
    u64 *block_time = bpf_map_lookup_elem(&block_list, &iph->saddr);

    if (block_time)
    {
        if (*block_time < now)
        {
            bpf_map_delete_elem(&block_list, &iph->saddr);
        }

        update_stats(stats_val, STATS_TYPE_BLOCKLIST, len);

        return XDP_DROP;
    }

    struct lpm_trie_key trie_key;
    trie_key.prefix_len = 32;
    trie_key.data = iph->saddr;

    u64 *black_listed = bpf_map_lookup_elem(&black_list, &trie_key);

    if (black_listed)
    {
        u32 bit_mask = *black_listed >> 32;
        u32 prefix = *black_listed & 0xffffffff;

        if ((iph->saddr & bit_mask) == prefix)
        {
            update_stats(stats_val, STATS_TYPE_BLACKLIST, len);

            return XDP_DROP;
        }
    }

    // Create connection key.
    struct connection_key ckey = {0};
    ckey.protocol = iph->protocol;
    ckey.bind.ip = iph->daddr;
    ckey.bind.port = dst_port;

    struct connection_val *cval = bpf_map_lookup_elem(&connections, &ckey);

    if (cval)
    {
        u8 *pl = data + sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len;
        u16 pl_len = len - sizeof(struct ethhdr) - (iph->ihl * 4) - l4_len;

        // Increase stats.
        struct connection_stats_val *cstats = bpf_map_lookup_elem(&connection_stats, &ckey);

        if (cstats)
        {
            cstats->pckts++;
            cstats->bytes += len;
        }
        else
        {
            struct connection_stats_val new_stats = {0};
            new_stats.pckts = 1;
            new_stats.bytes = len;

            bpf_map_update_elem(&connection_stats, &ckey, &new_stats, BPF_ANY);
        }

        // Check rate limits.
        struct client_connection_key clkey = {0};
        clkey.src.ip = iph->saddr;
        clkey.src.port = src_port;
        clkey.dst = ckey.bind;

        // Check for whitelist.
        u64 *white_listed = bpf_map_lookup_elem(&white_list, &trie_key);

        if (white_listed)
        {
            u32 bit_mask = *white_listed >> 32;
            u32 prefix = *white_listed & 0xffffffff;

            if ((iph->saddr & bit_mask) == prefix)
            {
                update_stats(stats_val, STATS_TYPE_WHITELIST, len);

                goto forward;
            }
        }

        if (udph)
        {
            struct client_connection_key clikey = {0};
            struct flow src = {0};
            struct flow dst = {0};
            src.ip = iph->saddr;
            src.port = udph->source;
            dst.ip = iph->daddr;
            dst.port = udph->dest;
            clikey.src = src;
            clikey.dst = dst;

            // Make sure we have five bytes of payload before checking A2S_INFO.
            if (pl + 5 <= (u8 *)data_end)
            {
                // Check whether A2S_INFO is enabled for this connection.
                if (a2s_enabled(cval))
                {
                    // Check if we have A2S_INFO request.
                    if (*(pl) == 0XFF && *(pl + 1) == 0XFF && *(pl + 2) == 0XFF && *(pl + 3) == 0XFF && *(pl + 4) == 0X54)
                    {
                        // Check A2S_INFO map.
                        struct flow info_key = {0};
                        info_key.ip = iph->daddr;
                        info_key.port = dst_port;

                        // Check map.
                        struct a2s_info_val *a2s = bpf_map_lookup_elem(&a2s_info, &info_key);

                        if (!a2s)
                        {
#ifdef A2S_DEBUG
                                bpf_printk("[A2S_REQ]No response found in map (%lu:%d). Forwarding packet.\n", info_key.ip, info_key.port);
#endif

                            goto forward;
                        }

#ifdef A2S_DEBUG
                            bpf_printk("[A2S_REQ]Passed length checks.\n");
#endif

                        if (pl_len < a2s->size)
                        {
                            u16 grow = a2s->size - (pl_len - 5);

#ifdef A2S_DEBUG
                                bpf_printk("[A2S_REQ]Growing packet by %d bytes.\n", grow);
#endif

                            if (bpf_xdp_adjust_tail(ctx, (int)grow) != 0)
                            {
#ifdef A2S_DEBUG
                                    bpf_printk("[A2S_REQ]FAILED to grow packet by %u bytes!\n", grow);
#endif
                                update_stats(stats_val, STATS_TYPE_BAD, len);

                                return XDP_DROP;
                            }
                        }
                        else if (pl_len > a2s->size)
                        {
                            u16 shrink = (pl_len - 5) - a2s->size;

#ifdef A2S_DEBUG
                                bpf_printk("[A2S_REQ]Shrinking packet by %d bytes.\n", shrink);
#endif

                            if (bpf_xdp_adjust_tail(ctx, 0 - (int)shrink) != 0)
                            {
#ifdef A2S_DEBUG
                                    bpf_printk("[A2S_REQ]FAILED to shrink packet!\n");
#endif
                                update_stats(stats_val, STATS_TYPE_BAD, len);

                                return XDP_DROP;
                            }
                        }

#ifdef A2S_DEBUG
                            bpf_printk("[A2S_REQ]Redefining headers.\n");
#endif

                        data = (void *)(long)ctx->data;
                        data_end = (void *)(long)ctx->data_end;

                        eth = data;

                        if (unlikely(eth + 1 > (struct ethhdr *)data_end))
                        {
                            update_stats(stats_val, STATS_TYPE_BAD, len);

                            return XDP_DROP;
                        }

                        iph = data + sizeof(struct ethhdr);

                        if (unlikely(iph + 1 > (struct iphdr *)data_end))
                        {
                            update_stats(stats_val, STATS_TYPE_BAD, len);

                            return XDP_DROP;
                        }

                        udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                        if (unlikely(udph + 1 > (struct udphdr *)data_end))
                        {
                            update_stats(stats_val, STATS_TYPE_BAD, len);

                            return XDP_DROP;
                        }

                        pl = data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr) + 5;
                        len = (ctx->data_end - ctx->data);

#ifdef A2S_DEBUG
                            bpf_printk("[A2S_REQ]New payload/response length => %u\n", a2s->size);
#endif

                        for (u16 i = 0; i < a2s->size; i++)
                        {
                            if (pl + (i + 1) > (u8 *)data_end)
                            {
                                break;
                            }

                            if (i >= sizeof(a2s->data))
                            {
                                break;
                            }

#ifdef A2S_DEBUG
                            bpf_printk("Setting index %d to %d", i, *(a2s->data + i));
#endif

                            *(pl + i) = *(a2s->data + i);
                        }

                        u8 expired = 0;

                        // Check cache time.
                        if (now > a2s->expires)
                        {
#ifdef A2S_DEBUG
                                bpf_printk("[A2S_REQ]Cache time expired (%llu > %llu) (%llu)! Reply to packet.\n", now, (a2s->expires + cval->cache_settings.A2S_INFO_time), cval->cache_settings.A2S_INFO_time);
#endif

                            expired = 1;
                        }

                        // Set response.
                        if (pl <= (u8 *)data_end)
                        {
                            if (expired)
                            {
                                // If expired, set to 0x55 for AF_XDP program.
                                *(pl - 1) = 0x55;
                            }
                            else
                            {
                                *(pl - 1) = 0x49;
                            }
                        }
                        
                        // Swap layer 2/3/4 headers.
                        swap_eth(eth);
                        swap_ip(iph);
                        swap_udp(udph);

                        // Recalculate UDP length and checksum.
                        udph->len = htons(sizeof(struct udphdr) + a2s->size + 5);
                        udph->check = 0;
                        udph->check = calc_udp_csum(iph, udph, data_end);

                        // Recalculate IP header length and set TTL to 64.
                        u16 old_len = iph->tot_len;
                        iph->tot_len = htons(len - sizeof(struct ethhdr));
                        u8 old_ttl = iph->ttl;
                        iph->ttl = 64;
                        iph->check = csum_diff4(old_len, iph->tot_len, iph->check);
                        iph->check = csum_diff4(old_ttl, iph->ttl, iph->check);

#ifdef A2S_DEBUG
                            bpf_printk("[A2S_REQ]Sending cached response back (%lu => %lu)!\n", iph->saddr, iph->daddr);
                            bpf_printk("[A2S_REQ] Src Eth => %x %x %x", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
                            bpf_printk("[A2S_REQ] Dst Eth => %x %x %x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
#endif

                        // Forward packet directly back to client.
                        update_stats(stats_val, STATS_TYPE_A2S_REPLY, len);

                        // If we're expired, send to AF_XDP program.
                        if (expired)
                        {
                            return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
                        }
        
                        return XDP_TX;
                    }
                }
            }

            /* Perform any INCOMING layer-7 filters here. */

            endfilters:
            if(check_rate_limits(&clikey, len, now, cval->udp_rl.pps, cval->udp_rl.bps, cval->udp_rl.block_time))
            {
                update_stats(stats_val, STATS_TYPE_DROP_OTHER, len);
                return XDP_DROP;
            }

            goto forward;
        }
        else if (tcph)
        {
            if(check_rate_limits(&clkey, len, now, cval->tcp_rl.pps, cval->tcp_rl.bps, cval->tcp_rl.block_time))
            {
                update_stats(stats_val, STATS_TYPE_DROP_OTHER, len);

                return XDP_DROP;
            }

            goto forward;
        }
        else if (icmph)
        {
            if(check_rate_limits(&clkey, len, now, cval->icmp_rl.pps, cval->icmp_rl.bps, cval->icmp_rl.block_time))
            {
                update_stats(stats_val, STATS_TYPE_DROP_OTHER, len);

                return XDP_DROP;
            }

            if (icmph->type == ICMP_ECHO) 
            {
                if(len > 1480){
                    return XDP_DROP;
                }
                swap_eth(eth);
                swap_ip(iph);
        
                u8 old_ttl = iph->ttl;
                iph->ttl = 64;
                iph->check = csum_diff4(old_ttl, 64, iph->check);

                icmph->type = ICMP_ECHOREPLY;
                icmph->checksum = csum_diff4(ICMP_ECHO, ICMP_ECHOREPLY, icmph->checksum);


#ifdef ICMP_DEBUG
                bpf_printk("[ICMP] Found ICMP request from %lu => %lu. Replying...\n", iph->daddr, iph->saddr);
#endif
                
                return XDP_TX;
            }
        }

        update_stats(stats_val, STATS_TYPE_DROP_CONN, len);

        return XDP_DROP;

        forward:;
        // Add IPIP header and swap, then TX out if successful.
        return add_ipip_and_forward(ctx, cval, dst_port, stats_val, len);
    }

    // Do port punch map check before dropping.
    struct port_punch_key pkey = {0};
    pkey.dest.ip = iph->saddr;
    pkey.dest.port = src_port;
    pkey.service.ip = iph->daddr;
    pkey.service.port = dst_port;

    struct port_punch_val *pval = bpf_map_lookup_elem(&port_punch, &pkey);

    if (pval)
    {
        // Create temporary connection value.
        struct connection_val new_cval = {0};
        new_cval.dest_ip = pval->dest_ip;

        pval->last_seen = now;

        return add_ipip_and_forward(ctx, &new_cval, 0, stats_val, len);
    }

    // Retrieve XDP config and edge IP.
    u32 one = 0;
    struct xdp_config_val *xdp_conf_val = bpf_map_lookup_elem(&xdp_conf, &one);

    be32 *edge_ip_val = bpf_map_lookup_elem(&edge_ip, &one);

    if (xdp_conf_val && edge_ip_val)
    {
        if (xdp_conf_val->allow_edge && *edge_ip_val == iph->daddr)
        {
            update_stats(stats_val, STATS_TYPE_PASS, len);

            return XDP_PASS;
        }
    }

    // Check white-list.
    struct lpm_trie_key new_trie_key = {0};
    new_trie_key.prefix_len = 32;
    new_trie_key.data = iph->saddr;

    u64 *white_listed = bpf_map_lookup_elem(&white_list, &new_trie_key);

    if (white_listed)
    {
        u32 bit_mask = *white_listed >> 32;
        u32 prefix = *white_listed & 0xffffffff;

        if ((iph->saddr & bit_mask) == prefix)
        {
            update_stats(stats_val, STATS_TYPE_WHITELIST, len);

            return XDP_PASS;
        }
    }

    return XDP_DROP;

    outgoing:;
    // If this is an IPIP packet, we should check if it's outgoing.
    if (iph->protocol == IPPROTO_IPIP)
    {
        struct iphdr *inner_iph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

        if (inner_iph + 1 > (struct iphdr *)data_end)
        {
            update_stats(stats_val, STATS_TYPE_BAD, len);

            return XDP_DROP;
        }

        // Create layer-four headers.
        struct udphdr *udph = NULL;
        struct tcphdr *tcph = NULL;
        struct icmphdr *icmph = NULL;

        be16 src_port = 0;
        be16 dst_port = 0;

        switch (inner_iph->protocol)
        {
            case IPPROTO_UDP:
                udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_iph->ihl * 4);

                if (udph + 1 > (struct udphdr *)data_end)
                {
                    update_stats(stats_val, STATS_TYPE_BAD, len);

                    return XDP_DROP;
                }

                src_port = udph->source;
                dst_port = udph->dest;

                break;

            case IPPROTO_TCP:
                tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_iph->ihl * 4);

                if (tcph + 1 > (struct tcphdr *)data_end)
                {
                    update_stats(stats_val, STATS_TYPE_BAD, len);

                    return XDP_DROP;
                }

                src_port = tcph->source;
                dst_port = tcph->dest;

                break;

            case IPPROTO_ICMP:
                icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_iph->ihl * 4);

                if (icmph + 1 > (struct icmphdr *)data_end)
                {
                    update_stats(stats_val, STATS_TYPE_BAD, len);

                    return XDP_DROP;
                }

                break;
        }        

        // For security, make sure we're seeing the right packets.
        struct outgoing_key okey = {0};
        okey.machine_ip = iph->saddr;
        okey.connection_ip = inner_iph->saddr;

        u8 *valid = bpf_map_lookup_elem(&outgoing, &okey);

        if (valid)
        {
            // Get current time.
            u64 now = bpf_ktime_get_ns();
            
            u8 redirect = 0;

            // Before removing the outer IP header, switch the ethernet header's source/destination MAC addresses.
            swap_eth(eth);

            // See if we need to do a port punch.
            struct connection_key ckey = {0};
            ckey.protocol = inner_iph->protocol;
            ckey.bind.ip = inner_iph->saddr;
            ckey.bind.port = src_port;

            struct connection_val *val = bpf_map_lookup_elem(&connections, &ckey);

            if (!val)
            {
                // Check white-list.
                struct lpm_trie_key new_trie_key = {0};
                new_trie_key.prefix_len = 32;
                new_trie_key.data = inner_iph->daddr;

                u8 keep_on = 1;

                u64 *whitelist_check = bpf_map_lookup_elem(&white_list, &new_trie_key);

                if (whitelist_check)
                {
                    u32 bit_mask = *whitelist_check >> 32;
                    u32 prefix = *whitelist_check & 0xffffffff;

                    if ((inner_iph->daddr & bit_mask) == prefix)
                    {
                        keep_on = 0;
                    }
                }

                if (keep_on)
                {
                    // Add to port punch map.
                    struct port_punch_key pkey = {0};
                    pkey.service.ip = inner_iph->saddr;
                    pkey.service.port = src_port;
                    pkey.dest.ip = inner_iph->daddr;
                    pkey.dest.port = dst_port;

                    struct port_punch_val *pval = bpf_map_lookup_elem(&port_punch, &pkey);

                    if (pval)
                    {
                        // If XDP added is 0 (e.g. added by Killfrenzy), set it to 1 now since it's coming through this POP.
                        if (pval->xdp_added == 0)
                        {
                            pval->xdp_added = 1;
                        }

                        pval->last_seen = now;
                    }
                    else
                    {
                        struct port_punch_val new_pval = {0};
                        new_pval.dest_ip = iph->saddr;
                        new_pval.last_seen = now;
                        new_pval.xdp_added = 1;
                        bpf_map_update_elem(&port_punch, &pkey, &new_pval, BPF_ANY);
                    }
                }
            }
            else
            {
                // Check for A2S_INFO response.
                if (udph)
                {
                    if (a2s_enabled(val))
                    {
                        u8 *pl = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_iph->ihl * 4) + sizeof(struct udphdr);

                        if (pl + 5 <= (u8 *)data_end)
                        {
                            // Check if valid A2S_INFO response.
                            if (*(pl) == 0XFF && *(pl + 1) == 0XFF && *(pl + 2) == 0XFF && *(pl + 3) == 0XFF && *(pl + 4) == 0x49)
                            {
#ifdef SEC_A2S_DEBUG
                                bpf_printk("[S2R] Found A2S_INFO response from %lu => %lu.\n", ntohl(inner_iph->saddr), ntohl(inner_iph->daddr));
#endif
                                redirect = 1;
                            }
                            // Check for challenge response.
                            else if (*(pl) == 0XFF && *(pl + 1) == 0XFF && *(pl + 2) == 0XFF && *(pl + 3) == 0XFF && *(pl + 4) == 0x41)
                            {
#ifdef A2SCH_DEBUG
                                bpf_printk("[A2S CH] Found for %lu:%d\n", ntohl(inner_iph->saddr), ntohs(udph->source));
#endif
                                struct flow a2s_key = {0};
                                a2s_key.ip = inner_iph->saddr;
                                a2s_key.port = udph->source;

                                struct a2s_info_val *a2s_val = bpf_map_lookup_elem(&a2s_info, &a2s_key);

                                if (a2s_val)
                                {
#ifdef A2SCH_DEBUG
                                    bpf_printk("[A2S CH] Found A2S_INFO map for %lu:%d\n", ntohl(inner_iph->saddr), ntohs(udph->source));
#endif
                                    // Save challenge.
                                    if (pl + 9 <= (u8 *)data_end)
                                    {
#ifdef A2SCH_DEBUG
                                        bpf_printk("[A2S CH] Saving challenge for %lu:%d\n", ntohl(inner_iph->saddr), ntohs(udph->source));
                                        bpf_printk("[A2S CH] Challenge => %x %x %x\n", *(pl + 5), *(pl + 6), *(pl + 7));
#endif
                                        memcpy(&a2s_val->challenge, (pl + 5), 4);
                                        a2s_val->challenge_set = 1;
                                    }
                                }
                            }
                        }
                    }
                }

                /* Perform any OUTGOING layer-7 filters here. */
            }

            struct ethhdr tmp = {0};
            memcpy(&tmp, eth, sizeof(struct ethhdr));

            // We'll want to remove the outer IPIP header.
            if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr)))
            {
                update_stats(stats_val, STATS_TYPE_BAD, len);

                return XDP_DROP;
            }

            // Reinitialize data and ethernet header.
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            eth = data;

            if (eth + 1 > (struct ethhdr *)data_end)
            {
                update_stats(stats_val, STATS_TYPE_BAD, len);
                
                return XDP_DROP;
            }

            memcpy(eth, &tmp, sizeof(struct ethhdr));

            // Check if we need to redirect to AF_XDP.
            if (redirect)
            {
                update_stats(stats_val, STATS_TYPE_A2S_RESPONSE, len);

                return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
            }

            iph = data + sizeof(struct ethhdr);

            if (iph + 1 > (struct iphdr *)data_end)
            {
                update_stats(stats_val, STATS_TYPE_BAD, len);

                return XDP_DROP;
            }

            // TX the packet.
            update_stats(stats_val, STATS_TYPE_FWD_OUT, len);

            return XDP_TX;
        }

        update_stats(stats_val, STATS_TYPE_DROP_OTHER, len);

        return XDP_DROP;
    }

    update_stats(stats_val, STATS_TYPE_DROP_OTHER, len);

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);