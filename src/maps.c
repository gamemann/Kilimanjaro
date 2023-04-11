#include "maps.h"

/**
 * Pins BPF maps to file system.
 * 
 * @param prog Pointer to XDP program.
 * @param path Path to pin maps to.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_pin(struct xdp_program *prog, const char *path)
{
    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    return bpf_object__pin_maps(obj, path);
}

/**
 * Unpins BPF maps from file system.
 * 
 * @param prog Pointer to XDP program.
 * @param path Path to unpin maps from.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_unpin(struct xdp_program *prog, const char *path)
{
    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    return bpf_object__unpin_maps(obj, path);
}

/**
 * Pins BPF maps to file system.
 * 
 * @param prog Pointer to XDP program.
 * @param xdp_maps A pointer to store the XDP map FDs in.
 * 
 * @return Void
**/
void maps_get(struct xdp_program *prog, xdp_maps_t *xdp_maps)
{
    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    xdp_maps->connections = bpf_object__find_map_fd_by_name(obj, "connections");
    xdp_maps->connection_stats = bpf_object__find_map_fd_by_name(obj, "connection_stats");
    xdp_maps->port_punch = bpf_object__find_map_fd_by_name(obj, "port_punch");
    xdp_maps->a2s_info = bpf_object__find_map_fd_by_name(obj, "a2s_info");
    xdp_maps->outgoing = bpf_object__find_map_fd_by_name(obj, "outgoing");
    xdp_maps->edge_ip = bpf_object__find_map_fd_by_name(obj, "edge_ip");
    xdp_maps->stats = bpf_object__find_map_fd_by_name(obj, "stats");
    xdp_maps->xdp_conf = bpf_object__find_map_fd_by_name(obj, "xdp_conf");
    xdp_maps->white_list = bpf_object__find_map_fd_by_name(obj, "white_list");
    xdp_maps->black_list = bpf_object__find_map_fd_by_name(obj, "black_list");
    xdp_maps->validated_clients = bpf_object__find_map_fd_by_name(obj, "validated_clients");
    xdp_maps->xsks_map = bpf_object__find_map_fd_by_name(obj, "xsks_map");
}

/**
 * Inserts edge IP into BPF map.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_insert_edge_ip(config_t *cfg, xdp_maps_t *xdp_maps)
{
    if (xdp_maps == NULL || cfg == NULL)
    {
        return EXIT_FAILURE;
    }

    unsigned int i;
    //unsigned int cpu_cnt = utils_cpu_cnt();

    struct in_addr addr;
    inet_pton(AF_INET, cfg->edge_ip, &addr);

    u32 key = 0;
    be32 val[MAX_CPUS];

    for (i = 0; i < MAX_CPUS; i++)
    {
        val[i] = addr.s_addr;
    }

    return bpf_map_update_elem(xdp_maps->edge_ip, &key, val, BPF_ANY);
}

/**
 * Inserts config connection into connection BPF map.
 * 
 * @param conn_conf A pointer to conf_connection structure.
 * @param xdp_maps A pointer to xdp_maps structure.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_insert_xdp_config(config_t *cfg, xdp_maps_t *xdp_maps)
{
    if (xdp_maps == NULL || cfg == NULL)
    {
        return EXIT_FAILURE;
    }

    unsigned int i;
    //unsigned int cpu_cnt = utils_cpu_cnt();

    struct xdp_config_val xdp_conf[MAX_CPUS];
    memset(&xdp_conf, 0, sizeof(xdp_conf));

    for (i = 0; i < MAX_CPUS; i++)
    {
        xdp_conf[i].allow_edge = cfg->allow_all_edge;
    }

    u32 key = 0;

    return bpf_map_update_elem(xdp_maps->xdp_conf, &key, xdp_conf, BPF_ANY);
}

/**
 * Inserts config connection into connection BPF map.
 * 
 * @param cfg Pointer to CFG structure.
 * @param xdp_maps A pointer to xdp_maps structure.
 * @param conn_conf A pointer to conf_connection structure.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_insert_connection(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t *conf_connection)
{
    if (xdp_maps == NULL || conf_connection == NULL || conf_connection->protocol == NULL || conf_connection->bind_ip == NULL || conf_connection->dest_ip == NULL)
    {
        return EXIT_FAILURE;
    }

    if (!conf_connection->is_enabled)
    {
        return EXIT_SUCCESS;
    }

    unsigned int i;
    //unsigned int cpu_cnt = utils_cpu_cnt();

    // Create key/values.
    struct connection_key key = {0};
    struct connection_key icmp_key = {0};
    struct connection_val val[MAX_CPUS];

    memset(&val, 0, sizeof(val));

    u8 protocol = IPPROTO_UDP;

    if (strncmp(conf_connection->protocol, "tcp", MAX_PROTOCOL_LEN) == 0)
    {
        protocol = IPPROTO_TCP;
    }
    else if (strncmp(conf_connection->protocol, "icmp", MAX_PROTOCOL_LEN) == 0)
    {
        protocol = IPPROTO_ICMP;
    }
    
    // Convert bind IP to NBO (32-bits).
    struct in_addr bind_addr;
    inet_pton(AF_INET, conf_connection->bind_ip, &bind_addr);

    // Convert bind port.
    be16 bind_port = htons(conf_connection->bind_port);

    // Convert destination IP to NBO (32-bits).
    struct in_addr dest_addr;
    inet_pton(AF_INET, conf_connection->dest_ip, &dest_addr);

    // Check and bind destination port.
    be16 dest_port = bind_port;

    if (conf_connection->dest_port > 0)
    {
        dest_port = htons(conf_connection->dest_port);
    }

    // Set key.
    key.protocol = protocol;
    key.bind.ip = bind_addr.s_addr;
    key.bind.port = bind_port;

    icmp_key.protocol = IPPROTO_ICMP;
    icmp_key.bind.ip = bind_addr.s_addr;
    icmp_key.bind.port = 0;

    // Update into outgoing map.
    u8 one[MAX_CPUS];
    struct outgoing_key okey = {0};
    okey.connection_ip = bind_addr.s_addr; 
    okey.machine_ip = dest_addr.s_addr;

    for (i = 0; i < MAX_CPUS; i++)
    {
        one[i] = 1;
    }

    if (bpf_map_update_elem(xdp_maps->outgoing, &okey, &one, BPF_ANY) != 0)
    {
        fprintf(stderr, "WARNING - Could not insert %s:%d => %s into outgoing map!\n", conf_connection->bind_ip, conf_connection->bind_port, conf_connection->dest_ip);
    }

    // Copy over config values to value in map.
    for (i = 0; i < MAX_CPUS; i++)
    {
        val[i].filters = (u32)conf_connection->filters;
        
        val[i].dest_ip = dest_addr.s_addr;
        val[i].dest_port = dest_port;

        val[i].udp_rl.block_time = (u16)conf_connection->udp_rl.block_time;
        val[i].udp_rl.pps = (u64) conf_connection->udp_rl.pps;
        val[i].udp_rl.bps = (u64) conf_connection->udp_rl.bps;

        val[i].tcp_rl.block_time = (u16)conf_connection->tcp_rl.block_time;
        val[i].tcp_rl.pps = (u64) conf_connection->tcp_rl.pps;
        val[i].tcp_rl.bps = (u64) conf_connection->tcp_rl.bps;

        val[i].icmp_rl.block_time = (u16)conf_connection->icmp_rl.block_time;
        val[i].icmp_rl.pps = (u64) conf_connection->icmp_rl.pps;
        val[i].icmp_rl.bps = (u64) conf_connection->icmp_rl.bps;

        val[i].syn_settings.rl.block_time = (u16) conf_connection->syn_settings.rl.block_time;
        val[i].syn_settings.rl.pps = (u64) conf_connection->syn_settings.rl.pps;
        val[i].syn_settings.rl.bps = (u64) conf_connection->syn_settings.rl.bps;

        val[i].cache_settings.A2S_INFO = conf_connection->cache_settings.A2S_INFO;
        val[i].cache_settings.A2S_INFO_time = (u16) conf_connection->cache_settings.A2S_INFO_time;
        val[i].cache_settings.A2S_INFO_global_cache = conf_connection->cache_settings.A2S_INFO_global_cache;
        val[i].cache_settings.A2S_INFO_cache_timeout = (u16) conf_connection->cache_settings.A2S_INFO_cache_timeout;
    }

    struct connection_val tmp[MAX_CPUS];
    u8 changed = 0;

    if (bpf_map_lookup_elem(xdp_maps->connections, &key, &tmp) == 0)
    {
        if (tmp[0].dest_ip != val[0].dest_ip)
        {
            changed = 1;
        }

        if (tmp[0].dest_port != val[0].dest_port)
        {
            changed = 1;
        }

        if (tmp[0].filters != val[0].filters)
        {
            changed = 1;
        }

        if (tmp[0].udp_rl.block_time != val[0].udp_rl.block_time)
        {
            changed = 1;
        }

        if (tmp[0].udp_rl.pps != val[0].udp_rl.pps)
        {
            changed = 1;
        }

        if (tmp[0].udp_rl.bps != val[0].udp_rl.bps)
        {
            changed = 1;
        }

        if (tmp[0].tcp_rl.block_time != val[0].tcp_rl.block_time)
        {
            changed = 1;
        }

        if (tmp[0].tcp_rl.pps != val[0].tcp_rl.pps)
        {
            changed = 1;
        }

        if (tmp[0].tcp_rl.bps != val[0].tcp_rl.bps)
        {
            changed = 1;
        }

        if (tmp[0].icmp_rl.block_time != val[0].icmp_rl.block_time)
        {
            changed = 1;
        }

        if (tmp[0].icmp_rl.pps != val[0].icmp_rl.pps)
        {
            changed = 1;
        }

        if (tmp[0].icmp_rl.bps != val[0].icmp_rl.bps)
        {
            changed = 1;
        }

        if (tmp[0].syn_settings.rl.block_time != val[0].syn_settings.rl.block_time)
        {
            changed = 1;
        }

        if (tmp[0].syn_settings.rl.pps != val[0].syn_settings.rl.pps)
        {
            changed = 1;
        }

        if (tmp[0].syn_settings.rl.bps != val[0].syn_settings.rl.bps)
        {
            changed = 1;
        }

        if (tmp[0].cache_settings.A2S_INFO != val[0].cache_settings.A2S_INFO)
        {
            changed = 1;
        }

        if (tmp[0].cache_settings.A2S_INFO_time !=  val[0].cache_settings.A2S_INFO_time)
        {
            changed = 1;
        }

        if (tmp[0].cache_settings.A2S_INFO_global_cache != val[0].cache_settings.A2S_INFO_global_cache)
        {
            changed = 1;
        }

        if (tmp[0].cache_settings.A2S_INFO_cache_timeout != val[0].cache_settings.A2S_INFO_cache_timeout)
        {
            changed = 1;
        }
    }
    else
    {
        changed = 1;
    }

    if (!changed)
    {
        return EXIT_SUCCESS;
    }

    if (cfg->verbose)
    {
        printf("Adding/updating connection %s:%d => %s:%d\n", conf_connection->bind_ip, conf_connection->bind_port, conf_connection->dest_ip, ntohs(dest_port));
    }

    // Insert into ICMP map.
    bpf_map_update_elem(xdp_maps->connections, &icmp_key, &val, BPF_ANY);

    // Update BPF map and return!
    return bpf_map_update_elem(xdp_maps->connections, &key, &val, BPF_ANY);
}

/**
 * Deletes connection from BPF map.
 * 
 * @param cfg A pointer to CFG structure.
 * @param xdp_maps A pointer to xdp_maps structure.
 * @param conn_conf A pointer to conf_connection structure.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_delete_connection(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t *conf_connection)
{
    if (cfg == NULL || xdp_maps == NULL || conf_connection == NULL)
    {
        return EXIT_FAILURE;
    }

    if (conf_connection->protocol == NULL || conf_connection->bind_ip == NULL)
    {
        return EXIT_FAILURE;
    }

    unsigned int i;

    // Create key/values.
    struct connection_key key = {0};

    u8 protocol = IPPROTO_UDP;

    if (strncmp(conf_connection->protocol, "tcp", MAX_PROTOCOL_LEN) == 0)
    {
        protocol = IPPROTO_TCP;
    }
    else if (strncmp(conf_connection->protocol, "icmp", MAX_PROTOCOL_LEN) == 0)
    {
        protocol = IPPROTO_ICMP;
    }
    
    // Convert bind IP to NBO (32-bits).
    struct in_addr bind_addr;
    inet_pton(AF_INET, conf_connection->bind_ip, &bind_addr);

    // Convert bind port.
    be16 bind_port = htons(conf_connection->bind_port);

    // Set key.
    key.protocol = protocol;
    key.bind.ip = bind_addr.s_addr;
    key.bind.port = bind_port;

    struct connection_val tmp[MAX_CPUS];

    if (bpf_map_lookup_elem(xdp_maps->connections, &key, &tmp) != 0)
    {
        return EXIT_SUCCESS;
    }

    // Set outgoing key.
    if (conf_connection->dest_ip != NULL)
    {
        // Convert destination IP to NBO (32-bits).
        struct in_addr dest_addr;
        inet_pton(AF_INET, conf_connection->dest_ip, &dest_addr);
        struct outgoing_key okey = {0};
        okey.connection_ip = bind_addr.s_addr; 
        okey.machine_ip = dest_addr.s_addr;

        if (bpf_map_delete_elem(xdp_maps->outgoing, &okey) != 0)
        {
            fprintf(stderr, "WARNING - Could not delete %s:%d => %s from outgoing map!\n", conf_connection->bind_ip, conf_connection->bind_port, conf_connection->dest_ip);
        }
    }

    if (cfg->verbose)
    {
        printf("Removing connection %s:%d.\n", (conf_connection->bind_ip != NULL) ? conf_connection->bind_ip : "ERR", conf_connection->bind_port);
    }

    // Update BPF map and return!
    return bpf_map_delete_elem(xdp_maps->connections, &key);
}

/**
 * Inserts a whitelist.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param wl Pointer to whitelist item.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_insert_whitelist(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t *wl)
{
    if (cfg == NULL || xdp_maps == NULL || wl == NULL || strlen(wl->prefix) < 4)
    {
        return EXIT_FAILURE;
    }

    unsigned int i;
    char str[256];
    char *ptr = NULL;

    u32 cidr = 32;

    ptr = strtok(wl->prefix, "\n");

    if (ptr == NULL)
    {
        return EXIT_FAILURE;
    }

    strcpy(str, wl->prefix);

    char *addr = strtok(str, "/");

    if (addr == NULL)
    {
        return EXIT_FAILURE;
    }

    char ip[32];
    strcpy(ip, addr);

    addr = strtok(NULL, "/");

    if (addr != NULL)
    {
        cidr = atoi(addr);
    }

    struct in_addr in_addr;
    inet_pton(AF_INET, ip, &in_addr);

    u32 bit_mask = (~((1 << (32 - cidr)) - 1));
    u32 start = in_addr.s_addr & bit_mask;
    struct lpm_trie_key key = {0};
    key.prefix_len = cidr;
    key.data = start;
    
    u64 tmp = 0;

    if (bpf_map_lookup_elem(xdp_maps->white_list, &key, &tmp) == 0)
    {
        return EXIT_SUCCESS;
    }

    u64 val = ((u64)bit_mask << 32) | start;

    if (cfg->verbose)
    {
        fprintf(stdout, "Whitelisting %s/%d...\n", ip, cidr);
    }

    return bpf_map_update_elem(xdp_maps->white_list, &key, &val, BPF_ANY);
}

/**
 * Deletes a whitelist item.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param wl Pointer to whitelist item.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_delete_whitelist(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t *wl)
{
    if (cfg == NULL || xdp_maps == NULL || wl == NULL || strlen(wl->prefix) < 4)
    {
        return EXIT_FAILURE;
    }

    unsigned int i;
    char str[256];
    char *ptr = NULL;

    u32 cidr = 32;

    ptr = strtok(wl->prefix, "\n");

    if (ptr == NULL)
    {
        return EXIT_FAILURE;
    }

    strcpy(str, wl->prefix);

    char *addr = strtok(str, "/");

    if (addr == NULL)
    {
        return EXIT_FAILURE;
    }

    char ip[32];
    strcpy(ip, addr);

    addr = strtok(NULL, "/");

    if (addr != NULL)
    {
        cidr = atoi(addr);
    }

    struct in_addr in_addr;
    inet_pton(AF_INET, ip, &in_addr);

    u32 bit_mask = (~((1 << (32 - cidr)) - 1));
    u32 start = in_addr.s_addr & bit_mask;
    struct lpm_trie_key key = {0};
    key.prefix_len = cidr;
    key.data = start;

    u64 tmp = 0;

    // Check if blacklist item is already removed or not.
    if (bpf_map_lookup_elem(xdp_maps->white_list, &key, &tmp) != 0)
    {
        return EXIT_SUCCESS;
    }

    if (cfg->verbose)
    {
        fprintf(stdout, "Removing whitelist %s/%d...\n", ip, cidr);
    }

    return bpf_map_delete_elem(xdp_maps->white_list, &key);
}

/**
 * Inserts a blacklist.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param bl Pointer to blacklist item.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_insert_blacklist(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t *bl)
{
    if (cfg == NULL || xdp_maps == NULL || bl == NULL || strlen(bl->prefix) < 4)
    {
        return EXIT_FAILURE;
    }

    unsigned int i;
    char str[256];
    char *ptr = NULL;

    u32 cidr = 32;

    ptr = strtok(bl->prefix, "\n");

    if (ptr == NULL)
    {
        return EXIT_FAILURE;
    }

    strcpy(str, bl->prefix);

    char *addr = strtok(str, "/");

    if (addr == NULL)
    {
        return EXIT_FAILURE;
    }

    char ip[32];
    strcpy(ip, addr);

    addr = strtok(NULL, "/");

    if (addr != NULL)
    {
        cidr = atoi(addr);
    }

    struct in_addr in_addr;
    inet_pton(AF_INET, ip, &in_addr);

    u32 bit_mask = (~((1 << (32 - cidr)) - 1));
    u32 start = in_addr.s_addr & bit_mask;
    struct lpm_trie_key key = {0};
    key.prefix_len = cidr;
    key.data = start;

    u64 tmp = 0;

    if (bpf_map_lookup_elem(xdp_maps->black_list, &key, &tmp) == 0)
    {
        return EXIT_SUCCESS;
    }

    u64 val = ((u64)bit_mask << 32) | start;

    if (cfg->verbose)
    {
        fprintf(stdout, "Adding Blacklist %s/%d...\n", ip, cidr);
    }

    return bpf_map_update_elem(xdp_maps->black_list, &key, &val, BPF_ANY);
}

/**
 * Deletes a blacklist.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param bl Pointer to blacklist item.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_delete_blacklist(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t *bl)
{
    if (cfg == NULL || xdp_maps == NULL || bl == NULL || strlen(bl->prefix) < 4)
    {
        return EXIT_FAILURE;
    }

    unsigned int i;
    char str[256];
    char *ptr = NULL;

    u32 cidr = 32;

    ptr = strtok(bl->prefix, "\n");

    if (ptr == NULL)
    {
        return EXIT_FAILURE;
    }

    strcpy(str, bl->prefix);

    char *addr = strtok(str, "/");

    if (addr == NULL)
    {
        return EXIT_FAILURE;
    }

    char ip[32];
    strcpy(ip, addr);

    addr = strtok(NULL, "/");

    if (addr != NULL)
    {
        cidr = atoi(addr);
    }

    struct in_addr in_addr;
    inet_pton(AF_INET, ip, &in_addr);

    u32 bit_mask = (~((1 << (32 - cidr)) - 1));
    u32 start = in_addr.s_addr & bit_mask;
    struct lpm_trie_key key = {0};
    key.prefix_len = cidr;
    key.data = start;

    u64 tmp = 0;
    
    if (bpf_map_lookup_elem(xdp_maps->black_list, &key, &tmp) != 0)
    {
        return EXIT_SUCCESS;
    }

    if (cfg->verbose)
    {
        fprintf(stdout, "Removing blacklist %s/%d...\n", ip, cidr);
    }

    return bpf_map_delete_elem(xdp_maps->black_list, &key);
}

/**
 * Inserts a port punch.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param pp Pointer to port punch.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_insert_port_punch(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t *pp)
{
    if (cfg == NULL || xdp_maps == NULL || pp == NULL || pp->ip == NULL || pp->service_ip == NULL || pp->dest_ip == NULL)
    {
        return EXIT_FAILURE;
    }

    struct sysinfo sysin;

    sysinfo(&sysin);

    struct in_addr ip_addr;
    inet_pton(AF_INET, pp->ip, &ip_addr);

    u16 i_port = htons(pp->port);

    struct in_addr service_ip_addr;
    inet_pton(AF_INET, pp->service_ip, &service_ip_addr);
    
    u16 service_i_port = htons(pp->service_port);

    struct in_addr dest_ip_addr;
    inet_pton(AF_INET, pp->dest_ip, &dest_ip_addr);

    struct port_punch_key key = {0};
    key.dest.ip = ip_addr.s_addr;
    key.dest.port = i_port;
    key.service.ip = service_ip_addr.s_addr;
    key.service.port = service_i_port;

    struct port_punch_val tmp = {0};

    struct port_punch_val val = {0};
    val.last_seen = sysin.uptime * 1e9;
    val.dest_ip = dest_ip_addr.s_addr;

    if (bpf_map_lookup_elem(xdp_maps->port_punch, &key, &tmp) == 0)
    {
        if (val.dest_ip == tmp.dest_ip)
        {
            return EXIT_SUCCESS;
        }
    }

    if (cfg->verbose)
    {
        fprintf(stdout, "Adding/updating port punch %s:%d => %s:%d (%s)...\n", pp->ip, pp->port, pp->service_ip, pp->service_port, pp->dest_ip);
    }

    return bpf_map_update_elem(xdp_maps->port_punch, &key, &val, BPF_ANY);
}

/**
 * Removes a port punch.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param pp Pointer to port punch.
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_delete_port_punch(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t *pp)
{
    if (cfg == NULL || xdp_maps == NULL || pp == NULL || pp->ip == NULL || pp->service_ip == NULL)
    {
        return EXIT_FAILURE;
    }

    struct in_addr ip_addr;
    inet_pton(AF_INET, pp->ip, &ip_addr);

    u16 i_port = htons(pp->port);

    struct in_addr service_ip_addr;
    inet_pton(AF_INET, pp->service_ip, &service_ip_addr);
    
    u16 service_i_port = htons(pp->service_port);

    struct port_punch_key key = {0};
    key.dest.ip = ip_addr.s_addr;
    key.dest.port = i_port;
    key.service.ip = service_ip_addr.s_addr;
    key.service.port = service_i_port;

    struct port_punch_val tmp = {0};

    if (bpf_map_lookup_elem(xdp_maps->port_punch, &key, &tmp) != 0)
    {
        return EXIT_SUCCESS;
    }

    if (cfg->verbose)
    {
        fprintf(stdout, "Removing port punch %s:%d => %s:%d...\n", pp->ip, pp->port, pp->service_ip, pp->service_port);
    }

    return bpf_map_delete_elem(xdp_maps->port_punch, &key);
}

/**
 * Inserts a validated client.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param vc Pointer to validated client.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_insert_validated_client(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t *vc)
{
    if (cfg == NULL || xdp_maps == NULL || vc == NULL || vc->src_ip == NULL || vc->dst_ip == NULL)
    {
        return EXIT_FAILURE;
    }

    struct sysinfo sysin;

    sysinfo(&sysin);

    struct in_addr src_ip_addr;
    inet_pton(AF_INET, vc->src_ip, &src_ip_addr);

    u16 i_src_port = htons(vc->src_port);

    struct in_addr dst_ip_addr;
    inet_pton(AF_INET, vc->dst_ip, &dst_ip_addr);
    
    u16 i_dst_port = htons(vc->dst_port);


    struct client_connection_key key = {0};
    key.src.ip = src_ip_addr.s_addr;
    key.src.port = i_src_port;
    key.dst.ip = dst_ip_addr.s_addr;
    key.dst.port = i_dst_port;

    struct client_validated_val tmp = {0};

    struct client_validated_val val = {0};
    val.last_seen = sysin.uptime * 1e9;

    if (cfg->verbose)
    {
        fprintf(stdout, "Adding/updating validated client %s:%d => %s:%d...\n", vc->src_ip, vc->src_port, vc->dst_ip, vc->dst_port);
    }

    return bpf_map_update_elem(xdp_maps->validated_clients, &key, &val, BPF_ANY);
}

/**
 * Removes a validated client.
 * 
 * @param cfg A pointer to the config structure.
 * @param xdp_maps A pointer to the xdp_maps structure.
 * @param vc Pointer to validated client.
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int maps_delete_validated_client(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t *vc)
{
    if (cfg == NULL || xdp_maps == NULL || vc == NULL || vc->src_ip == NULL || vc->dst_ip == NULL)
    {
        return EXIT_FAILURE;
    }

    struct in_addr src_ip_addr;
    inet_pton(AF_INET, vc->src_ip, &src_ip_addr);

    u16 i_src_port = htons(vc->src_port);

    struct in_addr dst_ip_addr;
    inet_pton(AF_INET, vc->dst_ip, &dst_ip_addr);
    
    u16 i_dst_port = htons(vc->dst_port);

    struct client_connection_key key = {0};
    key.src.ip = src_ip_addr.s_addr;
    key.src.port = i_src_port;
    key.dst.ip = dst_ip_addr.s_addr;
    key.dst.port = i_dst_port;

    struct port_punch_val tmp = {0};

    if (bpf_map_lookup_elem(xdp_maps->validated_clients, &key, &tmp) != 0)
    {
        return EXIT_SUCCESS;
    }

    if (cfg->verbose)
    {
        fprintf(stdout, "Removing validated client %s:%d => %s:%d...\n", vc->src_ip, vc->src_port, vc->dst_ip, vc->dst_port);
    }

    return bpf_map_delete_elem(xdp_maps->validated_clients, &key);
}

/**
 * Updates global stat counters on file system.
 * 
 * @param cfg A pointer to config structure.
 * @param xdp_maps A pointer to xdp_maps structure.
 * 
 * @return Void
**/
void maps_calc_stats(config_t *cfg, xdp_maps_t *xdp_maps)
{
    if (!cfg->calc_stats)
    {
        return;
    }

    FILE *fp = fopen("/etc/kilimanjaro/stats", "w");

    if (!fp)
    {
        if (cfg->verbose)
        {
            fprintf(stderr, "ERROR - Error opening /etc/kilimanjaro/stats\n");
        }

        return;
    }

    unsigned int i;
    unsigned int cpu_cnt = get_nprocs_conf();

    char buffer[2048];

    u32 key = 0;
    struct stats_val stats[MAX_CPUS];

    if (bpf_map_lookup_elem(xdp_maps->stats, &key, stats) != 0)
    {
        if (cfg->verbose)
        {
            fprintf(stderr, "ERROR - Could not lookup stats map (FD => %d)!\n", xdp_maps->stats);
        }

        memset(stats, 0, sizeof(stats));

        bpf_map_update_elem(xdp_maps->stats, &key, stats, BPF_ANY);

        fclose(fp);

        return;
    }

    u64 bla_pk = 0;
    static u64 bla_pk_ps = 0;
    static u64 bla_pk_lu = 0;

    u64 whi_pk = 0;
    static u64 whi_pk_ps = 0;
    static u64 whi_pk_lu = 0;

    u64 blo_pk = 0;
    static u64 blo_pk_ps = 0;
    static u64 blo_pk_lu = 0;

    u64 fwd_pk = 0;
    static u64 fwd_pk_ps = 0;
    static u64 fwd_pk_lu = 0;

    u64 fwdo_pk = 0;
    static u64 fwdo_pk_ps = 0;
    static u64 fwdo_pk_lu = 0;

    u64 bad_pk = 0;
    static u64 bad_pk_ps = 0;
    static u64 bad_pk_lu = 0;

    u64 pass_pk = 0;
    static u64 pass_pk_ps = 0;
    static u64 pass_pk_lu = 0;

    u64 a2rp_pk = 0;
    static u64 a2rp_pk_ps = 0;
    static u64 a2rp_pk_lu = 0;

    u64 a2rs_pk = 0;
    static u64 a2rs_pk_ps = 0;
    static u64 a2rs_pk_lu = 0;

    u64 dro_pk = 0;
    static u64 dro_pk_ps = 0;
    static u64 dro_pk_lu = 0;

    u64 drc_pk = 0;
    static u64 drc_pk_ps = 0;
    static u64 drc_pk_lu = 0;

    u64 bla_by = 0;
    static u64 bla_by_ps = 0;
    static u64 bla_by_lu = 0;

    u64 whi_by = 0;
    static u64 whi_by_ps = 0;
    static u64 whi_by_lu = 0;

    u64 blo_by = 0;
    static u64 blo_by_ps = 0;
    static u64 blo_by_lu = 0;
    
    u64 fwd_by = 0;
    static u64 fwd_by_ps = 0;
    static u64 fwd_by_lu = 0;

    u64 fwdo_by = 0;
    static u64 fwdo_by_ps = 0;
    static u64 fwdo_by_lu = 0;

    u64 bad_by = 0;
    static u64 bad_by_ps = 0;
    static u64 bad_by_lu = 0;

    u64 pass_by = 0;
    static u64 pass_by_ps = 0;
    static u64 pass_by_lu = 0;

    u64 a2rp_by = 0;
    static u64 a2rp_by_ps = 0;
    static u64 a2rp_by_lu = 0;

    u64 a2rs_by = 0;
    static u64 a2rs_by_ps = 0;
    static u64 a2rs_by_lu = 0;

    u64 dro_by = 0;
    static u64 dro_by_ps = 0;
    static u64 dro_by_lu = 0;

    u64 drc_by = 0;
    static u64 drc_by_ps = 0;
    static u64 drc_by_lu = 0;

    for (i = 0; i < cpu_cnt; i++)
    {
        bla_pk += stats[i].bla_pckts_total;
        bla_by += stats[i].bla_bytes_total;

        whi_pk += stats[i].whi_pckts_total;
        whi_by += stats[i].whi_bytes_total;

        blo_pk += stats[i].blo_pckts_total;
        blo_by += stats[i].blo_bytes_total;

        fwd_pk += stats[i].fwd_pckts_total;
        fwd_by += stats[i].fwd_bytes_total;

        fwdo_pk += stats[i].fwd_out_pckts_total;
        fwdo_by += stats[i].fwd_out_bytes_total;

        pass_pk += stats[i].pass_pckts_total;
        pass_by += stats[i].pass_bytes_total;

        bad_pk += stats[i].bad_pckts_total;
        bad_by += stats[i].bad_bytes_total;
    
        a2rp_pk += stats[i].a2s_reply_pckts_total;
        a2rp_by += stats[i].a2s_reply_bytes_total;
    
        a2rs_pk += stats[i].a2s_response_pckts_total;
        a2rs_by += stats[i].a2s_response_bytes_total;

        dro_pk += stats[i].drop_other_pckts_total;
        dro_by += stats[i].drop_other_bytes_total;

        drc_pk += stats[i].drop_conn_pckts_total;
        drc_by += stats[i].drop_conn_bytes_total;
    }

    // Receive per second stats.
    bla_pk_ps = bla_pk - bla_pk_lu;
    bla_pk_lu = bla_pk;

    whi_pk_ps = whi_pk - whi_pk_lu;
    whi_pk_lu = whi_pk;

    blo_pk_ps = blo_pk - blo_pk_lu;
    blo_pk_lu = blo_pk;

    fwd_pk_ps = fwd_pk - fwd_pk_lu;
    fwd_pk_lu = fwd_pk;

    fwdo_pk_ps = fwdo_pk - fwdo_pk_lu;
    fwdo_pk_lu = fwdo_pk;

    pass_pk_ps = pass_pk - pass_pk_lu;
    pass_pk_lu = pass_pk;

    bad_pk_ps = bad_pk - bad_pk_lu;
    bad_pk_lu = bad_pk;

    a2rp_pk_ps = a2rp_pk - a2rp_pk_lu;
    a2rp_pk_lu = a2rp_pk;

    a2rs_pk_ps = a2rs_pk - a2rs_pk_lu;
    a2rs_pk_lu = a2rs_pk;
    
    dro_pk_ps = dro_pk - dro_pk_lu;
    dro_pk_lu = dro_pk;

    drc_pk_ps = drc_pk - drc_pk_lu;
    drc_pk_lu = drc_pk;

    bla_by_ps = bla_by - bla_by_lu;
    bla_by_lu = bla_by;

    whi_by_ps = whi_by - whi_by_lu;
    whi_by_lu = whi_by;

    blo_by_ps = blo_by - blo_by_lu;
    blo_by_lu = blo_by;

    fwd_by_ps = fwd_by - fwd_by_lu;
    fwd_by_lu = fwd_by;

    fwdo_by_ps = fwdo_by - fwdo_by_lu;
    fwdo_by_lu = fwdo_by;

    pass_by_ps = pass_by - pass_by_lu;
    pass_by_lu = pass_by;

    bad_by_ps = bad_by - bad_by_lu;
    bad_by_lu = bad_by;

    a2rp_by_ps = a2rp_by - a2rp_by_lu;
    a2rp_by_lu = a2rp_by;

    a2rs_by_ps = a2rs_by - a2rs_by_lu;
    a2rs_by_lu = a2rs_by;

    dro_by_ps = dro_by - dro_by_lu;
    dro_by_lu = dro_by;

    drc_by_ps = drc_by - drc_by_lu;
    drc_by_lu = drc_by;

    double cpu_load[cpu_cnt];
    getloadavg(cpu_load, 1);
    u16 cpu = (cpu_load[0] * 100) / cpu_cnt;

    // Format buffer.
    snprintf(buffer, sizeof(buffer), "bla_pk:%llu\nbla_pps:%llu\nbla_by:%llu\nbla_bps:%llu\n" \
    "whi_pk:%llu\nwhi_pps:%llu\nwhi_by:%llu\nwhi_bps:%llu\n" \
    "blo_pk:%llu\nblo_pps:%llu\nblo_by:%llu\nblo_bps:%llu\n" \
    "fwd_pk:%llu\nfwd_pps:%llu\nfwd_by:%llu\nfwd_bps:%llu\n" \
    "fwdo_pk:%llu\nfwdo_pps:%llu\nfwdo_by:%llu\nfwdo_bps:%llu\n" \
    "pass_pk:%llu\npass_pps:%llu\npass_by:%llu\npass_bps:%llu\n" \
    "bad_pk:%llu\nbad_pps:%llu\nbad_by:%llu\nbad_bps:%llu\n" \
    "a2rp_pk:%llu\na2rp_pps:%llu\na2rp_by:%llu\na2rp_bps:%llu\n" \
    "a2rs_pk:%llu\na2rs_pps:%llu\na2rs_by:%llu\na2rs_bps:%llu\n" \
    "dro_pk:%llu\ndro_pps:%llu\ndro_by:%llu\ndro_bps:%llu\n" \
    "drc_pk:%llu\ndrc_pps:%llu\ndrc_by:%llu\ndrc_bps:%llu\n" \
    "cpu_load:%d",
    bla_pk, bla_pk_ps, bla_by, bla_by_ps,
    whi_pk, whi_pk_ps, whi_by, whi_by_ps,
    blo_pk, blo_pk_ps, blo_by, blo_by_ps,
    fwd_pk, fwd_pk_ps, fwd_by, fwd_by_ps,
    fwdo_pk, fwdo_pk_ps, fwdo_by, fwdo_by_ps,
    pass_pk, pass_pk_ps, pass_by, pass_by_ps,
    bad_pk, bad_pk_ps, bad_by, bad_by_ps,
    a2rp_pk, a2rp_pk_ps, a2rp_by, a2rp_by_ps,
    a2rs_pk, a2rs_pk_ps, a2rs_by, a2rs_by_ps,
    dro_pk, dro_pk_ps, dro_by, dro_by_ps,
    drc_pk, drc_pk_ps, drc_by, drc_by_ps, cpu);

    fprintf(fp, "%s", buffer);

    fclose(fp);
}

/**
 * Calculates connection-specific stats
 * 
 * @param cfg A pointer to config structure.
 * @param xdp_maps A pointer to xdp_maps structure.
 * 
 * @return Void
**/
void maps_calc_conn_stats(config_t *cfg, xdp_maps_t *xdp_maps)
{
    if (!cfg->calc_stats)
    {
        return;
    }

    struct connection_key key = {0};
    struct connection_key prev_key = {0};
    int delete_previous = 0;
    struct connection_stats_val stats[MAX_CPUS];

    while(utils_bpf_map_get_next_key_and_delete(xdp_maps->connection_stats, &prev_key, &key, &delete_previous) == 0)
    {
        if (bpf_map_lookup_elem(xdp_maps->connection_stats, &key, &stats) < 0)
        {
            prev_key = key;

            continue;
        }

        // Retrieve IP string.
        struct in_addr in_addr;
        in_addr.s_addr = key.bind.ip;

        char *ip_str = NULL;
        ip_str = inet_ntoa(in_addr);

        if (ip_str == NULL)
        {
            continue;
        }

        // Format path.
        char path_buffer[64];
        snprintf(path_buffer, sizeof(path_buffer), "%s%d_%s_%d", "/etc/kilimanjaro/connections/", key.protocol, ip_str, ntohs(key.bind.port));

        FILE *fp = fopen(path_buffer, "w");

        if (!fp)
        {
            if (cfg->verbose)
            {
                fprintf(stderr, "ERROR - Error opening %s.\n", path_buffer);
            }

            return;
        }

        unsigned int i;
        unsigned int cpu_cnt = get_nprocs_conf();

        char buffer[128];

        u64 pk = 0;
        u64 pk_ps = 0;
        u64 pk_lu = 0;

        u64 by = 0;
        u64 by_ps = 0;
        u64 by_lu = 0;

        for (i = 0; i < cpu_cnt; i++)
        {
            pk += stats[i].pckts;
            by += stats[i].bytes;
        }

        // Receive stats.
        pk_ps = pk - pk_lu;
        pk_lu = pk;

        by_ps = by - by_lu;
        by_lu = by;

        // Format buffer.
        snprintf(buffer, sizeof(buffer), "pk:%llu\npps:%llu\nby:%llu\nbps:%llu", pk, pk_ps, by, by_ps);

        fprintf(fp, "%s", buffer);

        fclose(fp);
    }
}

/**
 * Scans port map and pushes port punches to back-bone.
 * 
 * @param cfg A pointer to config structure.
 * @param xdp_maps A pointer to xdp_maps structure.
 * 
 * @return Void
**/
void maps_push_port_punches(config_t *cfg, xdp_maps_t *xdp_maps)
{
    struct port_punch_key key = {0};
    struct port_punch_key prev_key = {0};
    int delete_previous = 0;
    struct port_punch_val val = {0};

    struct sysinfo sys = {0};

    while(utils_bpf_map_get_next_key_and_delete(xdp_maps->port_punch, &prev_key, &key, &delete_previous) == 0)
    {
        if (bpf_map_lookup_elem(xdp_maps->port_punch, &key, &val) < 0)
        {
            prev_key = key;

            continue;
        }

        sysinfo(&sys);
        u64 now = sys.uptime * 1e9;

        u64 next = val.last_seen + (3 * 1e9);

        // Skip any that aren't within the last couple of seconds of last seen.
        if ((next > 0 && now > 0 && next < now) || !val.xdp_added)
        {
            prev_key = key;
            
            continue;
        }

        // Retrieve port punch information.
        struct in_addr ip_addr;
        ip_addr.s_addr = key.dest.ip;
        char *ip = strdup(inet_ntoa(ip_addr));

        unsigned short port = (unsigned short)ntohs(key.dest.port);

        struct in_addr service_addr;
        service_addr.s_addr = key.service.ip;
        char *service_ip = strdup(inet_ntoa(service_addr));

        unsigned short service_port = (unsigned short)ntohs(key.service.port);

        struct in_addr dest_addr;
        dest_addr.s_addr = val.dest_ip;
        char *dest_ip = strdup(inet_ntoa(dest_addr));

#ifdef PORTPUNCH_DEBUG
        if (ip == NULL || service_ip == NULL || dest_ip == NULL)
        {
            if (ip == NULL)
            {
                fprintf(stderr, "[PP_DEBUG] maps_push_port_punches() :: ip is NULL.\n");
            }
            
            if (service_ip == NULL)
            {
                fprintf(stderr, "[PP_DEBUG] maps_push_port_punches() :: service_ip is NULL.\n");
            }

            if (dest_ip == NULL)
            {
                fprintf(stderr, "[PP_DEBUG] maps_push_port_punches() :: dest_ip is NULL.\n");
            }
        }
        else
        {
            fprintf(stderr, "[PP_DEBUG] maps_push_port_punches() :: Received port punch that fits timeframe.\n");
        }
#endif

        if (ip == NULL || service_ip == NULL || dest_ip == NULL)
        {
            prev_key = key;

            continue;
        }

#ifdef PORTPUNCH_DEBUG
        fprintf(stderr, "[PP_DEBUG] maps_push_port_punches() :: Parsing port punch =.\n");
#endif


        int error = 0;

        if ((error = config_parse_and_send_port_punch(cfg, ip, port, service_ip, service_port, dest_ip)) > 0)
        {
            if (cfg->verbose)
            {
                if (!val.printed)
                {
                    fprintf(stderr, "Successfully pushed port punch %s:%d => %s:%d (%s)! XDP Added => %s.\n", ip, port, service_ip, service_port, dest_ip, val.xdp_added ? "True" : "False");
                    val.printed = 1;
                }
            }

            bpf_map_update_elem(xdp_maps->port_punch, &key, &val, BPF_ANY);
        }
        else
        {
            fprintf(stderr, "[ERROR] Failed to push port punch %s:%d => %s:%d (%s)! XDP Added => %s. Error Number = %d. Errno => %d. Error => %s.\n", ip, port, service_ip, service_port, dest_ip, val.xdp_added ? "True" : "False", error, errno, strerror(errno));
        }

        // Free.
        if (ip != NULL)
        {
            free(ip);
        }

        if (service_ip != NULL)
        {
            free(service_ip);
        }

        if (dest_ip != NULL)
        {
            free(dest_ip);
        }

        prev_key = key;
    }
}

/**
 * Scans validated connections map and pushes
 * 
 * @param cfg A pointer to config structure.
 * @param xdp_maps A pointer to xdp_maps structure.
 * 
 * @return Void
**/
void maps_push_validated_connections(config_t *cfg, xdp_maps_t *xdp_maps)
{
    struct client_connection_key key = {0};
    struct client_connection_key prev_key = {0};
    int delete_previous = 0;
    struct client_validated_val val = {0};
    struct sysinfo sys = {0};

    while(utils_bpf_map_get_next_key_and_delete(xdp_maps->validated_clients, &prev_key, &key, &delete_previous) == 0)
    {
        if (bpf_map_lookup_elem(xdp_maps->validated_clients, &key, &val) < 0)
        {
            prev_key = key;

            continue;
        }

        sysinfo(&sys);
        u64 now = sys.uptime * 1e9;
        u64 next = val.last_seen + (3 * 1e9);

        // Skip any that aren't within the last couple of seconds of last seen.
        if ((next > 0 && now > 0 && next < now) || !val.xdp_added)
        {
            prev_key = key;

            continue;
        }

        // Retrieve port punch information.
        struct in_addr ip_addr;
        ip_addr.s_addr = key.src.ip;
        char *src_ip = strdup(inet_ntoa(ip_addr));

        unsigned short src_port = (unsigned short)ntohs(key.src.port);

        ip_addr.s_addr = key.dst.ip;
        char *dst_ip = strdup(inet_ntoa(ip_addr));

        unsigned short dst_port = (unsigned short)ntohs(key.dst.port);

        if (src_ip == NULL || dst_ip == NULL)
        {
            prev_key = key;

            continue;
        }

        int error = 0;

        if ((error = config_parse_and_send_validated_connection(cfg, src_ip, src_port, dst_ip, dst_port)) > 0)
        {
            if (cfg->verbose)
            {
                if (!val.printed)
                {
                    fprintf(stderr, "Successfully pushed validated client %s:%d => %s:%d! XDP Added => %s.\n", src_ip, src_port, dst_ip, dst_port, val.xdp_added ? "True" : "False");
                    val.printed = 1;
                }
            }

            bpf_map_update_elem(xdp_maps->validated_clients, &key, &val, BPF_ANY);
        }
        else
        {
            fprintf(stderr, "[ERROR] Failed to push validated client %s:%d => %s:%d! XDP Added => %s. Error Number = %d. Errno =>  %d. Error => %s.\n", src_ip, src_port, dst_ip, dst_port, val.xdp_added ? "True" : "False", error, errno, strerror(errno));
        }

        // Free.
        if (src_ip != NULL)
        {
            free(src_ip);
        }

        if (dst_ip != NULL)
        {
            free(dst_ip);
        }

        prev_key = key;
    }
}