#include "config.h"

/**
 * Sets config defaults in structure.
 * 
 * @param cfg Pointer to config_t variable.
 * 
 * @return Void
**/
void config_set_defaults(config_t *cfg)
{
    cfg->interface = "ens18";
    cfg->force_mode = 0;
    cfg->socket_count = 0;
    cfg->verbose = 0;
    cfg->calc_stats = 1;
    cfg->zero_copy = 0;
    cfg->need_wakeup = 1;
    cfg->batch_size = 64;
    cfg->queue_is_static = 0;
    cfg->allow_all_edge = 1;

    // Wipe everything if they aren't already.
    config_connection_wipe_all(cfg);
    config_whitelist_wipe_all(cfg);
    config_blacklist_wipe_all(cfg);
    config_port_punch_wipe_all(cfg);
    config_validated_client_wipe_all(cfg);
}

/**
 * Receive default IP address of interface and stores it in edge IP.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
**/
void config_set_default_edge_ip(config_t *cfg)
{
    struct ifaddrs *if_ap, *if_a;
    struct sockaddr_in *sa;
    char *addr;

    getifaddrs(&if_ap);

    for (if_a = if_ap; if_a; if_a = if_a->ifa_next)
    {
        if (if_a->ifa_addr && if_a->ifa_addr->sa_family == AF_INET && strcmp(if_a->ifa_name, cfg->interface) == 0)
        {
            sa = (struct sockaddr_in *)if_a->ifa_addr;

            addr = inet_ntoa(sa->sin_addr);

            cfg->edge_ip = addr;

            break;
        } 
    } 
}

/**
 * Parses JSON config file.
 * 
 * @param file Path to CFG file.
 * @param cfg Pointer to config_t variable.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse(const char *file, config_t *cfg)
{
    // Load JSON from file and check.
    json_object *root = json_object_from_file(file);

    if (root == NULL)
    {
        return EXIT_FAILURE;
    }

    // Before parsing, set the config defaults.
    config_set_defaults(cfg);

    // Parse the JSON.
    config_parse_json(json_object_to_json_string(root), cfg, NULL);

    // Free the JSON object.
    json_object_put(root);

    return EXIT_SUCCESS;
}

/**
 * Wipes specific connection.
 * 
 * @param connection Pointer to connection.
 * 
 * @return Void
**/
void config_connection_wipe(conf_connection_t *connection)
{
    memset(connection, 0, sizeof(conf_connection_t));
}

/**
 * Wipes all connections.
 * 
 * @param cfg A pointer to the CFG structure.
 * 
 * @return Void
**/
void config_connection_wipe_all(config_t *cfg)
{
    memset(cfg->connections, 0, sizeof(cfg->connections));
}

/**
 * Sets config connection to defaults.
 * 
 * @param connections Pointer to connection.
 * 
 * @return Void
**/
void config_connection_set_defaults(conf_connection_t *connection)
{
    connection->is_enabled = 1;
    connection->protocol = "udp";

    connection->cache_settings.A2S_INFO_time = DEFAULT_A2S_CACHE_TIME;
    connection->cache_settings.A2S_INFO_cache_timeout = DEFAULT_A2S_CACHE_TIMEOUT;
}

/**
 * Finds next available connection index.
 * 
 * @param cfg Pointer to config_t pointer.
 * 
 * @return Index to next available connection index or -1 on failure.
**/
int config_connection_find_index(config_t *cfg)
{
    int ret = -1;

    unsigned int i;

    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (!cfg->connections[i].is_set)
        {
            ret = i;

            break;
        }
    }

    return ret;
}

/**
 * Finds connection.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param protocol The protocol.
 * @param bind_ip The bind IP.
 * @param bind_port The bind port.
 * 
 * @return A pointer to the structure or NULL on not found.
**/
conf_connection_t *config_connection_find(config_t *cfg, const char *protocol, const char *bind_ip, unsigned short bind_port)
{
    conf_connection_t *ret = NULL;

    if (protocol == NULL || bind_ip == NULL)
    {
        return ret;
    }

    unsigned int i;

    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        conf_connection_t *conn = &cfg->connections[i];

        if (conn->protocol == NULL)
        {
            continue;
        }

        if (conn->bind_ip == NULL)
        {
            continue;
        }

        if (strcmp(protocol, conn->protocol) == 0 && strcmp(bind_ip, conn->bind_ip) == 0 && bind_port == conn->bind_port)
        {
            ret = conn;

            break;
        }
    }

    return ret;
}

/**
 * Add/updates a connection.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_connection Connection to add.
 * 
 * @return A pointer to the new/updated structure or NULL on failure.
**/
conf_connection_t *config_connection_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t conf_connection)
{
    conf_connection_t *conn = NULL;

    if (cfg == NULL)
    {
        return conn;
    }

    conn = config_connection_find(cfg, conf_connection.protocol, conf_connection.bind_ip, conf_connection.bind_port);

    u8 not_new = 0;

    if (conn != NULL)
    {
        not_new = 1;
    }
    else
    {
        int idx = config_connection_find_index(cfg);

        if (idx < 0)
        {
            return conn;
        }

        // Retrieve new connection.
        conn = &cfg->connections[idx];

        if (conn == NULL)
        {
            return conn;
        }

        // Set defaults.
        config_connection_set_defaults(conn);

        if (conf_connection.protocol != NULL)
        {
            conn->protocol = conf_connection.protocol;
        }

        conn->is_set = 1;

        conn->bind_ip = conf_connection.bind_ip;
        conn->bind_port = conf_connection.bind_port;
    }

    // Update
    u8 changed = 0;

    if (conn->is_enabled != conf_connection.is_enabled)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: Enabled Set To => %s.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.is_enabled ? "True" : "False");
        }

        conn->is_enabled = conf_connection.is_enabled;
    }

    if (conn->dest_ip == NULL || strcmp(conn->dest_ip, conf_connection.dest_ip) != 0)
    {
        changed = 1;
        
        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: Destination IP Set To => %s.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.dest_ip);
        }


        conn->dest_ip = conf_connection.dest_ip;
    }

    if (conn->dest_port != conf_connection.dest_port)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: Destination Port Set To => %u.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.dest_port);
        }

        conn->dest_port = conf_connection.dest_port;
    }

    if (conn->filters != conf_connection.filters)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            if (conf_connection.filters & FILTER_TYPE_SRCDS)
            {
                fprintf(stdout, "[CFG] Conn %s:%d (%s) :: Filter SRCDS Set.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol);
            }

            if  (conf_connection.filters & FILTER_TYPE_RUST)
            {
                fprintf(stdout, "[CFG] Conn %s:%d (%s) :: Filter Rust Set.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol);
            }

            if  (conf_connection.filters & FILTER_TYPE_GMOD)
            {
                fprintf(stdout, "[CFG] Conn %s:%d (%s) :: Filter GMOD Challenge Set.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol);
            }
        }

        // Check filters and assign defaults before parsing individual PPS/BPS.
        if (conf_connection.filters & FILTER_TYPE_SRCDS)
        {
            conn->udp_rl.pps = FILTER_SCRDS_UDP_PPS_DEFAULT;
            conn->udp_rl.block_time = 30;

            conn->cache_settings.A2S_INFO = 1;
            conn->cache_settings.A2S_INFO_time = DEFAULT_A2S_CACHE_TIME;
        }

        if (conf_connection.filters & FILTER_TYPE_RUST)
        {
            conn->udp_rl.pps = FILTER_RUST_UDP_PPS_DEFAULT;
            conn->udp_rl.block_time = 30;

            conn->cache_settings.A2S_INFO = 1;
            conn->cache_settings.A2S_INFO_time = DEFAULT_A2S_CACHE_TIME;
        }

        if (conf_connection.filters & FILTER_TYPE_GMOD)
        {
            conn->udp_rl.pps = FILTER_GMOD_UDP_PPS_DEFAULT;
            conn->udp_rl.block_time = 30;

            conn->cache_settings.A2S_INFO = 1;
            conn->cache_settings.A2S_INFO_time = DEFAULT_A2S_CACHE_TIME;
        }

        conn->filters = conf_connection.filters;
    }

    if (conn->udp_rl.block_time != conf_connection.udp_rl.block_time)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: UDP Block Time Set To => %u.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.udp_rl.block_time);
        }

        conn->udp_rl.block_time = conf_connection.udp_rl.block_time;
    }

    if (conn->udp_rl.pps != conf_connection.udp_rl.pps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: UDP PPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.udp_rl.pps);
        }

        conn->udp_rl.pps = conf_connection.udp_rl.pps;
    }

    if (conn->udp_rl.bps != conf_connection.udp_rl.bps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: UDP BPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.udp_rl.bps);
        }

        conn->udp_rl.bps = conf_connection.udp_rl.bps;
    }

    if (conn->tcp_rl.block_time != conf_connection.tcp_rl.block_time)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: TCP Block Time Set To => %u.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.tcp_rl.block_time);
        }

        conn->tcp_rl.block_time = conf_connection.tcp_rl.block_time;
    }

    if (conn->tcp_rl.pps != conf_connection.tcp_rl.pps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: TCP PPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.tcp_rl.pps);
        }

        conn->tcp_rl.pps = conf_connection.tcp_rl.pps;
    }

    if (conn->tcp_rl.bps != conf_connection.tcp_rl.bps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: TCP BPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.tcp_rl.bps);
        }

        conn->tcp_rl.bps = conf_connection.tcp_rl.bps;
    }

    if (conn->icmp_rl.block_time != conf_connection.icmp_rl.block_time)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: ICMP Block Time Set To => %u.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.icmp_rl.block_time);
        }

        conn->icmp_rl.block_time = conf_connection.icmp_rl.block_time;
    }

    if (conn->icmp_rl.pps != conf_connection.icmp_rl.pps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: ICMP PPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.icmp_rl.pps);
        }

        conn->icmp_rl.pps = conf_connection.icmp_rl.pps;
    }

    if (conn->icmp_rl.bps != conf_connection.icmp_rl.bps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: ICMP BPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.icmp_rl.bps);
        }

        conn->icmp_rl.bps = conf_connection.icmp_rl.bps;
    }

    if (conn->syn_settings.rl.block_time != conf_connection.syn_settings.rl.block_time)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: SYN Block Time Set To => %u.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.syn_settings.rl.block_time);
        }

        conn->syn_settings.rl.block_time = conf_connection.syn_settings.rl.block_time;
    }

    if (conn->syn_settings.rl.pps != conf_connection.syn_settings.rl.pps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: SYN PPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.syn_settings.rl.pps);
        }

        conn->syn_settings.rl.pps = conf_connection.syn_settings.rl.pps;
    }

    if (conn->syn_settings.rl.bps != conf_connection.syn_settings.rl.bps)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: SYN BPS Set To => %llu.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.syn_settings.rl.bps);
        }

        conn->syn_settings.rl.bps = conf_connection.syn_settings.rl.bps;
    }

    if (conn->cache_settings.A2S_INFO != conf_connection.cache_settings.A2S_INFO)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: A2S_INFO Cache Set To => %s.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, (conf_connection.cache_settings.A2S_INFO) ? "True" : "False");
        }

        conn->cache_settings.A2S_INFO = conf_connection.cache_settings.A2S_INFO;
    }

    if (conn->cache_settings.A2S_INFO_time != conf_connection.cache_settings.A2S_INFO_time)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: A2S_INFO Cache Time Set To => %u.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.cache_settings.A2S_INFO_time);
        }

        conn->cache_settings.A2S_INFO_time = conf_connection.cache_settings.A2S_INFO_time;
    }

    if (conn->cache_settings.A2S_INFO_global_cache != conf_connection.cache_settings.A2S_INFO_global_cache)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: A2S_INFO Global Cache Set To => %s.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, (conf_connection.cache_settings.A2S_INFO_global_cache) ? "True" : "False");
        }

        conn->cache_settings.A2S_INFO_global_cache = conf_connection.cache_settings.A2S_INFO_global_cache;
    }

    if (conn->cache_settings.A2S_INFO_cache_timeout != conf_connection.cache_settings.A2S_INFO_cache_timeout)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Conn %s:%d (%s) :: A2S_INFO Cache Timeout Set To => %u.\n", conf_connection.bind_ip, conf_connection.bind_port, conf_connection.protocol, conf_connection.cache_settings.A2S_INFO_cache_timeout);
        }

        conn->cache_settings.A2S_INFO_cache_timeout = conf_connection.cache_settings.A2S_INFO_cache_timeout;
    }

    // If we've changed a value, update map.
    if ((!not_new || changed) && xdp_maps != NULL)
    {
        maps_insert_connection(cfg, xdp_maps, conn);
    }

    return conn;
}

/**
 * Removes a connection.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_connection Connection to delete.
 * 
 * @return 0 on success or 1 on failure.
**/
int config_connection_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_connection_t conf_connection)
{
    int ret = EXIT_FAILURE;
    
    conf_connection_t *conn = config_connection_find(cfg, conf_connection.protocol, conf_connection.bind_ip, conf_connection.bind_port);

    if (conn != NULL)
    {
        // First delete the BPF element.
        maps_delete_connection(cfg, xdp_maps, conn);

        // Wipe connection.
        config_connection_wipe(conn);

        ret = EXIT_SUCCESS;
    }

    return ret;
}

/**
 * Wipes specific whitelist.
 * 
 * @param whitelist Pointer to whitelist.
 * 
 * @return Void
**/
void config_whitelist_wipe(conf_whitelist_t *whitelist)
{
    memset(whitelist, 0, sizeof(conf_whitelist_t));
}

/**
 * Wipes all whitelists.
 * 
 * @param cfg A pointer to the CFG structure.
 * 
 * @return Void
**/
void config_whitelist_wipe_all(config_t *cfg)
{
    memset(cfg->whitelist, 0, sizeof(cfg->whitelist));
}

/**
 * Finds next available whitelist index.
 * 
 * @param cfg Pointer to config_t pointer.
 * 
 * @return Index to next available whitelist index or -1 on failure.
**/
int config_whitelist_find_index(config_t *cfg)
{
    int ret = -1;

    unsigned int i;

    for (i = 0; i < MAX_WHITELIST; i++)
    {
        if (!cfg->whitelist[i].is_set)
        {
            ret = i;

            break;
        }
    }

    return ret;
}

/**
 * Finds whitelist.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param prefix The prefix.
 * 
 * @return A pointer to the structure or NULL on not found.
**/
conf_whitelist_t *config_whitelist_find(config_t *cfg, const char *prefix)
{
    conf_whitelist_t *ret = NULL;

    if (prefix == NULL)
    {
        return ret;
    }

    unsigned int i;

    for (i = 0; i < MAX_WHITELIST; i++)
    {
        conf_whitelist_t *wl = &cfg->whitelist[i];

        if (strcmp(prefix, wl->prefix) == 0)
        {
            ret = wl;

            break;
        }
    }

    return ret;
}

/**
 * Add/updates a whitelist.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param conf_whitelist Whitelist to add.
 * 
 * @return A pointer to the new/updated structure or NULL on failure.
**/
conf_whitelist_t *config_whitelist_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t conf_whitelist)
{
    conf_whitelist_t *wl = NULL;

    if (cfg == NULL)
    {
        return wl;
    }

    wl = config_whitelist_find(cfg, conf_whitelist.prefix);

    if (wl != NULL)
    {
        return wl;
    }
    else
    {
        int idx = config_whitelist_find_index(cfg);

        if (idx < 0)
        {
            return wl;
        }

        // Retrieve new whitelist.
        wl = &cfg->whitelist[idx];

        if (wl == NULL)
        {
            return wl;
        }
    }

    // Make sure we're set.
    wl->is_set = 1;

    // Assign prefix.
    strcpy(wl->prefix, conf_whitelist.prefix);

    // Insert whitelist
    if (xdp_maps != NULL)
    {
        maps_insert_whitelist(cfg, xdp_maps, wl);
    }

    return wl;
}

/**
 * Removes a whitelist.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_whitelist Whitelist to delete..
 * 
 * @return 0 on success or 1 on failure.
**/
int config_whitelist_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_whitelist_t conf_whitelist)
{
    int ret = EXIT_FAILURE;
    
    conf_whitelist_t *wl = config_whitelist_find(cfg, conf_whitelist.prefix);

    if (wl != NULL)
    {
        // First delete the BPF element.
        maps_delete_whitelist(cfg, xdp_maps, wl);

        // Wipe prefix.
        config_whitelist_wipe(wl);

        ret = EXIT_SUCCESS;
    }

    return ret;
}

/**
 * Wipes specific blacklist.
 * 
 * @param blacklist Pointer to blacklist.
 * 
 * @return Void
**/
void config_blacklist_wipe(conf_blacklist_t *blacklist)
{
    memset(blacklist, 0, sizeof(conf_blacklist_t));
}

/**
 * Wipes all blacklists.
 * 
 * @param cfg A pointer to the CFG structure.
 * 
 * @return Void
**/
void config_blacklist_wipe_all(config_t *cfg)
{
    memset(cfg->blacklist, 0, sizeof(cfg->blacklist));
}

/**
 * Finds next available blacklist index.
 * 
 * @param cfg Pointer to config_t pointer.
 * 
 * @return Index to next available blacklist index or -1 on failure.
**/
int config_blacklist_find_index(config_t *cfg)
{
    int ret = -1;

    unsigned int i;

    for (i = 0; i < MAX_BLACKLIST; i++)
    {
        if (!cfg->blacklist[i].is_set)
        {
            ret = i;

            break;
        }
    }

    return ret;
}

/**
 * Finds blacklist.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param prefix The prefix.
 * 
 * @return A pointer to the structure or NULL on not found.
**/
conf_blacklist_t *config_blacklist_find(config_t *cfg, const char *prefix)
{
    conf_blacklist_t *ret = NULL;

    if (prefix == NULL)
    {
        return ret;
    }

    unsigned int i;

    for (i = 0; i < MAX_BLACKLIST; i++)
    {
        conf_blacklist_t *bl = &cfg->blacklist[i];

        if (strcmp(prefix, bl->prefix) == 0)
        {
            ret = bl;

            break;
        }
    }

    return ret;
}

/**
 * Add/updates a blacklist.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param conf_blacklist Blacklist to add.
 * 
 * @return A pointer to the new/updated structure or NULL on failure.
**/
conf_blacklist_t *config_blacklist_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t conf_blacklist)
{
    conf_blacklist_t *bl = NULL;

    if (cfg == NULL)
    {
        return bl;
    }

    bl = config_blacklist_find(cfg, conf_blacklist.prefix);

    if (bl != NULL)
    {
        return bl;
    }
    else
    {
        int idx = config_blacklist_find_index(cfg);

        if (idx < 0)
        {
            return bl;
        }

        // Retrieve new blacklist.
        bl = &cfg->blacklist[idx];

        if (bl == NULL)
        {
            return bl;
        }
    }

    // Make sure we're set.
    bl->is_set = 1;

    // Assign prefix.
    strcpy(bl->prefix, conf_blacklist.prefix);

    // Insert blacklist.
    if (xdp_maps != NULL)
    {
        maps_insert_blacklist(cfg, xdp_maps, bl);
    }

    return bl;
}

/**
 * Removes a blacklist.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_blacklist Blacklist to delete..
 * 
 * @return 0 on success or 1 on failure.
**/
int config_blacklist_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_blacklist_t conf_blacklist)
{
    int ret = EXIT_FAILURE;
    
    conf_blacklist_t *bl = config_blacklist_find(cfg, conf_blacklist.prefix);

    if (bl != NULL)
    {
        // First delete the BPF element.
        maps_delete_blacklist(cfg, xdp_maps, bl);

        // Wipe prefix.
        config_blacklist_wipe(bl);

        ret = EXIT_SUCCESS;
    }

    return ret;
}

/**
 * Wipes specific port punch
 * 
 * @param pp Pointer to port punch.
 * 
 * @return Void
**/
void config_port_punch_wipe(conf_port_punch_t *pp)
{
    memset(pp, 0, sizeof(conf_port_punch_t));
}

/**
 * Wipes specific validated client.
 * 
 * @param vc Pointer to validated client.
 * 
 * @return Void
**/
void config_validated_client_wipe(conf_validated_client_t *vc)
{
    memset(vc, 0, sizeof(conf_validated_client_t));
}

/**
 * Wipes all port punches.
 * 
 * @param cfg A pointer to the CFG structure.
 * 
 * @return Void
**/
void config_port_punch_wipe_all(config_t *cfg)
{
    memset(cfg->port_punch, 0, sizeof(cfg->port_punch));
}

/**
 * Wipes all validated clients.
 * 
 * @param cfg A pointer to the CFG structure.
 * 
 * @return Void
**/
void config_validated_client_wipe_all(config_t *cfg)
{
    memset(cfg->validated_client, 0, sizeof(cfg->validated_client));
}

/**
 * Finds next available port puunch index.
 * 
 * @param cfg Pointer to config_t pointer.
 * 
 * @return Index to next available port punch index or -1 on failure.
**/
int config_port_punch_find_index(config_t *cfg)
{
    int ret = -1;

    unsigned int i;

    for (i = 0; i < MAX_PORT_PUNCH; i++)
    {
        if (!cfg->port_punch[i].is_set)
        {
            ret = i;

            break;
        }
    }

    // If return value is still -1, start from beginning and reset next index.
    if (ret == -1)
    {
        ret = 0;
    }

    return ret;
}

/**
 * Finds next available validated client index.
 * 
 * @param cfg Pointer to config_t pointer.
 * 
 * @return Index to next available validated client index or -1 on failure.
**/
int config_validated_client_find_index(config_t *cfg)
{
    int ret = -1;

    unsigned int i;

    for (i = 0; i < MAX_CLIENTS_VALIDATED; i++)
    {
        if (!cfg->validated_client[i].is_set)
        {
            ret = i;

            break;
        }
    }

    return ret;
}

/**
 * Finds port punch.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param ip The IP.
 * @param port The port.
 * @param service_ip The service IP.
 * @param service_port The service port.
 * 
 * @return A pointer to the structure or NULL on not found.
**/
conf_port_punch_t *config_port_punch_find(config_t *cfg, const char *ip, unsigned short port, const char *service_ip, unsigned short service_port)
{
    conf_port_punch_t *ret = NULL;

    if (ip == NULL || service_ip == NULL)
    {
        return ret;
    }

    unsigned int i;

    for (i = 0; i < MAX_PORT_PUNCH; i++)
    {
        conf_port_punch_t *pp = &cfg->port_punch[i];

        if (pp->ip == NULL)
        {
            continue;
        }

        if (pp->service_ip == NULL)
        {
            continue;
        }

        if (strcmp(ip, pp->ip) == 0 && port == pp->port && strcmp(service_ip, pp->service_ip) == 0 && service_port == pp->service_port)
        {
            ret = pp;

            break;
        }
    }

    return ret;
}

/**
 * Finds a validated client.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param src_ip The source IP.
 * @param src_port The source port.
 * @param dst_ip The service IP.
 * @param dst_port The service port.
 * 
 * @return A pointer to the structure or NULL on not found.
**/
conf_validated_client_t *config_validated_client_find(config_t *cfg, const char *src_ip, unsigned short src_port, const char *dst_ip, unsigned short dst_port)
{
    conf_validated_client_t *ret = NULL;

    if (src_ip == NULL || dst_ip == NULL)
    {
        return ret;
    }

    unsigned int i;

    for (i = 0; i < MAX_CLIENTS_VALIDATED; i++)
    {
        conf_validated_client_t *vc = &cfg->validated_client[i];

        if (vc->src_ip == NULL)
        {
            continue;
        }

        if (vc->dst_ip == NULL)
        {
            continue;
        }

        if (strcmp(src_ip, vc->src_ip) == 0 && src_port == vc->src_port && strcmp(dst_ip, vc->dst_ip) == 0 && dst_port == vc->dst_port)
        {
            ret = vc;

            break;
        }
    }

    return ret;
}

/**
 * Add/updates a port punch.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_port_punch Port punch to add.
 * 
 * @return A pointer to the new/updated structure or NULL on failure.
**/
conf_port_punch_t *config_port_punch_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t conf_port_punch)
{
    conf_port_punch_t *pp = NULL;

    if (cfg == NULL)
    {
        return pp;
    }

    pp = config_port_punch_find(cfg, conf_port_punch.ip, conf_port_punch.port, conf_port_punch.service_ip, conf_port_punch.service_port);

    u8 not_new = 0;

    if (pp != NULL)
    {
        not_new = 1;
    }
    else
    {
        int idx = config_port_punch_find_index(cfg);

        if (idx < 0)
        {
            return pp;
        }

        // Retrieve new connection.
        pp = &cfg->port_punch[idx];

        if (pp == NULL)
        {
            return pp;
        }

        pp->is_set = 1;
        pp->ip = conf_port_punch.ip;
        pp->port = conf_port_punch.port;
        pp->service_ip = conf_port_punch.service_ip;
        pp->service_port = conf_port_punch.service_port;
    }

    u8 changed = 0;

    if (pp->dest_ip == NULL || strcmp(pp->dest_ip, conf_port_punch.dest_ip) != 0)
    {
        changed = 1;

        if (cfg->verbose && not_new)
        {
            fprintf(stdout, "[CFG] Port Punch %s:%d => %s:%d :: Destination Set To => %s.\n", conf_port_punch.ip, conf_port_punch.port, conf_port_punch.service_ip, conf_port_punch.service_port, conf_port_punch.dest_ip);
        }

        pp->dest_ip = conf_port_punch.dest_ip;
    }

    // If we've changed a value (or new), update map.
    if ((!not_new || changed) && xdp_maps != NULL)
    {
        maps_insert_port_punch(cfg, xdp_maps, pp);
    }

    return pp;
}

/**
 * Add/updates a validated client.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_validated_client Port punch to add.
 * 
 * @return A pointer to the new/updated structure or NULL on failure.
**/
conf_validated_client_t *config_validated_client_add_or_update(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t conf_validated_client)
{
    conf_validated_client_t *vc = NULL;

    if (cfg == NULL)
    {
        return vc;
    }

    vc = config_validated_client_find(cfg, conf_validated_client.src_ip, conf_validated_client.src_port, conf_validated_client.dst_ip, conf_validated_client.dst_port);

    u8 not_new = 0;

    if (vc != NULL)
    {
        not_new = 1;
    }
    else
    {
        int idx = config_validated_client_find_index(cfg);

        if (idx < 0)
        {
            return vc;
        }

        // Retrieve new connection.
        vc = &cfg->validated_client[idx];

        if (vc == NULL)
        {
            return vc;
        }

        vc->is_set = 1;
        vc->src_ip = conf_validated_client.src_ip;
        vc->src_port = conf_validated_client.src_port;
        vc->dst_ip = conf_validated_client.dst_ip;
        vc->dst_port = conf_validated_client.dst_port;
    }

    // If.
    if ((!not_new) && xdp_maps != NULL)
    {
        maps_insert_validated_client(cfg, xdp_maps, vc);
    }

    return vc;
}


/**
 * Removes a port punch.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_port_punch Port punch to delete.
 * 
 * @return 0 on success or 1 on failure.
**/
int config_port_punch_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_port_punch_t conf_port_punch)
{
    int ret = EXIT_FAILURE;
    
    conf_port_punch_t *pp = config_port_punch_find(cfg, conf_port_punch.ip, conf_port_punch.port, conf_port_punch.service_ip, conf_port_punch.service_port);

    if (pp != NULL)
    {
        // First delete the BPF element.
        maps_delete_port_punch(cfg, xdp_maps, pp);

        // Set everything to 0 (including is set).
        config_port_punch_wipe(pp);

        ret = EXIT_SUCCESS;
    }

    return ret;
}

/**
 * Removes a validated client
 * 
 * @param cfg Pointer to config_t pointer.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param conf_validated_client Validated client to delete.
 * 
 * @return 0 on success or 1 on failure.
**/
int config_validated_client_remove(config_t *cfg, xdp_maps_t *xdp_maps, conf_validated_client_t conf_validated_client)
{
    int ret = EXIT_FAILURE;
    
    conf_validated_client_t *vc = config_validated_client_find(cfg, conf_validated_client.src_ip, conf_validated_client.src_port, conf_validated_client.dst_ip, conf_validated_client.dst_port);

    if (vc != NULL)
    {
        // First delete the BPF element.
        maps_delete_validated_client(cfg, xdp_maps, vc);

        // Set everything to 0 (including is set).
        config_validated_client_wipe(vc);

        ret = EXIT_SUCCESS;
    }

    return ret;
}

/**
 * Parses connection in JSON and updates/inserts BPF map.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param connections A pointer to the JSON connections object (JSON object).
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param i Index of connection.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse_json_conn(config_t *cfg, struct json_object *connection, xdp_maps_t *xdp_maps, unsigned int i)
{
    // Initialize connection objects.
    struct json_object *is_enabled;

    struct json_object *protocol;
    struct json_object *bind_ip;
    struct json_object *bind_port;
    struct json_object *dest_ip;
    struct json_object *dest_port;

    struct json_object *filters;

    struct json_object *conn_udp_rl;
    struct json_object *conn_tcp_rl;
    struct json_object *conn_icmp_rl;

    struct json_object *conn_syn_settings;
    struct json_object *conn_cache_settings;

    conf_connection_t connection_conf = {0};
    connection_conf.is_set = 1;

    char *s_protocol = NULL;
    char *s_bind_ip = NULL;
    unsigned short s_bind_port = 0;

    // Retrieve protocol.
    if (json_object_object_get_ex(connection, "protocol", &protocol))
    {
        connection_conf.protocol = (char *)json_object_get_string(protocol);
    }

    // Retrieve bind IP.
    if (!json_object_object_get_ex(connection, "bind_ip", &bind_ip))
    {
        return EXIT_FAILURE;
    }

    // Retrieve bind port.
    if (!json_object_object_get_ex(connection, "bind_port", &bind_port))
    {
        return EXIT_FAILURE;
    }

    connection_conf.bind_ip = (char *)json_object_get_string(bind_ip);
    connection_conf.bind_port = (unsigned int)json_object_get_int(bind_port);

    // Check enabled.
    if (json_object_object_get_ex(connection, "enabled", &is_enabled))
    {
        connection_conf.is_enabled = (unsigned int)(json_object_get_boolean(is_enabled)) ? 1 : 0;
    }

    // Retrieve destination IP.
    if (json_object_object_get_ex(connection, "dest_ip", &dest_ip))
    {
        connection_conf.dest_ip = (char *)json_object_get_string(dest_ip);
    }

    // Retrieve destination port.
    if (json_object_object_get_ex(connection, "dest_port", &dest_port))
    {
        connection_conf.dest_port = (unsigned int)json_object_get_int(dest_port);
    }

    // Retrieve filter length.
    if (json_object_object_get_ex(connection, "filters", &filters))
    {
        connection_conf.filters = (unsigned int)json_object_get_int(filters);
    }

    // Retrieve connection-specific settings.
    // Retrieve UDP rate limiting.
    if (json_object_object_get_ex(connection, "udp_rl", &conn_udp_rl))
    {
        // UDP rate limiting objects.
        struct json_object *block_time;
        struct json_object *pps;
        struct json_object *bps;

        // Block time.
        if (json_object_object_get_ex(conn_udp_rl, "block_time", &block_time))
        {
            connection_conf.udp_rl.block_time = (unsigned int)json_object_get_int(block_time);
        }

        // PPS.
        if (json_object_object_get_ex(conn_udp_rl, "pps", &pps))
        {
            connection_conf.udp_rl.pps = (unsigned long long)json_object_get_int64(pps);
        }

        // BPS.
        if (json_object_object_get_ex(conn_udp_rl, "bps", &bps))
        {
            connection_conf.udp_rl.bps = (unsigned long long)json_object_get_int64(bps);
        }
    }

    // Retrieve TCP rate limiting.
    if (json_object_object_get_ex(connection, "tcp_rl", &conn_tcp_rl))
    {
        // UDP rate limiting objects.
        struct json_object *block_time;
        struct json_object *pps;
        struct json_object *bps;

        // Block time.
        if (json_object_object_get_ex(conn_tcp_rl, "block_time", &block_time))
        {
            connection_conf.tcp_rl.block_time = (unsigned int)json_object_get_int(block_time);
        }

        // PPS.
        if (json_object_object_get_ex(conn_tcp_rl, "pps", &pps))
        {
            connection_conf.tcp_rl.pps = (unsigned long long)json_object_get_int64(pps);
        }

        // BPS.
        if (json_object_object_get_ex(conn_tcp_rl, "bps", &bps))
        {
            connection_conf.tcp_rl.bps = (unsigned long long)json_object_get_int64(bps);
        }
    }

    // Retrieve ICMP rate limiting.
    if (json_object_object_get_ex(connection, "icmp_rl", &conn_icmp_rl))
    {
        // UDP rate limiting objects.
        struct json_object *block_time;
        struct json_object *pps;
        struct json_object *bps;

        // Block time.
        if (json_object_object_get_ex(conn_icmp_rl, "block_time", &block_time))
        {
            connection_conf.icmp_rl.block_time = (unsigned int)json_object_get_int(block_time);
        }

        // PPS.
        if (json_object_object_get_ex(conn_icmp_rl, "pps", &pps))
        {
            connection_conf.icmp_rl.pps = (unsigned long long)json_object_get_int64(pps);
        }

        // BPS.
        if (json_object_object_get_ex(conn_icmp_rl, "bps", &bps))
        {
            connection_conf.icmp_rl.bps = (unsigned long long)json_object_get_int64(bps);
        }
    }

    // Retrieve SYN settings.
    if (json_object_object_get_ex(connection, "syn_settings", &conn_syn_settings))
    {
        // SYN rate limiting.
        struct json_object *rl;

        // Rate limiting
        if (json_object_object_get_ex(conn_syn_settings, "rl", &rl))
        {
            struct json_object *block_time;
            struct json_object *pps;
            struct json_object *bps;

            // Block time.
            if (json_object_object_get_ex(rl, "block_time", &block_time))
            {
                connection_conf.syn_settings.rl.block_time = (unsigned int)json_object_get_int(block_time);
            }

            // PPS.
            if (json_object_object_get_ex(rl, "pps", &pps))
            {
                connection_conf.syn_settings.rl.pps = (unsigned long long)json_object_get_int64(pps);
            }

            // BPS.
            if (json_object_object_get_ex(rl, "bps", &bps))
            {
                connection_conf.syn_settings.rl.bps = (unsigned long long)json_object_get_int64(bps);
            }
        }
    }

    // Retrieve cache settings.
    if (json_object_object_get_ex(connection, "cache_settings", &conn_cache_settings))
    {
        // Cache setting objects.
        struct json_object *a2s_info;
        struct json_object *a2s_info_time;
        struct json_object *a2s_info_global_cache;
        struct json_object *a2s_info_cache_timeout;

        // Retrieve A2S_INFO.
        if (json_object_object_get_ex(conn_cache_settings, "a2s_info_enabled", &a2s_info))
        {
            connection_conf.cache_settings.A2S_INFO = (unsigned int)(json_object_get_boolean(a2s_info)) ? 1 : 0;
        }

        // Retrieve A2S_INFO time.
        if(json_object_object_get_ex(conn_cache_settings, "a2s_info_cache_time", &a2s_info_time))
        {
            connection_conf.cache_settings.A2S_INFO_time = (unsigned int)json_object_get_int(a2s_info_time);
        }

        // Retrieve A2S_INFO global cache.
        if (json_object_object_get_ex(conn_cache_settings, "a2s_info_global_cache", &a2s_info_global_cache))
        {
            connection_conf.cache_settings.A2S_INFO_global_cache = (unsigned int)(json_object_get_boolean(a2s_info_global_cache)) ? 1 : 0;
        }

        // Retrieve A2S_INFO cache timeout.
        if(json_object_object_get_ex(conn_cache_settings, "a2s_info_cache_timeout", &a2s_info_cache_timeout))
        {
            connection_conf.cache_settings.A2S_INFO_cache_timeout = (unsigned int)json_object_get_int(a2s_info_cache_timeout);
        }
    }

    config_connection_add_or_update(cfg, xdp_maps, connection_conf);

    return EXIT_SUCCESS;
}

/**
 * Parses whitelist in JSON and updates/inserts BPF map.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param whitelist Pointer to the whitelist entry JSON object.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param i Index of whitelist.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse_json_whitelist(config_t *cfg, struct json_object *whitelist, xdp_maps_t *xdp_maps, unsigned int i)
{
    char *prefix = (char *)json_object_get_string(whitelist);

    if (prefix != NULL)
    {
        conf_whitelist_t wl = {0};
        wl.is_set = 1;

        strncpy(wl.prefix, prefix, MAX_PREFIX_LEN);

        config_whitelist_add_or_update(cfg, xdp_maps, wl);

        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

/**
 * Parses blacklist in JSON and updates/inserts BPF map.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param blacklist Pointer to the blacklist entry JSON object.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param i Index of blacklist.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse_json_blacklist(config_t *cfg, struct json_object *blacklist, xdp_maps_t *xdp_maps, unsigned int i)
{
    char *prefix = (char *)json_object_get_string(blacklist);

    if (prefix != NULL)
    {
        conf_blacklist_t bl = {0};
        bl.is_set = 1;

        strncpy(bl.prefix, prefix, MAX_PREFIX_LEN);
        
        config_blacklist_add_or_update(cfg, xdp_maps, bl);

        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

/**
 * Parses port punch in JSON and updates/inserts BPF map.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param port_punch Pointer to the port punch entry JSON object.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param i Index of blacklist.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse_json_port_punch(config_t *cfg, struct json_object *port_punch, xdp_maps_t *xdp_maps, unsigned int i)
{
    struct json_object *ip;
    struct json_object *port;
    struct json_object *service_ip;
    struct json_object *service_port;
    struct json_object *dest_ip;

    if (!json_object_object_get_ex(port_punch, "ip", &ip))
    {
        fprintf(stderr, "[ERROR] config_parse_json_port_punch() :: Failed to find IP JSON.\n");

        return EXIT_FAILURE;
    }

    if (!json_object_object_get_ex(port_punch, "port", &port))
    {
        fprintf(stderr, "[ERROR] config_parse_json_port_punch() :: Failed to find port JSON.\n");

        return EXIT_FAILURE;
    }

    if (!json_object_object_get_ex(port_punch, "service_ip", &service_ip))
    {
        fprintf(stderr, "[ERROR] config_parse_json_port_punch() :: Failed to find service IP JSON.\n");

        return EXIT_FAILURE;
    }

    if (!json_object_object_get_ex(port_punch, "service_port", &service_port))
    {
        fprintf(stderr, "[ERROR] config_parse_json_port_punch() :: Failed to find service port JSON.\n");

        return EXIT_FAILURE;
    }

    if (!json_object_object_get_ex(port_punch, "dest_ip", &dest_ip))
    {
        fprintf(stderr, "[ERROR] config_parse_json_port_punch() :: Failed to find dest IP JSON.\n");

        return EXIT_FAILURE;
    }

    const char *s_ip = json_object_get_string(ip);
    unsigned short i_port = (unsigned short)json_object_get_int(port);

    const char *service_s_ip = json_object_get_string(service_ip);
    unsigned short service_i_port = (unsigned short)json_object_get_int(service_port);

    const char *dest_s_ip = json_object_get_string(dest_ip);

    if (s_ip != NULL && service_s_ip != NULL)
    {
        conf_port_punch_t pp = {0};
        pp.is_set = 1;

        pp.ip = (char *)s_ip;
        pp.port = i_port;
        pp.service_ip = (char *)service_s_ip;
        pp.service_port = service_i_port;
        pp.dest_ip = (char *)dest_s_ip;

        config_port_punch_add_or_update(cfg, xdp_maps, pp);

        return EXIT_SUCCESS;
    }

    fprintf(stderr, "[ERROR] config_parse_json_port_punch() :: s_ip or service_s_ip is NULL.\n");

    return EXIT_FAILURE;
}

/**
 * Parses validated client in JSON and updates/inserts BPF map.
 * 
 * @param cfg Pointer to config_t pointer.
 * @param validated_client Pointer to the validated_client entry JSON object.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param i Index of blacklist.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse_json_validated_client(config_t *cfg, struct json_object *validated_client, xdp_maps_t *xdp_maps, unsigned int i)
{
    struct json_object *src_ip;
    struct json_object *src_port;
    struct json_object *dst_ip;
    struct json_object *dst_port;

    if (!json_object_object_get_ex(validated_client, "src_ip", &src_ip))
    {
        return EXIT_FAILURE;
    }

    if (!json_object_object_get_ex(validated_client, "src_port", &src_port))
    {
        return EXIT_FAILURE;
    }

    if (!json_object_object_get_ex(validated_client, "dst_ip", &dst_ip))
    {
        return EXIT_FAILURE;
    }

    if (!json_object_object_get_ex(validated_client, "dst_port", &dst_port))
    {
        return EXIT_FAILURE;
    }

    const char *s_src_ip = json_object_get_string(src_ip);
    unsigned short i_src_port = (unsigned short)json_object_get_int(src_port);

    const char *s_dst_ip = json_object_get_string(dst_ip);
    unsigned short s_dst_port = (unsigned short)json_object_get_int(dst_port);

    if (s_src_ip != NULL && s_dst_ip != NULL)
    {
        conf_validated_client_t vc = {0};
        vc.is_set = 1;

        vc.src_ip = (char *)s_src_ip;
        vc.src_port = i_src_port;
        vc.dst_ip = (char *)s_dst_ip;
        vc.dst_port = s_dst_port;

        config_validated_client_add_or_update(cfg, xdp_maps, vc);

        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

/**
 * Parses JSON and changes CFG structure.
 * 
 * @param cfg Pointer to config_t variable.
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * @param parser A pointer to the JSON parser (root JSON object).
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse_json_config(config_t *cfg, xdp_maps_t *xdp_maps, struct json_object *parser)
{
    // Iterators.
    unsigned int i;

    unsigned int changed = 0;

    // Create main config objects.
    struct json_object *interface;
    struct json_object *edge_ip;
    struct json_object *force_mode;
    struct json_object *socket_count;
    struct json_object *queue_is_static;
    struct json_object *queue_id;
    struct json_object *zero_copy;
    struct json_object *need_wakeup;
    struct json_object *batch_size;
    struct json_object *verbose;
    struct json_object *calc_stats;
    struct json_object *allow_all_edge;

    struct json_object *connections;
    struct json_object *whitelist;
    struct json_object *blacklist;
    struct json_object *port_punch;
    struct json_object *validated_client;

    // Read if we want verbose.
    if (json_object_object_get_ex(parser, "verbose", &verbose))
    {
        unsigned int old_v = cfg->verbose;
        cfg->verbose = (unsigned int)(json_object_get_boolean(verbose)) ? 1 : 0;

        if (old_v != cfg->verbose)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Verbose Set To => %s.\n", cfg->verbose ? "True" : "False");
            }
        }
    }

    // Read interface.
    if (json_object_object_get_ex(parser, "interface", &interface))
    {
        char *old_v = (cfg->interface != NULL) ? (cfg->interface) : NULL;
        cfg->interface = (char *)strdup(json_object_get_string(interface));

        if (old_v == NULL || strcmp(cfg->interface, old_v) != 0)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Interface Set To => %s.\n", cfg->interface);
            }
        }
    }

    // Read edge IP.
    if (json_object_object_get_ex(parser, "edge_ip", &edge_ip))
    {
        char *old_v = (cfg->edge_ip != NULL) ? (cfg->edge_ip) : NULL;
        cfg->edge_ip = (char *)strdup(json_object_get_string(edge_ip));

        if (old_v == NULL || strcmp(cfg->edge_ip, old_v) != 0)
        {
            changed = 1;

            maps_insert_edge_ip(cfg, xdp_maps);

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Edge IP Set To => %s.\n", cfg->edge_ip);
            }
        }
    }
    else
    {
        // Set default edge IP.
        if (cfg->interface != NULL && cfg->edge_ip == NULL)
        {
            config_set_default_edge_ip(cfg);

            maps_insert_edge_ip(cfg, xdp_maps);
        }
    }

    // Read force mode.
    if (json_object_object_get_ex(parser, "force_mode", &force_mode))
    {
        unsigned int old_v = cfg->force_mode;
        cfg->force_mode = (unsigned int) json_object_get_int(force_mode);

        if (old_v != cfg->force_mode)
        {
            changed = 1;
            
            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Force Mode Set To => %u.\n", cfg->force_mode);
            }
        }
    }

    // Read socket count.
    if (json_object_object_get_ex(parser, "socket_count", &socket_count))
    {
        unsigned int old_v = cfg->socket_count;
        cfg->socket_count = (unsigned int)json_object_get_int(socket_count);

        if (old_v != cfg->socket_count)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Socket Count Set To => %u.\n", cfg->socket_count);
            }
        }
    }

    // Read if queue is static.
    if (json_object_object_get_ex(parser, "queue_is_static", &queue_is_static))
    {
        unsigned int old_v = cfg->queue_is_static;
        cfg->queue_is_static = (unsigned int)(json_object_get_boolean(queue_is_static)) ? 1 : 0;

        if (old_v != cfg->queue_is_static)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Queue Is Static Set To => %s.\n", cfg->queue_is_static ? "True" : "False");
            }
        }
    }

    // Read queue ID.
    if (json_object_object_get_ex(parser, "queue_id", &queue_id))
    {
        unsigned int old_v = cfg->queue_id;
        cfg->queue_id = (unsigned int)json_object_get_int(queue_id);

        if (old_v != cfg->queue_id)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Queue ID Set To => %u.\n", cfg->queue_id);
            }
        }
    }

    // Read if we want zero-copy.
    if (json_object_object_get_ex(parser, "zero_copy", &zero_copy))
    {
        unsigned int old_v = cfg->zero_copy;
        cfg->zero_copy = (unsigned int)(json_object_get_boolean(zero_copy)) ? 1 : 0;

        if (old_v != cfg->zero_copy)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Zero Copy Set To => %s.\n", cfg->zero_copy ? "True" : "False");
            }
        }
    }

    // Read if we need wakeup.
    if (json_object_object_get_ex(parser, "need_wakeup", &need_wakeup))
    {
        unsigned int old_v = cfg->need_wakeup;
        cfg->need_wakeup = (unsigned int)(json_object_get_boolean(need_wakeup)) ? 1 : 0;

        if (old_v != cfg->need_wakeup)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Need Wakeup Set To => %s.\n", cfg->need_wakeup ? "True" : "False");
            }
        }
    }

    // Read batch size.
    if (json_object_object_get_ex(parser, "batch_size", &batch_size))
    {
        unsigned int old_v = cfg->batch_size;
        cfg->batch_size = (unsigned int)json_object_get_int(batch_size);

        if (old_v != cfg->batch_size)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Batch Size Set To => %d.\n", cfg->batch_size);
            }
        }
    }

    // Read if we want to calculate stats.
    if (json_object_object_get_ex(parser, "calc_stats", &calc_stats))
    {
        unsigned int old_v = cfg->calc_stats;
        cfg->calc_stats = (unsigned int)(json_object_get_boolean(calc_stats)) ? 1 : 0;

        if (old_v != cfg->calc_stats)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Calculate Stats Set To => %s.\n", cfg->calc_stats ? "True" : "False");
            }
        }
    }

    // Read if we want to allow all edge traffic.
    if (json_object_object_get_ex(parser, "allow_all_edge", &allow_all_edge))
    {
        unsigned int old_v = cfg->allow_all_edge;
        cfg->allow_all_edge = (unsigned int)(json_object_get_boolean(allow_all_edge)) ? 1 : 0;

        if (old_v != cfg->allow_all_edge)
        {
            changed = 1;

            if (cfg->verbose)
            {
                fprintf(stdout, "[CFG] Allow All Edge Set To => %s.\n", cfg->allow_all_edge ? "True" : "False");
            }
        }
    }

    // Receive connections length if there are any.
    size_t connection_len = 0;

    if (json_object_object_get_ex(parser, "connections", &connections))
    {
        connection_len = json_object_array_length(connections);;
    }

    // Loop through all connections.
    for (i = 0; i < connection_len; i++)
    {
        // Receive connection at index.
        struct json_object *connection = json_object_array_get_idx(connections, i);

        config_parse_json_conn(cfg, connection, xdp_maps, i);
    }

    // Receive whitelist length if there are any.
    size_t whitelist_len = 0;

    if (json_object_object_get_ex(parser, "whitelist", &whitelist))
    {
        whitelist_len = json_object_array_length(whitelist);
    }

    // Loop through all whitelist entries.
    for (i = 0; i < whitelist_len; i++)
    {
        // Receive connection at index.
        struct json_object *whitelist_entry = json_object_array_get_idx(whitelist, i);

        config_parse_json_whitelist(cfg, whitelist_entry, xdp_maps, i);
    }

    // Receive blacklist length if there are any.
    size_t blacklist_len = 0;

    if (json_object_object_get_ex(parser, "blacklist", &blacklist))
    {
        blacklist_len = json_object_array_length(blacklist);
    }

    // Loop through all blacklist entries.
    for (i = 0; i < blacklist_len; i++)
    {
        // Receive connection at index.
        struct json_object *blacklist_entry = json_object_array_get_idx(blacklist, i);

        config_parse_json_blacklist(cfg, blacklist_entry, xdp_maps, i);
    }

    // Receive port punch length if there are any.
    size_t pp_len = 0;

    if (json_object_object_get_ex(parser, "port_punch", &port_punch))
    {
        pp_len = json_object_array_length(port_punch);
    }

    // Loop through all port punch entries.
    for (i = 0; i < pp_len; i++)
    {
        // Receive connection at index.
        struct json_object *pp_entry = json_object_array_get_idx(port_punch, i);

        config_parse_json_port_punch(cfg, pp_entry, xdp_maps, i);
    }

    // Receive validated client length if there are any.
    size_t vc_len = 0;

    if (json_object_object_get_ex(parser, "validated_client", &validated_client))
    {
        vc_len = json_object_array_length(validated_client);
    }

    // Loop through all validated client entries.
    for (i = 0; i < vc_len; i++)
    {
        // Receive connection at index.
        struct json_object *vc_entry = json_object_array_get_idx(validated_client, i);

        config_parse_json_validated_client(cfg, vc_entry, xdp_maps, i);
    }

    return EXIT_SUCCESS;
}

/**
 * Performs update.
 * 
 * @param update_data JSON update data object.
 * @param cfg Pointer to config_t variable.
 * @param parser A pointer to the JSON parser (root JSON object).
 * @param xdp_maps A pointer to the XDP maps structure (xdp_maps_t).
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_do_update(const char *type, struct json_object *update_data, config_t *cfg, struct json_object *parser, xdp_maps_t *xdp_maps)
{
    // Check for update/add or delete.
    if (strstr(type, "update") != NULL)
    {
        if (config_parse_json_config(cfg, xdp_maps, update_data) != 0)
        {
            fprintf(stderr, "[ERROR] config_do_update() :: config_parse_json_config() returned unsuccessful.\n");

            return EXIT_FAILURE;
        }
    }
    else if (strstr(type, "delete") != NULL)
    {
        unsigned int i;

        if (strcmp(type, "connection_delete") == 0)
        {
            struct json_object *connections;

            if (!json_object_object_get_ex(update_data, "connections", &connections))
            {
                return EXIT_FAILURE;
            }

            size_t conn_len = 0;
            
            conn_len = json_object_array_length(connections);

            for (i = 0; i < conn_len; i++)
            {
                struct json_object *conn = json_object_array_get_idx(connections, i);

                struct json_object *protocol;
                struct json_object *bind_ip;
                struct json_object *bind_port;
                struct json_object *dest_ip;

                if (!json_object_object_get_ex(conn, "protocol", &protocol))
                {
                    continue;
                }

                if (!json_object_object_get_ex(conn, "bind_ip", &bind_ip))
                {
                    continue;
                }

                if (!json_object_object_get_ex(conn, "bind_port", &bind_port))
                {
                    continue;
                }

                char *s_dest_ip = NULL;

                if (json_object_object_get_ex(conn, "dest_ip", &dest_ip))
                {
                    s_dest_ip = (char *)json_object_get_string(dest_ip);
                }

                const char *s_protocol = json_object_get_string(protocol);

                if (s_protocol == NULL)
                {
                    continue;
                }

                const char *s_bind_ip = json_object_get_string(bind_ip);

                if (s_bind_ip == NULL)
                {
                    continue;
                }

                unsigned short s_bind_port = (unsigned short)json_object_get_int(bind_port);

                conf_connection_t new_conf = {0};
                new_conf.protocol = (char *)s_protocol;
                new_conf.bind_ip = (char *)s_bind_ip;
                new_conf.bind_port = s_bind_port;
                new_conf.dest_ip = (char *)s_dest_ip;

                if (config_connection_remove(cfg, xdp_maps, new_conf))
                {
                    fprintf(stderr, "Error removing connection %s:%d (%s/%s) from update.\n", (new_conf.bind_ip != NULL) ? new_conf.bind_ip : "ERR", new_conf.bind_port, (new_conf.protocol != NULL) ? new_conf.protocol : "ERR", (new_conf.dest_ip != NULL) ? new_conf.dest_ip : "N/A");

                    continue;
                }
            }
        }
        else if (strcmp(type, "whitelist_delete") == 0)
        {
            struct json_object *whitelists;

            if (!json_object_object_get_ex(update_data, "whitelist", &whitelists))
            {
                return EXIT_FAILURE;
            }

            size_t whitelist_len = 0;

            whitelist_len = json_object_array_length(whitelists);

            for (i = 0; i < whitelist_len; i++)
            {
                struct json_object *whitelist = json_object_array_get_idx(whitelists, i);

                struct json_object *prefix;

                if (!json_object_object_get_ex(whitelist, "prefix", &prefix))
                {
                    continue;
                }

                char *s_prefix = (char *)json_object_get_string(prefix);

                if (s_prefix == NULL)
                {
                    continue;
                }

                conf_whitelist_t wl = {0};
                strcpy(wl.prefix, s_prefix);

                if (config_whitelist_remove(cfg, xdp_maps, wl) != 0)
                {
                    fprintf(stderr, "Error removing whitelist %s from update.\n", s_prefix);

                    continue;
                }
            }
        }
        else if (strcmp(type, "blacklist_delete") == 0)
        {
            struct json_object *blacklists;

            if (!json_object_object_get_ex(update_data, "blacklist", &blacklists))
            {
                return EXIT_FAILURE;
            }

            size_t blacklist_len = 0;

            blacklist_len = json_object_array_length(blacklists);

            for (i = 0; i < blacklist_len; i++)
            {
                struct json_object *blacklist = json_object_array_get_idx(blacklists, i);
                

                struct json_object *prefix;

                if (!json_object_object_get_ex(blacklist, "prefix", &prefix))
                {
                   continue;
                }

                char *s_prefix = (char *)json_object_get_string(prefix);

                if (s_prefix == NULL)
                {
                    continue;
                }

                conf_blacklist_t bl = {0};
                strcpy(bl.prefix, s_prefix);

                if (config_blacklist_remove(cfg, xdp_maps, bl) != 0)
                {
                    fprintf(stderr, "Error removing blacklist %s from update.\n", s_prefix);

                    continue;
                }
            }
        }
        else if (strcmp(type, "port_punch_delete") == 0)
        {
            struct json_object *port_punches;

            if (!json_object_object_get_ex(update_data, "port_punch", &port_punches))
            {
                return EXIT_FAILURE;
            }
            
            size_t port_punch_len = 0;

            port_punch_len = json_object_array_length(port_punches);

            for (i = 0; i < port_punch_len; i++)
            {
                struct json_object *port_punch = json_object_array_get_idx(port_punches, i);
                
                struct json_object *ip;
                struct json_object *port;
                struct json_object *service_ip;
                struct json_object *service_port;

                if (!json_object_object_get_ex(port_punch, "ip", &ip))
                {
                   continue;
                }

                if (!json_object_object_get_ex(port_punch, "port", &port))
                {
                    continue;
                }

                if (!json_object_object_get_ex(port_punch, "service_ip", &service_ip))
                {
                    continue;
                }

                if (!json_object_object_get_ex(port_punch, "service_port", &service_port))
                {
                   continue;
                }

                const char *s_ip = json_object_get_string(ip);

                if (s_ip == NULL)
                {
                    continue;
                }

                unsigned short s_port = (unsigned short)json_object_get_int(port);

                const char *s_service_ip = json_object_get_string(service_ip);

                if (s_service_ip == NULL)
                {
                    continue;
                }

                unsigned short s_service_port = (unsigned short)json_object_get_int(service_port);

                conf_port_punch_t pp = {0};
                pp.ip = (char *)s_ip;
                pp.port = s_port;
                pp.service_ip = (char *)s_service_ip;
                pp.service_port = s_service_port;

                if (config_port_punch_remove(cfg, xdp_maps, pp) != 0)
                {
                    fprintf(stderr, "[ERROR] Failed to remove port punch %s:%d => %s:%d from update.\n", s_ip, s_port, s_service_ip, s_service_port);

                    continue;
                }
                else
                {
                    if (cfg->verbose)
                    {
                        fprintf(stderr, "Successfully removed port punch %s:%d => %s:%d from update.\n", s_ip, s_port, s_service_ip, s_service_port);
                    }
                }
            }
        }
        else if (strcmp(type, "validated_client_delete") == 0)
        {
            struct json_object *validated_clients;

            if (!json_object_object_get_ex(update_data, "validated_client", &validated_clients))
            {
                return EXIT_FAILURE;
            }
            
            size_t validated_client_len = 0;

            validated_client_len = json_object_array_length(validated_clients);

            for (i = 0; i < validated_client_len; i++)
            {
                struct json_object *validated_client = json_object_array_get_idx(validated_clients, i);
                
                struct json_object *src_ip;
                struct json_object *src_port;
                struct json_object *dst_ip;
                struct json_object *dst_port;

                if (!json_object_object_get_ex(validated_client, "src_ip", &src_ip))
                {
                   continue;
                }

                if (!json_object_object_get_ex(validated_client, "src_port", &src_port))
                {
                    continue;
                }

                if (!json_object_object_get_ex(validated_client, "dst_ip", &dst_ip))
                {
                    continue;
                }

                if (!json_object_object_get_ex(validated_client, "dst_port", &dst_port))
                {
                   continue;
                }

                conf_validated_client_t vc = {0};

                const char *s_src_ip = json_object_get_string(src_ip);

                if (s_src_ip == NULL)
                {
                    continue;
                }

                unsigned short s_src_port = (unsigned short)json_object_get_int(src_port);

                const char *s_dst_ip = json_object_get_string(dst_ip);

                if (s_dst_ip == NULL)
                {
                    continue;
                }

                unsigned short s_dst_port = (unsigned short)json_object_get_int(dst_port);

                vc.src_ip = (char *)s_src_ip;
                vc.src_port = s_src_port;
                vc.dst_ip = (char *)s_dst_ip;
                vc.dst_port = s_dst_port;

                if (config_validated_client_remove(cfg, xdp_maps, vc) != 0)
                {
                    fprintf(stderr, "[ERROR] Failed to remove validated client %s:%d => %s:%d from update.\n", s_src_ip, s_src_port, s_dst_ip, s_dst_port);

                    continue;
                }
                else
                {
                    if (cfg->verbose)
                    {
                        fprintf(stderr, "Successfully removed validated client %s:%d => %s:%d from update.\n", s_src_ip, s_src_port, s_dst_ip, s_dst_port);
                    }
                }
            }
        }
    }

    return EXIT_SUCCESS;
}

/**
 * Parses JSON data from Python program.
 * 
 * @param data JSON data.
 * @param cfg Pointer to config_t variable.
 * @param xdp_maps A pointer to XDP maps.
 * 
 * @return 0 (EXIT_SUCCESS) on success or 1 (EXIT_FAILURE) on failure.
**/
int config_parse_json(const char *data, config_t *cfg, xdp_maps_t *xdp_maps)
{
    unsigned int i;
    
    // Create parser and parse the data.
    struct json_object *parser = json_tokener_parse(data);

    if (parser == NULL)
    {
        fprintf(stderr, "config_parse_json() : INVALID JSON :: %s!\n", data);

        return EXIT_FAILURE;
    }
    
    // Now handle additional JSON data (e.g. JSON data from Killtrocity socket).
    struct json_object *update_type;
    struct json_object *update_data;

   // Check for type.
   if (!json_object_object_get_ex(parser, "type", &update_type))
   {
       config_parse_json_config(cfg, xdp_maps, parser);

       goto out;
   }

    const char *type = json_object_get_string(update_type);

    // Check type.
    if (type == NULL)
    {
        goto out;
    }

   // If this is a ping, just print to stdout and exit.
   if (strcmp(type, "ping") == 0)
   {
       fprintf(stdout, "[PING] Received ping.\n");

       goto out;
   }

    // Check for data.
    if (!json_object_object_get_ex(parser, "data", &update_data))
    {
        goto err;
    }

   // Finally, if this is an update, we actually have to do some stuff.

   // Now we need to check the name.
    if (cfg->verbose)
    {
        if (strcmp(type, "full_update") == 0)
        {    
            fprintf(stdout, "[KF] Found full update :: setting values!\n");
        }
        else if (strcmp(type, "edge_update") == 0)
        {    
            fprintf(stdout, "[KF] Found edge update :: setting values!\n");
        }
        else if (strcmp(type, "connection_update") == 0)
        {
            fprintf(stdout, "[KF] Found connect update :: setting values!\n");
        }
        else if (strcmp(type, "connection_delete") == 0)
        {
            fprintf(stdout, "[KF] Found connect delete :: setting values!\n");
        }
        else if (strcmp(type, "whitelist_update") == 0)
        {
            fprintf(stdout, "[KF] Found whitelist update :: setting values!\n");
        }
        else if (strcmp(type, "whitelist_delete") == 0)
        {
            fprintf(stdout, "[KF] Found whitelist delete :: setting values!\n");
        }
        else if (strcmp(type, "blacklist_update") == 0)
        {
            fprintf(stdout, "[KF] Found blacklist update :: setting values!\n");
        }
        else if (strcmp(type, "blacklist_delete") == 0)
        {
            fprintf(stdout, "[KF] Found blacklist delete :: setting values!\n");
        }
        else if (strcmp(type, "port_punch_update") == 0)
        {
            fprintf(stdout, "[KF] Found port punch update :: setting values!\n");
        }
        else if (strcmp(type, "port_punch_delete") == 0)
        {
            fprintf(stdout, "[KF] Found port punch delete :: setting values!\n");        
        }
        else if (strcmp(type, "validated_client_update") == 0)
        {
            fprintf(stdout, "[KF] Found validated client update :: setting values!\n");
        }
        else if (strcmp(type, "validated_client_delete") == 0)
        {
            fprintf(stdout, "[KF] Found validated client delete :: setting values!\n");        
        }
    }

    if (config_do_update(type, update_data, cfg, parser, xdp_maps))
    {
        if (cfg->verbose)
        {
            fprintf(stderr, "Failed to perform update => %s.\n", type);
        }
    }

    json_object_put(parser);

out:;
    return EXIT_SUCCESS;

err:;
    return EXIT_FAILURE;
}

/**
 * Parses values from port punch into JSON and sends them to socket.
 * 
 * @param cfg Pointer to config_t variable.
 * @param ip Port punch IP.
 * @param port Port punch port.
 * @param service_ip Port punch service IP.
 * @param service_port Port punch service port.
 * @param dest_ip Port punch destination IP.
 * 
 * @return < 1 on failure. Otherwise, amount of bytes sent.
**/
int config_parse_and_send_port_punch(config_t *cfg, char *ip, unsigned short port, char *service_ip, unsigned short service_port, char *dest_ip)
{
    struct json_object *root;
    struct json_object *data;

    root = json_object_new_object();
    data = json_object_new_object();

    json_object_object_add(data, "ip", json_object_new_string((const char *)ip));
    json_object_object_add(data, "port", json_object_new_int(port));

    json_object_object_add(data, "service_ip", json_object_new_string((const char *)service_ip));
    json_object_object_add(data, "service_port", json_object_new_int(service_port));

    json_object_object_add(data, "dest_ip", json_object_new_string((const char *)dest_ip));

    json_object_object_add(root, "type", json_object_new_string("push_port_punch"));
    json_object_object_add(root, "data", data);

    size_t len;

    const char *s_data = json_object_to_json_string_length(root, 0, &len);

    if (len < 1)
    {
        return -2;
    }

    char new_data[len + 1];
    strncpy((char *)new_data, s_data, len);
    //printf("Char before => %c.\n", new_data[len]);
    new_data[len] = '\n';
    //new_data[len] = '\0';

    int ret = socket_send(cfg, new_data, len + 1);

    json_object_put(root);

    return ret;
}

/**
 * Parses values from validated connections and send to Killtrocity -> Killfrenzy.
 * 
 * @param cfg Pointer to config_t variable.
 * @param src_ip The validated source IP.
 * @param src_port The validated source port.
 * @param dst_ip The validated destination IP.
 * @param dst_port The validated destination port.
 * @param last_seen The last seen for the connection.
 * 
 * @return < 1 on failure. Otherwise, amount of bytes sent.
**/
int config_parse_and_send_validated_connection(config_t *cfg, char *src_ip, unsigned short src_port, char *dst_ip, unsigned short dst_port)
{
    struct json_object *root;
    struct json_object *data;

    root = json_object_new_object();
    data = json_object_new_object();

    json_object_object_add(data, "src_ip", json_object_new_string((const char *)src_ip));
    json_object_object_add(data, "src_port", json_object_new_int(src_port));

    json_object_object_add(data, "dst_ip", json_object_new_string((const char *)dst_ip));
    json_object_object_add(data, "dst_port", json_object_new_int(dst_port));

    json_object_object_add(root, "type", json_object_new_string("push_validated_client"));
    json_object_object_add(root, "data", data);

    size_t len;

    const char *s_data = json_object_to_json_string_length(root, 0, &len);

    if (len < 1)
    {
        return -2;
    }
    
    char new_data[len + 1];
    strncpy((char *)new_data, s_data, len);
    //printf("Char before => %c.\n", new_data[len]);
    new_data[len] = '\n';
    //new_data[len] = '\0';

    int ret = socket_send(cfg, new_data, len + 1);

    json_object_put(root);

    return ret;
}

/**
 * Parses values from port punch into JSON and sends them to socket.
 * 
 * @param cfg Pointer to config_t variable.
 * @param ip The bind IP.
 * @param port The bind port.
 * @param resp The A2S_INFO response
 * @param expires The A2S_INFO expire time.
 * 
 * @return < 1 on failure. Otherwise, amount of bytes sent.
**/
int config_parse_and_send_a2s_response(config_t *cfg, const char *ip, unsigned short port, const char *resp, u64 expires)
{
    struct json_object *root;
    struct json_object *data;

    root = json_object_new_object();
    data = json_object_new_object();

    json_object_object_add(data, "ip", json_object_new_string((const char *)ip));
    json_object_object_add(data, "port", json_object_new_int(port));
    json_object_object_add(data, "expires", json_object_new_int64(expires));

    json_object_object_add(data, "response", json_object_new_string((const char *)resp));

    json_object_object_add(root, "type", json_object_new_string("push_a2s_response"));
    json_object_object_add(root, "data", data);

    size_t len;

    const char *s_data = json_object_to_json_string_length(root, 0, &len);

    return socket_send(cfg, s_data, len);
}