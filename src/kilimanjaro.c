#include "kilimanjaro.h"

volatile int stop = 0;

/**
 * Handles signals and stops program if found.
 * 
 * @param tmp A temporary variable.
 * 
 * @return Void
**/
void signal_handle(int tmp)
{
    stop = 1;
}

int main(int argc, char **argv)
{
    // Raise RLimit
    if (utils_raise_rlimit() != 0)
    {
        fprintf(stderr, "Error setting rlimit. Please ensure you're running this program as a privileged user.\n");

        return EXIT_FAILURE;
    }

    // Parse command line.
    cmd_line_t cmd = {0};

    cmd_line_parse(&cmd, argc, argv);

    // Check for version output.
    if (cmd.version)
    {
        fprintf(stdout, "%s", VERSION);

        return EXIT_SUCCESS;
    }

    // Check for help output.
    if (cmd.help)
    {
        fprintf(stdout, "Usage: kilimanjaro [-vlh]\n" \
                        "--version -v => Outputs current version to stdout.\n" \
                        "--list -l => Outputs list of configuration.\n" \
                        "--help -h => Outputs help menu.\n");

        return EXIT_SUCCESS;
    }

    // Retrieve config settings.
    char *cfg_file = "/etc/kilimanjaro/kilimanjaro.json";

    config_t cfg = {0};

    if(config_parse(cfg_file, &cfg) != 0)
    {
        fprintf(stderr, "Error parsing config file :: %s (%d).\n", strerror(errno), errno);

        return EXIT_FAILURE;
    }

    // Check for list option.
    if (cmd.list)
    {
        unsigned int i;
        fprintf(stdout, "Main Options\n");
        fprintf(stdout, "\tInterface => %s.\n", (cfg.interface != NULL) ? cfg.interface : "NULL");
        fprintf(stdout, "\tEdge IP => %s.\n", (cfg.edge_ip != NULL) ? cfg.edge_ip : "NULL");
        fprintf(stdout, "\tForce Mode => %s.\n", (cfg.force_mode == 1) ? "SKB" : (cfg.force_mode == 2) ? "Offload" : "Off");
        fprintf(stdout, "\tVerbose => %s.\n", cfg.verbose ? "True" : "False");
        fprintf(stdout, "\tCalculate Stats => %s.\n", cfg.calc_stats ? "True" : "False");
        fprintf(stdout, "\tAllow All Edge => %s.\n", cfg.allow_all_edge ? "True" : "False");

        fprintf(stdout, "\nAF_XDP Options.\n");
        fprintf(stdout, "\tSocket Count => %d (0 = CPU count).\n", cfg.socket_count);
        fprintf(stdout, "\tStatic Queue ID => %s.\n", cfg.queue_is_static ? "True" : "False");

        if (cfg.queue_is_static)
        {
            fprintf(stdout, "\tQueue ID => %d.\n", cfg.queue_id);
        }

        fprintf(stdout, "\tZero Copy => %s.\n", cfg.zero_copy ? "True" : "False");
        fprintf(stdout, "\tNeed Wakeup => %s.\n", cfg.need_wakeup ? "True" : "False");
        fprintf(stdout, "\tBatch Size => %d.\n", cfg.batch_size);

        fprintf(stdout, "\nConnections\n");
        for (i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (cfg.connections[i].is_set < 1)
            {
                break;
            }

            fprintf(stdout, "\tConnection #%d\n", i);
            fprintf(stdout, "\t\tEnabled => %s.\n", cfg.connections[i].is_enabled ? "True" : "False");
            fprintf(stdout, "\t\tProtocol => %s.\n", cfg.connections[i].protocol);
            fprintf(stdout, "\t\tBind IP => %s.\n", cfg.connections[i].bind_ip);
            fprintf(stdout, "\t\tBind Port => %d.\n", cfg.connections[i].bind_port);
            fprintf(stdout, "\t\tDestination IP => %s.\n", cfg.connections[i].dest_ip);
            fprintf(stdout, "\t\tDestination Port => %d (0 = use bind port).\n", cfg.connections[i].dest_port);

            fprintf(stdout, "\t\tFilters => ");
            
            if (cfg.connections[i].filters & FILTER_TYPE_SRCDS)
            {
                fprintf(stdout, "SRCDS, ");
            }

            if (cfg.connections[i].filters & FILTER_TYPE_RUST)
            {
                fprintf(stdout, "Rust, ");
            }

            if (cfg.connections[i].filters & FILTER_TYPE_GMOD)
            {
                fprintf(stdout, "GMOD, ");
            }

            fprintf(stdout, ".\n\n");

            fprintf(stdout, "\t\tUDP Rate Limits\n");
            fprintf(stdout, "\t\t\tPPS => %llu.\n", cfg.connections[i].udp_rl.pps);
            fprintf(stdout, "\t\t\tBPS => %llu.\n", cfg.connections[i].udp_rl.bps);
            fprintf(stdout, "\t\t\tBlock Time => %u seconds.\n\n", cfg.connections[i].udp_rl.block_time);

            fprintf(stdout, "\t\tTCP Rate Limits\n");
            fprintf(stdout, "\t\t\tPPS => %llu.\n", cfg.connections[i].tcp_rl.pps);
            fprintf(stdout, "\t\t\tBPS => %llu.\n", cfg.connections[i].tcp_rl.bps);
            fprintf(stdout, "\t\t\tBlock Time => %u seconds.\n\n", cfg.connections[i].tcp_rl.block_time);

            fprintf(stdout, "\t\tICMP Rate Limits\n");
            fprintf(stdout, "\t\t\tPPS => %llu.\n", cfg.connections[i].icmp_rl.pps);
            fprintf(stdout, "\t\t\tBPS => %llu.\n", cfg.connections[i].icmp_rl.bps);
            fprintf(stdout, "\t\t\tBlock Time => %u seconds.\n\n", cfg.connections[i].icmp_rl.block_time);

            fprintf(stdout, "\t\tSYN Settings\n");
            fprintf(stdout, "\t\t\tPPS => %llu.\n", cfg.connections[i].syn_settings.rl.pps);
            fprintf(stdout, "\t\t\tBPS => %llu.\n", cfg.connections[i].syn_settings.rl.bps);
            fprintf(stdout, "\t\t\tBlock Time => %u seconds.\n\n", cfg.connections[i].syn_settings.rl.block_time);

            fprintf(stdout, "\t\tCache Settings\n");
            fprintf(stdout, "\t\t\tA2S_INFO => %s.\n", cfg.connections[i].cache_settings.A2S_INFO ? "True" : "False");
            fprintf(stdout, "\t\t\tA2S_INFO Cache Time => %u seconds.\n", cfg.connections[i].cache_settings.A2S_INFO_time);
            fprintf(stdout, "\t\t\tA2S_INFO Global Cache => %s.\n", cfg.connections[i].cache_settings.A2S_INFO_global_cache ? "True" : "False");
            fprintf(stdout, "\t\t\tA2S_INFO Cache Timeout => %u seconds.\n", cfg.connections[i].cache_settings.A2S_INFO_cache_timeout);
        }

        fprintf(stdout, "\nWhitelist\n");
        for (i = 0; i < MAX_WHITELIST; i++)
        {
            if (strlen(cfg.whitelist[i].prefix) < 3)
            {
                continue;
            }

            fprintf(stdout, "\t- %s.\n", cfg.whitelist[i].prefix);
        }

        fprintf(stdout, "\nBlacklist\n");
        for (i = 0; i < MAX_BLACKLIST; i++)
        {
            if (strlen(cfg.blacklist[i].prefix) < 3)
            {
                continue;
            }

            fprintf(stdout, "\t- %s.\n", cfg.blacklist[i].prefix);
        }

        fprintf(stdout, "\nPort Punches\n");
        for (i = 0; i < MAX_PORT_PUNCH; i++)
        {
            if (cfg.port_punch[i].ip == NULL || cfg.port_punch[i].service_ip == NULL)
            {
                continue;
            }

            fprintf(stdout, "\t- %s:%d => %s:%d (%s).\n", cfg.port_punch[i].ip, cfg.port_punch[i].port, cfg.port_punch[i].service_ip, cfg.port_punch[i].service_port, cfg.port_punch[i].dest_ip);
        }

        fprintf(stdout, "\nValidated Clients\n");
        for (i = 0; i < MAX_CLIENTS_VALIDATED; i++)
        {
            if (cfg.validated_client[i].src_ip == NULL || cfg.validated_client[i].dst_ip == NULL)
            {
                continue;
            }

            fprintf(stdout, "\t- %s:%d => %s:%d.\n", cfg.validated_client[i].src_ip, cfg.validated_client[i].src_port, cfg.validated_client[i].dst_ip, cfg.validated_client[i].dst_port);
        }

        return EXIT_SUCCESS;
    }

    // Check interface name.
    if (cfg.interface == NULL)
    {
        fprintf(stderr, "No interface specified.\n");

        return EXIT_FAILURE;
    }

    // Retrieve interface index and check if it's valid.
    int if_idx = if_nametoindex(cfg.interface);

    if (if_idx < 1)
    {
        fprintf(stderr, "Interface '%s' not found.\n", cfg.interface);

        return EXIT_FAILURE;
    }

    // Load the XDP program.
    int prog_fd;

    const char *bpf_obj = "/etc/kilimanjaro/xdp_prog.o";

    struct xdp_program *obj = utils_xdp_prog_load(bpf_obj, if_idx, &prog_fd);

    if (obj == NULL)
    {
        fprintf(stderr, "Error loading BPF object file.\n");

        return EXIT_FAILURE;
    }

    // Attempt to attach program.
    int err = 0;

    err = utils_attach_xdp(if_idx, obj, 0, cfg.force_mode);

    if (err != XDP_MODE_HW && err != XDP_MODE_NATIVE && err != XDP_MODE_SKB)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(-err), err);

        return EXIT_FAILURE;
    }
    
    // Retrieve XDP maps.
    xdp_maps_t xdp_maps = {0};

    maps_get(obj, &xdp_maps);

    // Check connections map.
    if (xdp_maps.connections < 1)
    {
        fprintf(stderr, "Error finding connections map from BPF object file.\n");

        return EXIT_FAILURE;
    }

    unsigned i;

    // Insert connections into map.
    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (cfg.connections[i].is_set < 1)
        {
            continue;
        }

        if (maps_insert_connection(&cfg, &xdp_maps, &cfg.connections[i]) != 0)
        {
            fprintf(stderr, "ERROR - Inserting connection into map at index %d.\n", i);
        }
    }

    // Insert connections whitelist map.
    for (i = 0; i < MAX_WHITELIST; i++)
    {
        if (strlen(cfg.whitelist[i].prefix) < 3)
        {
            continue;
        }

        if (maps_insert_whitelist(&cfg, &xdp_maps, &cfg.whitelist[i]) != 0)
        {
            fprintf(stderr, "ERROR - Inserting whitelist into map at index %d.\n", i);
        }
    }

    // Insert connections blacklist map.
    for (i = 0; i < MAX_BLACKLIST; i++)
    {
        if (strlen(cfg.blacklist[i].prefix) < 3)
        {
            continue;
        }

        if (maps_insert_blacklist(&cfg, &xdp_maps, &cfg.blacklist[i]) != 0)
        {
            fprintf(stderr, "ERROR - Inserting blacklist into map at index %d.\n", i);
        }
    }

    // Insert port punches into map.
    for (i = 0; i < MAX_PORT_PUNCH; i++)
    {
        if (cfg.port_punch[i].ip == NULL || cfg.port_punch[i].service_ip == NULL || cfg.port_punch[i].dest_ip == NULL)
        {
            continue;
        }

        if (maps_insert_port_punch(&cfg, &xdp_maps, &cfg.port_punch[i]))
        {
            fprintf(stderr, "ERROR - Inserting port punch into map at index %d.\n", i);
        }
    }

    // Insert validated clients into map.
    for (i = 0; i < MAX_CLIENTS_VALIDATED; i++)
    {
        if (cfg.validated_client[i].src_ip == NULL || cfg.validated_client[i].dst_ip == NULL)
        {
            continue;
        }

        if (maps_insert_validated_client(&cfg, &xdp_maps, &cfg.validated_client[i]))
        {
            fprintf(stderr, "ERROR - Inserting validated client into map at index %d.\n", i);
        }
    }

    // Insert edge IP into BPF map.
    if (maps_insert_edge_ip(&cfg, &xdp_maps) != 0)
    {
        fprintf(stderr, "WARNING - Failed to insert edge IP into map!\n");
    }

    // Insert XDP config into BPF map.
    if (maps_insert_xdp_config(&cfg, &xdp_maps) != 0)
    {
        fprintf(stderr, "WARNING - Failed to insert XDP config into map!\n");
    }

    // Setup socket and listen.
    if (socket_create() == 0)
    {
        socket_listen(&cfg, &xdp_maps);
    }
    else
    {
        fprintf(stderr, "Socket error => %s\n", strerror(errno));
    }

    // Setup AF_XDP variables.
    af_xdp_setup_variables(&cfg);

    // Setup AF_XDP sockets.
    af_xdp_setup_sockets(&cfg, &xdp_maps);

    // Setup signals.
    signal(SIGINT, signal_handle);
    signal(SIGTERM, signal_handle);

    // Create loop.
    while (!stop)
    {
        maps_push_port_punches(&cfg, &xdp_maps);
        maps_push_validated_connections(&cfg, &xdp_maps);
        maps_calc_stats(&cfg, &xdp_maps);

        sleep(1);
    }

    // Detach XDP program.
    utils_attach_xdp(if_idx, obj, 1, cfg.force_mode);

    // Close XDP program.
    xdp_program__close(obj);

    // Close global socket.
    socket_close();

    // Exit program successfully.
    return EXIT_SUCCESS;
}