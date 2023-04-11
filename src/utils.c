#include "utils.h"

/**
 * Raises the RLimit.
 * 
 * @return Returns 0 on success (EXIT_SUCCESS) or 1 on failure (EXIT_FAILURE).
**/
int utils_raise_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Retrieves maximum CPU count (useful for RX queue calculation).
 * 
 * @return Number of CPUs.
**/
unsigned int utils_cpu_cnt()
{
    static const char *fcpu = "/sys/devices/system/cpu/possible";
    unsigned int start, end, possible_cpus = 0;
    char buff[128];
    FILE *fp;
    int n;

    fp = fopen(fcpu, "r");

    if (!fp) 
    {
        printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
        exit(1);
    }

    while (fgets(buff, sizeof(buff), fp)) 
    {
        n = sscanf(buff, "%u-%u", &start, &end);

        if (n == 0) 
        {
            printf("Failed to retrieve # possible CPUs!\n");

            return 0;
        } 
        else if (n == 1) 
        {
            end = start;
        }

        possible_cpus = start == 0 ? end + 1 : 0;

        break;
    }

    fclose(fp);

    return possible_cpus;
}

/**
 * Loads an XDP/BPF program.
 * 
 * @param bpf_prog Path to BPF object file.
 * @param if_idx The index to the interface to attach to.
 * @param prog_fd A file description (FD) to the BPF/XDP program.
 * 
 * @return The BPF object or NULL on error.
**/
struct xdp_program *utils_xdp_prog_load(const char *bpf_prog, int if_idx, int *prog_fd)
{
    struct xdp_program *prog = NULL;

    int err = 0;    

    prog = xdp_program__open_file(bpf_prog, "kilimanjaro_xdp", NULL);

    if (prog == NULL)
    {
        fprintf(stderr, "Error opening XDP program.\n");
    }
    
    return prog;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param if_idx The index to the interface to attach to.
 * @param prog XDP program object file.
 * @param detach Whether we are detaching the program.
 * @param force_mode If set to 1, forces SKB mode. If set to 2, forces offload mode.
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
**/
int utils_attach_xdp(int if_idx, struct xdp_program *prog, int detach, int force_mode)
{
    int err;

    char *smode;

    u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    u32 mode = XDP_MODE_NATIVE;

    smode = "DRV/native";

    if (force_mode == 2)
    {
        smode = "HW/offload";

        mode = XDP_MODE_HW;
    }
    else if (force_mode == 1)
    {
        smode = "SKB/generic";
        mode = XDP_MODE_SKB;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        if (detach)
        {
            err = xdp_program__detach(prog, if_idx, mode, 0);
        }
        else
        {
            err = xdp_program__attach(prog, if_idx, mode, 0);
        }

        if (err)
        {
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_MODE_HW:
                    mode = XDP_MODE_NATIVE;
                    flags &= ~XDP_MODE_HW;
                    errmode = "HW/offload";

                    break;

                case XDP_MODE_NATIVE:
                    mode = XDP_MODE_SKB;
                    flags &= ~XDP_MODE_NATIVE;
                    errmode = "DRV/native";

                    break;

                case XDP_MODE_SKB:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";

                    break;
            }

            if (mode != -err)
            {
                smode = (mode == XDP_MODE_HW) ? "HW/offload" : (mode == XDP_MODE_NATIVE) ? "DRV/native" : (mode == XDP_MODE_SKB) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            if (!detach)
            {
                fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);
            }

            break;
        }
    }

    return mode;
}

int utils_bpf_map_get_next_key_and_delete(int fd, const void *key, void *next_key, int *delete)
{
    int res = bpf_map_get_next_key(fd, key, next_key);

    if (*delete) 
    {
        bpf_map_delete_elem(fd, key);
        *delete = 0;
    }

    return res;
}