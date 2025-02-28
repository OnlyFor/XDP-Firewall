#include <loader/utils/xdp.h>

/**
 * Finds a BPF map's FD.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
 */
int FindMapFd(struct xdp_program *prog, const char *map_name)
{
    int fd = -1;

    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    if (obj == NULL)
    {
        fprintf(stderr, "Error finding BPF object from XDP program.\n");

        goto out;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", map_name);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}

/**
 * Custom print function for LibBPF that doesn't print anything (silent mode).
 * 
 * @param level The current LibBPF log level.
 * @param format The message format.
 * @param args Format arguments for the message.
 * 
 * @return void
 */
static int LibBPFSilent(enum libbpf_print_level level, const char *format, va_list args)
{
    return 0;
}

/**
 * Sets custom LibBPF log mode.
 * 
 * @param silent If 1, disables LibBPF logging entirely.
 * 
 * @return void
 */
void SetLibBPFLogMode(int silent)
{
    if (silent)
    {
        libbpf_set_print(LibBPFSilent);
    }
}

/**
 * Loads a BPF object file.
 * 
 * @param file_name The path to the BPF object file.
 * 
 * @return XDP program structure (pointer) or NULL.
 */
struct xdp_program *LoadBpfObj(const char *file_name)
{
    struct xdp_program *prog = xdp_program__open_file(file_name, "xdp_prog", NULL);

    if (prog == NULL)
    {
        // The main function handles this error.
        return NULL;
    }

    return prog;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mode_used The mode being used.
 * @param ifidx The index to the interface to attach to.
 * @param detach If above 0, attempts to detach XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return 0 on success and 1 on error.
 */
int AttachXdp(struct xdp_program *prog, char** mode, int ifidx, u8 detach, cmdline_t *cmd)
{
    int err;

    u32 attach_mode = XDP_MODE_NATIVE;

    *mode = "DRV/native";

    if (cmd->offload)
    {
        *mode = "HW/offload";

        attach_mode = XDP_MODE_HW;
    }
    else if (cmd->skb)
    {
        *mode = "SKB/generic";
        
        attach_mode = XDP_MODE_SKB;
    }

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        if (detach)
        {
            err = xdp_program__detach(prog, ifidx, attach_mode, 0);
        }
        else
        {
            err = xdp_program__attach(prog, ifidx, attach_mode, 0);
        }

        if (err)
        {
            // Decrease mode.
            switch (attach_mode)
            {
                case XDP_MODE_HW:
                    attach_mode = XDP_MODE_NATIVE;
                    *mode = "DRV/native";

                    break;

                case XDP_MODE_NATIVE:
                    attach_mode = XDP_MODE_SKB;
                    *mode = "SKB/generic";

                    break;

                case XDP_MODE_SKB:
                    // Exit loop.
                    exit = 1;

                    *mode = NULL;
                    
                    break;
            }

            // Retry.
            continue;
        }
        
        // Success, so break current loop.
        break;
    }

    // If exit is set to 1 or smode is NULL, it indicates full failure.
    if (exit || *mode == NULL)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Updates the filter's BPF map with current config settings.
 * 
 * @param map_filters The filter's BPF map FD.
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
 */
void UpdateFilters(int map_filters, config__t *cfg)
{
    int ret;
    int cur_idx = 0;

    // Add a filter to the filter maps.
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_t* filter = &cfg->filters[i];

        // Delete previous rule from BPF map.
        // We do this in the case rules were edited and were put out of order since the key doesn't uniquely map to a specific rule.
        u32 key = i;

        bpf_map_delete_elem(map_filters, &key);

        // Only insert set and enabled filters.
        if (!filter->set || !filter->enabled)
        {
            continue;
        }

        // Create value array (max CPUs in size) since we're using a per CPU map.
        filter_t filter_cpus[MAX_CPUS];
        memset(filter_cpus, 0, sizeof(filter_cpus));

        for (int j = 0; j < MAX_CPUS; j++)
        {
            filter_cpus[j] = *filter;
        }

        // Attempt to update BPF map.
        if ((ret = bpf_map_update_elem(map_filters, &cur_idx, &filter_cpus, BPF_ANY)) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to update filter #%d due to BPF update error (%d)...\n", i, ret);
        }

        cur_idx++;
    }
}