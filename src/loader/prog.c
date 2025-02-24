#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <signal.h>

#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>

#include <net/if.h>

#include <loader/utils/cmdline.h>
#include <loader/utils/config.h>
#include <loader/utils/xdp.h>
#include <loader/utils/stats.h>
#include <loader/utils/helpers.h>

int cont = 1;

int main(int argc, char *argv[])
{
    int ret;

    // Parse the command line.
    cmdline_t cmd = {0};
    cmd.cfgfile = CONFIG_DEFAULT_PATH;

    ParseCommandLine(&cmd, argc, argv);

    // Check for help.
    if (cmd.help)
    {
        PrintHelpMenu();

        return EXIT_SUCCESS;
    }

    // Raise RLimit.
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        fprintf(stderr, "[ERROR] Failed to raise rlimit. Please make sure this program is ran as root!\n");

        return EXIT_FAILURE;
    }

    // Initialize config.
    config__t cfg = {0};

    SetCfgDefaults(&cfg);

    // Load config.
    if ((ret = LoadConfig(&cfg, cmd.cfgfile)) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to load config from file system (%s)(%d).\n", cmd.cfgfile, ret);

        return EXIT_FAILURE;
    }

    // Check for list option.
    if (cmd.list)
    {
        PrintConfig(&cfg);

        return EXIT_SUCCESS;
    }

    // Get interface index.
    int ifidx = if_nametoindex(cfg.interface);

    if (ifidx < 0)
    {
        fprintf(stderr, "[ERROR] Failed to retrieve index of network interface '%s'.\n", cfg.interface);

        return EXIT_FAILURE;
    }

    // Load BPF object.
    struct xdp_program *prog = LoadBpfObj(XDP_OBJ_PATH);

    if (prog == NULL)
    {
        fprintf(stderr, "[ERROR] Failed to load eBPF object file. Object path => %s.\n", XDP_OBJ_PATH);

        return EXIT_FAILURE;
    }
    
    // Attach XDP program.
    if ((ret = AttachXdp(prog, ifidx, 0, &cmd)) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to attach XDP program to interface '%s' (%d).\n", cfg.interface, ret);

        return EXIT_FAILURE;
    }

    // Retrieve BPF maps.
    int filters_map = FindMapFd(prog, "filters_map");

    // Check for valid maps.
    if (filters_map < 0)
    {
        fprintf(stderr, "[ERROR] Failed to find 'filters_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    int stats_map = FindMapFd(prog, "stats_map");

    if (stats_map < 0)
    {
        fprintf(stderr, "[ERROR] Failed to find 'stats_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    // Update BPF maps.
    UpdateFilters(filters_map, &cfg);

    // Signal.
    signal(SIGINT, SignalHndl);
    signal(SIGTERM, SignalHndl);

    // Receive CPU count for stats map parsing.
    int cpus = get_nprocs_conf();

    unsigned int end_time = (cmd.time > 0) ? time(NULL) + cmd.time : 0;

    // Create last updated variables.
    time_t last_update_check = time(NULL);
    time_t last_config_check = time(NULL);

    unsigned int sleep_time = cfg.stdout_update_time * 1000;

    struct stat conf_stat;

    while (cont)
    {
        // Get current time.
        time_t cur_time = time(NULL);

        // Check if we should end the program.
        if (end_time > 0 && cur_time >= end_time)
        {
            break;
        }

        // Check for auto-update.
        if (cfg.updatetime > 0 && (cur_time - last_update_check) > cfg.updatetime)
        {
            // Check if config file have been modified
            if (stat(cmd.cfgfile, &conf_stat) == 0 && conf_stat.st_mtime > last_config_check) {
                // Memleak fix for strdup() in LoadConfig()
                // Before updating it again, we need to free the old return value
                free(cfg.interface);

                // Update config.
                if ((ret = LoadConfig(&cfg, cmd.cfgfile)) != 0)
                {
                    fprintf(stderr, "[WARNING] Failed to load config after update check (%d)\n", ret);
                }

                // Update BPF maps.
                UpdateFilters(filters_map, &cfg);

                // Update timer
                last_config_check = time(NULL);
            }

            // Update last updated variable.
            last_update_check = time(NULL);
        }

        // Calculate and display stats if enabled.
        if (!cfg.nostats)
        {
            if (CalculateStats(stats_map, cpus))
            {
                fprintf(stderr, "[WARNING] Failed to calculate packet stats. Stats map FD => %d.\n", stats_map);
            }
        }

        usleep(sleep_time);
    }

    fprintf(stdout, "\n");

    // Detach XDP program.
    if (AttachXdp(prog, ifidx, 1, &cmd))
    {
        fprintf(stderr, "[ERROR] Failed to detach XDP program from interface '%s'.\n", cfg.interface);

        return EXIT_FAILURE;
    }

    fprintf(stdout, "Cleaned up and exiting...\n");

    // Exit program successfully.
    return EXIT_SUCCESS;
}