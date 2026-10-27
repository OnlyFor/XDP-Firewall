#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <loader/utils/xdp.h>
#include <loader/utils/config.h>

#include <time.h>
#include <rule_del/utils/cli.h>

// These are required due to being extern with Loader.
// To Do: Figure out a way to not require the below without requiring separate object files.
int cont = 0;
int doing_stats = 0;

// 与内核 bpf_ktime_get_ns() 完全一致的单调时钟（纳秒）
static u64 get_ktime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

int main(int argc, char *argv[])
{
    int ret;

    // Parse command line.
    cli_t cli = {0};
    cli.cfg_file = CONFIG_DEFAULT_PATH;

    parse_cli(&cli, argc, argv);

    if (!cli.help)
    {
        printf("Parsed command line...\n");
    } else
    {
        printf("Usage: xdpfw-del [OPTIONS]\n\n");
        printf("OPTIONS:\n");
        printf("  -c, --cfg         The path to the config file (default /etc/xdpfw/xdpfw.conf).\n");
        printf("  -s, --save        Saves the new config to file system.\n");
        printf("  -m, --mode        The mode to use (0 = filters, 1 = IPv4 range drop, 2 = IP block map, 3 = GC & stats all maps, 4 = IP allow map).\n");
        printf("  -i, --idx         The filters index to remove when using filters mode (0) (index starts from 1; retrieve index using xdpfw -l).\n");
        printf("  -d, --ip          The IP range or single IP to use (for modes 1 and 2).\n");
        printf("  -v, --v6          If set, parses IP address as IPv6 when removing from block map (for mode 2).\n");

        return EXIT_SUCCESS;
    }

    // Check for config file path.
    if ((cli.save || cli.mode == 0) && (!cli.cfg_file || strlen(cli.cfg_file) < 1))
    {
        fprintf(stderr, "[ERROR] CFG file not specified or empty. This is required for current mode or options set.\n");

        return EXIT_FAILURE;
    }

    // Load config.
    config__t cfg = {0};

    if (cli.save || cli.mode == 0)
    {
        if ((ret = load_cfg(&cfg, cli.cfg_file, 1, NULL)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to load config at '%s' (%d)\n", cli.cfg_file, ret);

            return EXIT_FAILURE;
        }

        printf("Loaded config...\n");
    }

    // Handle filters mode.
    if (cli.mode == 0)
    {
        printf("Using filters mode (0)...\n");

        // Check index.
        if (cli.idx < 1 || cli.idx > MAX_FILTERS || !cfg.filters[cli.idx - 1].set)
        {
            fprintf(stderr, "Invalid filter index. Index must start from 1.\n");

            return EXIT_FAILURE;
        }

        // Retrieve filters map FD.
        int map_filters = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_filters");

        if (map_filters < 0)
        {
            fprintf(stderr, "[ERROR] Failed to retrieve BPF map 'map_filters' from file system.\n");

            return EXIT_FAILURE;
        }

        printf("Using 'map_filters' FD => %d...\n", map_filters);

        int cfg_idx = cli.idx - 1;
        // Always remove from the in-memory config; --save only controls disk IO.
        // update_filters() handles compaction around disabled/unset rules.
        cfg.filters[cfg_idx].set = 0;

        // Update filters.
        fprintf(stdout, "Updating filters...\n");

        if (update_filters(map_filters, &cfg) != 0)
        {
            return EXIT_FAILURE;
        }
    }
    // Handle IPv4 range drop mode.
    else if (cli.mode == 1)
    {
        printf("Using IPv4 range drop mode (1)...\n");

        // Make sure IP range is specified.
        if (!cli.ip)
        {
            fprintf(stderr, "No IP address or range specified. Please set an IP range using -s, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        // Get range map.
        int map_range_drop = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_range_drop");

        if (map_range_drop < 0)
        {
            fprintf(stderr, "Failed to retrieve 'map_range_drop' BPF map FD.\n");

            return EXIT_FAILURE;
        }

        printf("Using 'map_range_drop' FD => %d.\n", map_range_drop);

        // Parse IP range.
        ip_range_t range = parse_ip_range(cli.ip);
        if (!range.success)
        {
            fprintf(stderr, "Invalid IPv4 range: %s\n", cli.ip);
            return EXIT_FAILURE;
        }

        // Attempt to delete range.
        if ((ret = delete_range_drop(map_range_drop, range.ip, range.cidr)) != 0)
        {
            fprintf(stderr, "Error deleting range from BPF map (%d).\n", ret);

            return EXIT_FAILURE;
        }

        printf("Removed IP range '%s'...\n", cli.ip);

        if (cli.save)
        {
            // Loop through IP drop ranges and unset if found.
            for (int i = 0; i < MAX_IP_RANGES; i++)
            {
                const char* cur_range = cfg.drop_ranges[i];

                if (!cur_range)
                {
                    continue;
                }

                if (strcmp(cur_range, cli.ip) != 0)
                {
                    continue;
                }

                free((void*)cfg.drop_ranges[i]);
                cfg.drop_ranges[i] = NULL;
            }
        }
    }
    // Handle block map mode.
    else if (cli.mode == 2)
    {
        printf("Using source IP block mode (2)...\n");

        if (!cli.ip)
        {
            fprintf(stderr, "No source IP address specified. Please set an IP using -s, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        int map_block = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_block");
        int map_block6 = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_block6");

        if (cli.v6)
        {
            if (map_block6 < 0)
            {
                fprintf(stderr, "Failed to find the 'map_block6' BPF map.\n");

                return EXIT_FAILURE;
            }

            printf("Using 'map_block6' FD => %d.\n", map_block6);

            struct in6_addr addr;

            if ((ret = inet_pton(AF_INET6, cli.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert IPv6 address '%s' to decimal (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }

            u128 ip;
            memcpy(&ip, &addr, sizeof(ip));

            if ((ret = delete_block6(map_block6, ip)) != 0)
            {
                fprintf(stderr, "Failed to delete IP '%s' from BPF map (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }
        }
        else
        {
            if (map_block < 0)
            {
                fprintf(stderr, "Failed to find the 'map_block' BPF map.\n");

                return EXIT_FAILURE;
            }

            printf("Using 'map_block' FD => %d.\n", map_block);

            struct in_addr addr;

            if ((ret = inet_pton(AF_INET, cli.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert IP address '%s' to decimal (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }

            if ((ret = delete_block(map_block, addr.s_addr)) != 0)
            {
                fprintf(stderr, "Failed to delete IP '%s' from BPF map (%d).\n", cli.ip, ret);

                return EXIT_FAILURE;
            }

            printf("Deleted IP '%s'...\n", cli.ip);
        }
    }
    // Handle GC & real-time stats mode (mode 3).
    else if (cli.mode == 3)
    {
        printf("Running GC & consistency cleanup on pinned BPF maps (mode 3)...\n");

        u64 now = get_ktime_ns();

        int map_block     = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_block");
        int map_allow     = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow");
        int map_allow_ip  = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow_ip");
        int map_block6    = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_block6");
        int map_allow6    = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow6");
        int map_allow_ip6 = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow_ip6");

        // 1. GC IPv4 map_block (删除已到期黑名单)
        if (map_block >= 0)
        {
            u32 cur_k = 0, next_k = 0;
            u64 exp = 0;
            u64 active = 0, expired = 0;
            int has_cur = (bpf_map_get_next_key(map_block, NULL, &cur_k) == 0);

            while (has_cur)
            {
                int has_next = (bpf_map_get_next_key(map_block, &cur_k, &next_k) == 0);
                if (bpf_map_lookup_elem(map_block, &cur_k, &exp) == 0)
                {
                    if (exp > 0 && now > exp)
                    {
                        bpf_map_delete_elem(map_block, &cur_k);
                        expired++;
                    }
                    else
                    {
                        active++;
                    }
                }
                cur_k = next_k;
                has_cur = has_next;
            }
            printf("  [map_block]     active: %-6llu | expired_del: %-6llu\n", active, expired);
        }

        // 2. GC IPv4 map_allow_ip (删除已到期，或已被 map_block 封禁的单 IP 白名单)
        if (map_allow_ip >= 0)
        {
            u32 cur_k = 0, next_k = 0;
            u64 exp = 0, blk_exp = 0;
            u64 active = 0, expired = 0, conflict = 0;
            int has_cur = (bpf_map_get_next_key(map_allow_ip, NULL, &cur_k) == 0);

            while (has_cur)
            {
                int has_next = (bpf_map_get_next_key(map_allow_ip, &cur_k, &next_k) == 0);
                if (bpf_map_lookup_elem(map_allow_ip, &cur_k, &exp) == 0)
                {
                    if (now >= exp)
                    {
                        bpf_map_delete_elem(map_allow_ip, &cur_k);
                        expired++;
                    }
                    else if (map_block >= 0 && bpf_map_lookup_elem(map_block, &cur_k, &blk_exp) == 0 &&
                                (blk_exp == 0 || blk_exp > now))
                    {
                        bpf_map_delete_elem(map_allow_ip, &cur_k);
                        conflict++;
                    }
                    else
                    {
                        active++;
                    }
                }
                cur_k = next_k;
                has_cur = has_next;
            }
            printf("  [map_allow_ip]  active: %-6llu | expired_del: %-6llu | blocked_del: %-6llu\n", active, expired, conflict);
        }

        // 3. GC IPv4 map_allow (删除已到期，或源 IP 已不在 map_allow_ip 中的孤儿五元组)
        if (map_allow >= 0)
        {
            allow_key4_t cur_k = {0}, next_k = {0};
            u64 exp = 0, ip_exp = 0;
            u64 active = 0, expired = 0, orphan = 0;
            int has_cur = (bpf_map_get_next_key(map_allow, NULL, &cur_k) == 0);

            while (has_cur)
            {
                int has_next = (bpf_map_get_next_key(map_allow, &cur_k, &next_k) == 0);
                if (bpf_map_lookup_elem(map_allow, &cur_k, &exp) == 0)
                {
                    if (now >= exp)
                    {
                        bpf_map_delete_elem(map_allow, &cur_k);
                        expired++;
                    }
                    else if (map_allow_ip >= 0 &&
                                (bpf_map_lookup_elem(map_allow_ip, &cur_k.src_ip, &ip_exp) != 0 || now >= ip_exp))
                    {
                        // 单 IP 白名单已被踢出或过期，连带清理该 IP 残留的五元组
                        bpf_map_delete_elem(map_allow, &cur_k);
                        orphan++;
                    }
                    else
                    {
                        active++;
                    }
                }
                cur_k = next_k;
                has_cur = has_next;
            }
            printf("  [map_allow]     active: %-6llu | expired_del: %-6llu | orphan_del:  %-6llu\n", active, expired, orphan);
        }

        // 4. GC IPv6 map_block6
        if (map_block6 >= 0)
        {
            u128 cur_k = 0, next_k = 0;
            u64 exp = 0;
            u64 active = 0, expired = 0;
            int has_cur = (bpf_map_get_next_key(map_block6, NULL, &cur_k) == 0);

            while (has_cur)
            {
                int has_next = (bpf_map_get_next_key(map_block6, &cur_k, &next_k) == 0);
                if (bpf_map_lookup_elem(map_block6, &cur_k, &exp) == 0)
                {
                    if (exp > 0 && now > exp)
                    {
                        bpf_map_delete_elem(map_block6, &cur_k);
                        expired++;
                    }
                    else
                    {
                        active++;
                    }
                }
                cur_k = next_k;
                has_cur = has_next;
            }
            printf("  [map_block6]    active: %-6llu | expired_del: %-6llu\n", active, expired);
        }

        // 5. GC IPv6 map_allow_ip6
        if (map_allow_ip6 >= 0)
        {
            u128 cur_k = 0, next_k = 0;
            u64 exp = 0, blk_exp = 0;
            u64 active = 0, expired = 0, conflict = 0;
            int has_cur = (bpf_map_get_next_key(map_allow_ip6, NULL, &cur_k) == 0);

            while (has_cur)
            {
                int has_next = (bpf_map_get_next_key(map_allow_ip6, &cur_k, &next_k) == 0);
                if (bpf_map_lookup_elem(map_allow_ip6, &cur_k, &exp) == 0)
                {
                    if (now >= exp)
                    {
                        bpf_map_delete_elem(map_allow_ip6, &cur_k);
                        expired++;
                    }
                    else if (map_block6 >= 0 && bpf_map_lookup_elem(map_block6, &cur_k, &blk_exp) == 0 &&
                                (blk_exp == 0 || blk_exp > now))
                    {
                        bpf_map_delete_elem(map_allow_ip6, &cur_k);
                        conflict++;
                    }
                    else
                    {
                        active++;
                    }
                }
                cur_k = next_k;
                has_cur = has_next;
            }
            printf("  [map_allow_ip6] active: %-6llu | expired_del: %-6llu | blocked_del: %-6llu\n", active, expired, conflict);
        }

        // 6. GC IPv6 map_allow6
        if (map_allow6 >= 0)
        {
            allow_key6_t cur_k = {0}, next_k = {0};
            u64 exp = 0, ip_exp = 0;
            u64 active = 0, expired = 0, orphan = 0;
            int has_cur = (bpf_map_get_next_key(map_allow6, NULL, &cur_k) == 0);

            while (has_cur)
            {
                int has_next = (bpf_map_get_next_key(map_allow6, &cur_k, &next_k) == 0);
                if (bpf_map_lookup_elem(map_allow6, &cur_k, &exp) == 0)
                {
                    if (now >= exp)
                    {
                        bpf_map_delete_elem(map_allow6, &cur_k);
                        expired++;
                    }
                    else if (map_allow_ip6 >= 0 &&
                                (bpf_map_lookup_elem(map_allow_ip6, &cur_k.src_ip6, &ip_exp) != 0 || now >= ip_exp))
                    {
                        bpf_map_delete_elem(map_allow6, &cur_k);
                        orphan++;
                    }
                    else
                    {
                        active++;
                    }
                }
                cur_k = next_k;
                has_cur = has_next;
            }
            printf("  [map_allow6]    active: %-6llu | expired_del: %-6llu | orphan_del:  %-6llu\n", active, expired, orphan);
        }
    }
    // Handle allow map single-IP eviction mode (mode 4: 删除某 IP 的白名单及所有关联五元组).
    else if (cli.mode == 4)
    {
        printf("Using source IP allow-evict mode (4)...\n");

        if (!cli.ip)
        {
            fprintf(stderr, "No source IP address specified. Please set an IP using -d, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        if (cli.v6)
        {
            struct in6_addr addr;
            if ((ret = inet_pton(AF_INET6, cli.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to parse IPv6 address '%s'.\n", cli.ip);
                return EXIT_FAILURE;
            }

            u128 ip6 = 0;
            memcpy(&ip6, &addr, sizeof(ip6));

            int map_allow_ip6 = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow_ip6");
            int map_allow6    = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow6");

            if (map_allow_ip6 >= 0)
            {
                bpf_map_delete_elem(map_allow_ip6, &ip6);
            }

            u64 del_flows = 0;
            if (map_allow6 >= 0)
            {
                allow_key6_t cur_k = {0}, next_k = {0};
                int has_cur = (bpf_map_get_next_key(map_allow6, NULL, &cur_k) == 0);
                while (has_cur)
                {
                    int has_next = (bpf_map_get_next_key(map_allow6, &cur_k, &next_k) == 0);
                    if (cur_k.src_ip6 == ip6)
                    {
                        bpf_map_delete_elem(map_allow6, &cur_k);
                        del_flows++;
                    }
                    cur_k = next_k;
                    has_cur = has_next;
                }
            }
            printf("Removed IPv6 '%s' from allow_ip6 and deleted %llu flow(s) from map_allow6.\n", cli.ip, del_flows);
        }
        else
        {
            struct in_addr addr;
            if ((ret = inet_pton(AF_INET, cli.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to parse IPv4 address '%s'.\n", cli.ip);
                return EXIT_FAILURE;
            }

            u32 ip4 = addr.s_addr;
            int map_allow_ip = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow_ip");
            int map_allow    = get_map_fd_pin(XDP_MAP_PIN_DIR, "map_allow");

            if (map_allow_ip >= 0)
            {
                bpf_map_delete_elem(map_allow_ip, &ip4);
            }

            u64 del_flows = 0;
            if (map_allow >= 0)
            {
                allow_key4_t cur_k = {0}, next_k = {0};
                int has_cur = (bpf_map_get_next_key(map_allow, NULL, &cur_k) == 0);
                while (has_cur)
                {
                    int has_next = (bpf_map_get_next_key(map_allow, &cur_k, &next_k) == 0);
                    if (cur_k.src_ip == ip4)
                    {
                        bpf_map_delete_elem(map_allow, &cur_k);
                        del_flows++;
                    }
                    cur_k = next_k;
                    has_cur = has_next;
                }
            }
            printf("Removed IPv4 '%s' from allow_ip and deleted %llu flow(s) from map_allow.\n", cli.ip, del_flows);
        }
    }
    else
    {
        fprintf(stderr, "Invalid mode '%d'. Valid modes: 0 (filters), 1 (range), 2 (block IP), 3 (GC all), 4 (allow IP).\n", cli.mode);
        return EXIT_FAILURE;
    }

    if (cli.save)
    {
        // Save config.
        printf("Saving config...\n");

        if ((ret = save_cfg(&cfg, cli.cfg_file)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to save config.\n");

            return EXIT_FAILURE;
        }
    }

    printf("Success! Exiting.\n");

    return EXIT_SUCCESS;
}
