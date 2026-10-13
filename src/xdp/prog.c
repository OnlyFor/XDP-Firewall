#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <common/all.h>

#include <xdp/utils/rl.h>
#include <xdp/utils/rule.h>
#include <xdp/utils/stats.h>
#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

#ifdef ENABLE_ARP_FILTER
// 手动定义 ARP 相关内容，避免引入 <linux/if_arp.h> 中依赖 struct sockaddr 的 arpreq 结构体
// （BPF 编译环境没有 <sys/socket.h>，直接 include 整个头文件会报错）。
// linux/if_arp.h doesn't compile under -target bpf, define locally.
#define ARPHRD_ETHER 1

struct arphdr {
    __be16 ar_hrd;
    __be16 ar_pro;
    u8      ar_hln;
    u8      ar_pln;
    __be16 ar_op;
} __attribute__((packed));
#endif

struct
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog_main);

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Retrieve stats map value.
    u32 key = 0;
    stats_t* stats = bpf_map_lookup_elem(&map_stats, &key);

    // Scan ethernet header.
    struct ethhdr *eth = data;

    // Check if the ethernet header is valid.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

#ifdef ENABLE_ARP_FILTER
    // ARP filter: only allow ARP requests targeting our IP.
    if (eth->h_proto == htons(ETH_P_ARP))
    {
        struct arphdr *arp = data + sizeof(struct ethhdr);

        // Ethernet ARP = arphdr(8) + SHA(6) + SPA(4) + THA(6) + TPA(4) = 28 bytes.
        if (unlikely((void *)arp + sizeof(struct arphdr) + 2 * ETH_ALEN + 2 * 4 > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }

        // Check if ARP filter is enabled (my_ips_cnt > 0).
        u32 zero = 0;
        u32 *arp_enabled = bpf_map_lookup_elem(&map_arp_enabled, &zero);

        // Only filter Ethernet/IPv4 ARP; let other ARP variants fall through.
        // if (arp->ar_hrd == htons(ARPHRD_ETHER) && arp->ar_pro == htons(ETH_P_IP))
        if (arp_enabled && *arp_enabled &&
            arp->ar_hrd == htons(ARPHRD_ETHER) && arp->ar_pro == htons(ETH_P_IP))
        {
            // Walk to target IP field: skip arphdr(8) + SHA(6) + SPA(4) + THA(6) = 24 bytes.
            u8 *ptr = (u8 *)arp + sizeof(struct arphdr) + ETH_ALEN + 4 + ETH_ALEN;
            u32 ar_tip;
            __builtin_memcpy(&ar_tip, ptr, 4);

            // u32 key = 0;
            // u32 *my_ip = bpf_map_lookup_elem(&map_my_ip, &key);
            // // Drop if target IP is not ours (my_ip == 0 means unconfigured, let all pass).
            // if (my_ip && *my_ip != 0 && ar_tip != *my_ip)
            u8 *found = bpf_map_lookup_elem(&map_my_ip, &ar_tip);
            if (!found)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
        }
    }
#endif

    // Check Ethernet protocol.
#ifdef ENABLE_IPV6
    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
#else
    if (unlikely(eth->h_proto != htons(ETH_P_IP)))
#endif
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);

        return XDP_PASS;
    }

    // Initialize IP headers.
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    u128 src_ip6 = 0;

    // Set IPv4 and IPv6 common variables.
    if (eth->h_proto == htons(ETH_P_IP))
    {
        iph = data + sizeof(struct ethhdr);

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }
    }
#ifdef ENABLE_IPV6
    else
    {
        iph6 = data + sizeof(struct ethhdr);

        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }

        memcpy(&src_ip6, iph6->saddr.in6_u.u6_addr32, sizeof(src_ip6));
    }
#endif

    // We only want to process TCP, UDP, and ICMP protocols.
    if ((iph && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP) || (iph6 && iph6->nexthdr != IPPROTO_UDP && iph6->nexthdr != IPPROTO_TCP && iph6->nexthdr != IPPROTO_ICMPV6))
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);

        return XDP_PASS;
    }

    // Retrieve nanoseconds since system boot as timestamp.
    u64 now = bpf_ktime_get_ns();

    // Check block map.
    u64 *blocked = NULL;

    if (iph)
    {
        blocked = bpf_map_lookup_elem(&map_block, &iph->saddr);
    }
#ifdef ENABLE_IPV6
    else
    {
        blocked = bpf_map_lookup_elem(&map_block6, &src_ip6);
    }
#endif

    if (blocked != NULL)
    {
        if (*blocked > 0 && now > *blocked)
        {
            // Remove element from map.
            if (iph)
            {
                bpf_map_delete_elem(&map_block, &iph->saddr);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_delete_elem(&map_block6, &src_ip6);
            }
#endif
        }
        else
        {
#ifdef DO_STATS_ON_BLOCK_MAP
            // Increase blocked stats entry.
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

            // They're still blocked. Drop the packet.
            return XDP_DROP;
        }
    }

#ifdef ENABLE_IP_RANGE_DROP
    if (iph && check_ip_range_drop(iph->saddr))
    {
#ifdef DO_STATS_ON_IP_RANGE_DROP_MAP
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

        return XDP_DROP;
    }
#endif

#ifdef ENABLE_UDP_JUNK_FILTER
    // Drop UDP junk: multicast/broadcast destinations or known junk ports.
    // Self-contained — does not depend on udph from ENABLE_FILTERS block.
    if ((iph && iph->protocol == IPPROTO_UDP) ||
        (iph6 && iph6->nexthdr == IPPROTO_UDP))
    {
        struct udphdr *udph_j = iph
            ? (void *)iph + (iph->ihl * 4)
            : (void *)iph6 + sizeof(struct ipv6hdr);

        if (likely((void *)udph_j + sizeof(struct udphdr) <= data_end))
        {
            int junk_dst = 0;

            if (iph)
            {
                // 224.0.0.0/4 multicast: MSB byte in [0xE0, 0xEF].
                // 255.255.255.255 limited broadcast: all-ones (same in any byte order).
                u8 msb = *((u8 *)&iph->daddr);
                junk_dst = (msb >= 0xE0 && msb <= 0xEF) || (iph->daddr == 0xFFFFFFFF);
            }
            else
            {
                // IPv6 multicast = ff00::/8.
                junk_dst = (iph6->daddr.in6_u.u6_addr8[0] == 0xff);
            }

            // Multicast/broadcast short-circuits first; only non-multicast
            // packets reach the port checks.
            u16 dport = ntohs(udph_j->dest);

            if (junk_dst ||
                dport == 5353  ||                   // mDNS
                dport == 1900  ||                   // UPnP/SSDP
                dport == 5355  ||                   // LLMNR
                dport == 5060  ||                   // SIP
                dport == 161   ||                   // SNMP
                dport == 389   ||                   // CLDAP（苹果，公网反射放大）
                dport == 17    ||                   // QOTD（经典反射源，~100x 放大）
                dport == 5683  ||                   // CoAP/LwM2M（IoT 反射重灾区）
                dport == 69    ||                   // TFTP
                dport == 19    ||                   // chargen
                dport == 111   ||                   // rpcbind/Portmapper
                (dport >= 137 && dport <= 138) ||   // NetBIOS
                dport == 67    ||                   // DHCP server
                dport == 21027 ||                   // Syncthing
                dport == 1968  ||                   // ?
                dport == 4466  ||                   // ?
                dport == 33445 ||                  // Tailscale
                // ↓ Uncomment if not running these services:
                // dport == 123   ||                // NTP
                // dport == 53    ||                // DNS
                // dport == 11211 ||                // memcached
                0)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
        }
    }
#endif

#ifdef ENABLE_NDP_FILTER
    if (iph6 && iph6->nexthdr == IPPROTO_ICMPV6)
    {
        struct icmp6hdr *icmp6_hdr = (void *)iph6 + sizeof(struct ipv6hdr);

        // Check ICMPv6 header (8B) — enough to read type.
        if (likely((void *)icmp6_hdr + sizeof(struct icmp6hdr) <= data_end))
        {
            u8 type = icmp6_hdr->icmp6_type;

            // 133 = RS, 137 = Redirect, 130/131/132 = MLD, 143 = MLDv2,
            // 138 = Router Renumbering, 139 = Node Information Query.
            if (type == 133 || type == 137 ||
                type == 130 || type == 131 || type == 132 ||
                type == 143 || type == 138 || type == 139)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            // NS (135) / NA (136): whitelist by target address.
            // Need additional 16B for target address beyond the 8B ICMPv6 header.
            if ((type == 135 || type == 136) &&
                likely((void *)icmp6_hdr + 24 <= data_end))
            {
                u32 zero = 0;
                u32 *ndp_enabled = bpf_map_lookup_elem(&map_ndp_enabled, &zero);

                if (ndp_enabled && *ndp_enabled)
                {
                    u128 ndp_target;
                    __builtin_memcpy(&ndp_target, (u8 *)icmp6_hdr + 8, sizeof(ndp_target));

                    u8 *found = bpf_map_lookup_elem(&map_my_ip6, &ndp_target);

                    if (!found)
                    {
                        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                        return XDP_DROP;
                    }
                }
            }
        }
    }
#endif

#ifdef ENABLE_FILTERS
    // Retrieve total packet length.
    u16 pkt_len = data_end - data;

    // Parse layer-4 headers and determine source port and protocol.
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;

    struct icmp6hdr *icmp6h = NULL;

    u16 src_port = 0;

#ifdef ENABLE_FILTER_LOGGING
    u16 dst_port = 0;
#endif

    u8 protocol = 0;

    if (iph)
    {
        protocol = iph->protocol;

        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = tcph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = tcph->dest;
#endif

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check UDP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = udph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = udph->dest;
#endif

                break;

            case IPPROTO_ICMP:
                // Scan ICMP header.
                icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check ICMP header.
                if (unlikely(icmph + 1 > (struct icmphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                break;
        }
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
        protocol = iph6->nexthdr;

        switch (iph6->nexthdr)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = tcph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = tcph->dest;
#endif

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check TCP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = udph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = udph->dest;
#endif

                break;

            case IPPROTO_ICMPV6:
                // Scan ICMPv6 header.
                icmp6h = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check ICMPv6 header.
                if (unlikely(icmp6h + 1 > (struct icmp6hdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                break;
        }
    }
#endif

#ifdef ENABLE_FILTERS
    // Update client stats (PPS/BPS).
    u64 ip_pps = 0;
    u64 ip_bps = 0;

    u64 flow_pps = 0;
    u64 flow_bps = 0;

#if defined(ENABLE_RL_IP) || defined(ENABLE_RL_FLOW)
    if (iph)
    {
#ifdef ENABLE_RL_IP
        update_ip_stats(&ip_pps, &ip_bps, iph->saddr, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow_stats(&flow_pps, &flow_bps, iph->saddr, src_port, protocol, pkt_len, now);
#endif
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
#ifdef ENABLE_RL_IP
        update_ip6_stats(&ip_pps, &ip_bps, &src_ip6, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow6_stats(&flow_pps, &flow_bps, &src_ip6, src_port, protocol, pkt_len, now);
#endif
    }
#endif
#endif
#endif

    // Create rule context.
    rule_ctx_t rule = {0};
    rule.flow_pps = flow_pps;
    rule.flow_bps = flow_bps;
    rule.ip_pps = ip_pps;
    rule.ip_bps = ip_bps;
    rule.pkt_len = pkt_len;

#ifdef ENABLE_FILTER_LOGGING
    rule.now = now;
    rule.protocol = protocol;
    rule.src_port = src_port;
    rule.dst_port = dst_port;
#endif

    rule.iph = iph;

    rule.tcph = tcph;
    rule.udph = udph;
    rule.icmph = icmph;

    rule.iph6 = iph6;
    rule.icmph6 = icmp6h;

#ifdef USE_NEW_LOOP
    bpf_loop(MAX_FILTERS, process_rule, &rule, 0);
#else
#pragma unroll 30
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        if (process_rule(i, &rule))
        {
            break;
        }
    }
#endif

    if (rule.matched)
    {
        goto matched;
    }
#endif

    inc_pkt_stats(stats, STATS_TYPE_PASSED);

    return XDP_PASS;

#ifdef ENABLE_FILTERS
matched:
    if (rule.action == 0)
    {
        // Before dropping, update the block map.
        if (rule.block_time > 0)
        {
            u64 new_time = now + (rule.block_time * NANO_TO_SEC);

            if (iph)
            {
                bpf_map_update_elem(&map_block, &iph->saddr, &new_time, BPF_ANY);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_update_elem(&map_block6, &src_ip6, &new_time, BPF_ANY);
            }
#endif
        }

        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }
    else
    {
        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
    }

    return XDP_PASS;
#endif
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);
