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
    u128 dst_ip6 = 0;          // ← 新增

    // =========================================================================
    // Stage 1: L3 Header Parsing, Sanity Check & "Not-My-IP" Destination Filter
    // Executed BEFORE bpf_ktime_get_ns() and map_block lookup so malformed,
    // truncated, bogon-spoofed, or neighbor-flooded packets are dropped early.
    // =========================================================================
    if (eth->h_proto == htons(ETH_P_IP))
    {
        iph = data + sizeof(struct ethhdr);

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        u16 tot_len = ntohs(iph->tot_len);
        u16 ihl_len = iph->ihl * 4;
        u8  s_msb   = *((u8 *)&iph->saddr);
        u8  d_msb   = *((u8 *)&iph->daddr);

        // 1. Version must be 4; ihl >= 20B; tot_len >= ihl_len;
        // 2. Truncated packet check: (void *)iph + tot_len > data_end;
        // 3. Bogon source IPs (RFC 1122 §3.2.1.3 / RFC 6890):
        //    - 0.0.0.0/8   (s_msb == 0)
        //    - 127.0.0.0/8 (s_msb == 127 or d_msb == 127, loopback on external NIC)
        //    - 224.0.0.0/3 (s_msb >= 0xE0, multicast + reserved + broadcast)
        // 4. LAND attack: saddr == daddr on external interface;
        // 5. Cross-protocol mismatch: IPPROTO_ICMPV6 (58) inside an IPv4 packet.
        if (unlikely(iph->version != 4 ||
                        iph->ihl < 5 ||
                        tot_len < ihl_len ||
                        (void *)iph + tot_len > data_end ||
                        s_msb == 0 || s_msb == 127 || d_msb == 127 || s_msb >= 0xE0 ||
                        iph->saddr == iph->daddr ||
                        iph->protocol == IPPROTO_ICMPV6))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

#ifdef ENABLE_ARP_FILTER
        // ---- Global IPv4 Destination Filter (Covers TCP / UDP / ICMP / All Protocols) ----
        // Drops all IPv4 packets whose dst_ip is NOT our own IP (when my_ips is configured):
        //   1. Eliminates host-bridge "unknown unicast flooding" (neighbor VPS traffic on 443, etc.);
        //   2. Eliminates unauthorized routing/forwarding probes from L2 neighbors;
        //   3. Automatically drops IPv4 multicast/broadcast traffic since they are not in map_my_ip.
        // Do NOT call junk_block_src() here because saddr on flooded packets may be a
        // legitimate external server talking to a neighbor VPS.
        {
            u32 zero = 0;
            u32 *arp_enabled = bpf_map_lookup_elem(&map_arp_enabled, &zero);

            if (arp_enabled && *arp_enabled)
            {
                u32 daddr_check;
                __builtin_memcpy(&daddr_check, &iph->daddr, sizeof(daddr_check));

                if (!bpf_map_lookup_elem(&map_my_ip, &daddr_check))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }
        }
#endif
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
        memcpy(&dst_ip6, iph6->daddr.in6_u.u6_addr32, sizeof(dst_ip6));    // ← 新增

        u16 plen   = ntohs(iph6->payload_len);
        u8  s6_msb = iph6->saddr.in6_u.u6_addr8[0];

        // 1. Version must be 6;
        // 2. Truncated IPv6 payload: (void *)(iph6 + 1) + plen > data_end;
        // 3. Multicast source (ff00::/8, RFC 4291 §2.7) is never valid;
        // 4. LAND attack: src_ip6 == dst_ip6 (also catches :: -> ::);
        // 5. Unspecified source (::) is only valid in DAD Neighbor Solicitation (ICMPv6),
        //    never in TCP/UDP or other protocols;
        // 6. Cross-protocol mismatch: IPv4 ICMP (1) or No-Next-Header (59) on IPv6.
        if (unlikely(iph6->version != 6 ||
                        (void *)(iph6 + 1) + plen > data_end ||
                        s6_msb == 0xff ||
                        (__builtin_memcmp(&src_ip6, &dst_ip6, sizeof(src_ip6)) == 0) ||
                        (src_ip6 == 0 && iph6->nexthdr != IPPROTO_ICMPV6) ||
                        iph6->nexthdr == IPPROTO_ICMP ||
                        iph6->nexthdr == 59))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

#ifdef ENABLE_NDP_FILTER
        // ---- Global IPv6 Destination Filter (Covers TCP / UDP / Non-ICMPv6) ----
        // For TCP, UDP, and all non-ICMPv6 protocols, dst_ip6 MUST be either:
        //   - One of our configured global IPv6 addresses in map_my_ip6, OR
        //   - A link-local address (fe80::/10).
        // Note: IPPROTO_ICMPV6 is intentionally skipped here and checked inside
        // ENABLE_NDP_FILTER below, because NDP (134 RA / 135 NS / 136 NA) uses
        // multicast (ff02::) as outer dst_ip6 and carries the target IP inside the payload.
        if (iph6->nexthdr != IPPROTO_ICMPV6)
        {
            u8 d0 = iph6->daddr.in6_u.u6_addr8[0];
            u8 d1 = iph6->daddr.in6_u.u6_addr8[1];
            int is_link_local_dst = (d0 == 0xfe && (d1 & 0xc0) == 0x80);

            if (!is_link_local_dst)
            {
                u32 zero = 0;
                u32 *ndp_enabled = bpf_map_lookup_elem(&map_ndp_enabled, &zero);

                if (ndp_enabled && *ndp_enabled &&
                    !bpf_map_lookup_elem(&map_my_ip6, &dst_ip6))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }
        }
#endif
    }
#endif

    // Retrieve nanoseconds since system boot as timestamp.
    u64 now = bpf_ktime_get_ns();

    // Check block map.
    // =========================================================================
    // Stage 2: Block Map & IP Range Drop (Checked BEFORE L4 Protocol Filter!)
    // Placed before protocol filtering so banned IPs cannot bypass the block
    // map by sending GRE, IPIP, SCTP, IGMP, or IPv6 extension-header packets.
    // =========================================================================
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

    // =========================================================================
    // Stage 3: L3 Protocol Number Filter
    // Drop invalid/reconnaissance IP protocols (nmap -sO, protocol floods)
    // and only process TCP, UDP, and ICMP/ICMPv6 downstream.
    // =========================================================================
    if ((iph && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP) ||
        (iph6 && iph6->nexthdr != IPPROTO_UDP && iph6->nexthdr != IPPROTO_TCP && iph6->nexthdr != IPPROTO_ICMPV6))
    {
        // Drop known invalid/scan/flood L3 protocols on a public VPS:
        //   - IPv4 protocol 0 (zero-init flood), 2 (IGMP), 88 (EIGRP), 89 (OSPF),
        //     103 (PIM), 112 (VRRP), 144..255 (IANA unassigned/experimental/reserved)
        //   - IPv6 nexthdr 0 (Hop-by-Hop DoS), 43 (Routing Header), 144..255
        if ((iph && (iph->protocol == 0 || iph->protocol == 2 ||
                        iph->protocol == 88 || iph->protocol == 89 ||
                        iph->protocol == 103 || iph->protocol == 112 ||
                        iph->protocol >= 144)) ||
            (iph6 && (iph6->nexthdr == 0 || iph6->nexthdr == 43 ||
                        iph6->nexthdr >= 144)))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        inc_pkt_stats(stats, STATS_TYPE_PASSED);
        return XDP_PASS;
    }

// Do not parse L4 on non-first fragments — payload would be misread
// as TCP/UDP/ICMP headers. tcph/udph/icmph stay NULL; rules that
// require L4 fields simply won't match, IP-level rules still apply.

// Non-first IPv4 fragments (offset != 0) carry no L4 header.
int is_nonfirst_frag = (iph && (iph->frag_off & htons(0x1FFF)));

    // =========================================================================
    // Stage 4: ICMPv4 & ICMPv6 / NDP Pre-Filters
    // =========================================================================
#ifdef ENABLE_ARP_FILTER
    // IPv4 ICMP pre-filter:
    // Note: dst_ip ownership (map_my_ip), bogon saddr, and LAND attack were ALREADY
    // verified in Stage 1 above, so no duplicate map_my_ip lookup is needed here!
    if (iph && iph->protocol == IPPROTO_ICMP)
    {
        u8 d_msb = *((u8 *)&iph->daddr);

        // Fallback multicast/broadcast destination drop (Smurf amplification, RFC 2644)
        // in case map_arp_enabled (my_ips) is not configured in xdpfw.conf.
        if (unlikely((d_msb >= 0xE0 && d_msb <= 0xEF) || iph->daddr == 0xFFFFFFFF))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // ---- Step 3: L4 ICMPv4 header & payload sanity (on first/unfragmented packet) ----
        if (!is_nonfirst_frag)
        {
            struct icmphdr *icmph_j = (void *)iph + (iph->ihl * 4);

            // Truncated ICMP header (< 8B) is always malformed.
            if (unlikely((void *)icmph_j + sizeof(struct icmphdr) > data_end))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            u8 type = icmph_j->type;
            u8 code = icmph_j->code;

            // Strict RFC whitelist for ICMPv4 types & codes:
            //   - Type 0/8 (Echo Reply/Request): code MUST be 0 (non-zero = Nmap/Sing OS probe)
            //   - Type 3   (Dest Unreachable):   code 0..15 (includes Code 4 PMTUD)
            //   - Type 11  (Time Exceeded):      code 0..1
            //   - Type 12  (Parameter Problem):  code 0..2
            // Drops Timestamp (13/14), Info (15/16), Address Mask (17/18), Redirect (5), Source Quench (4).
            int valid_icmp4 =
                ((type == 0 || type == 8) && code == 0) ||
                (type == 3  && code <= 15) ||
                (type == 11 && code <= 1)  ||
                (type == 12 && code <= 2);

            if (unlikely(!valid_icmp4))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // RFC 792 / RFC 1812: ICMPv4 Error messages (Type 3, 11, 12) must carry at least
            // 8B icmphdr + 20B offending iphdr + 8B L4 = 36B, and are never fragmented (MF=1).
            if ((type == 3 || type == 11 || type == 12) &&
                unlikely((void *)icmph_j + 36 > data_end || (iph->frag_off & htons(0x2000))))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }
    }
#endif

#ifdef ENABLE_NDP_FILTER
    // IPv6 ICMPv6 & NDP pre-filter:
    // Because Stage 1 skipped IPPROTO_ICMPV6, we validate NDP target (Case A)
    // and non-NDP outer dst_ip6 (Case B) against map_my_ip6 here.
    if (iph6 && iph6->nexthdr == IPPROTO_ICMPV6)
    {
        struct icmp6hdr *icmp6_hdr = (void *)iph6 + sizeof(struct ipv6hdr);

        if (unlikely((void *)icmp6_hdr + sizeof(struct icmp6hdr) > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        u8 type = icmp6_hdr->icmp6_type;
        u8 code = icmp6_hdr->icmp6_code;

        // ---- Case A: On-link NDP (134 RA, 135 NS, 136 NA) ----
        // (RS 133 and Redirect 137 fall into Case B and are dropped.)
        if (type == 134 || type == 135 || type == 136)
        {
            // RFC 4861 §6.1.2 / §7.1.1: hop_limit MUST be 255 and code MUST be 0.
            // Blocks all off-link routed NDP spoofing / neighbor-table exhaustion attacks.
            if (unlikely(iph6->hop_limit != 255 || code != 0))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // RA (134): source address MUST be link-local fe80::/10 (RFC 4861 §6.1.2).
            if (type == 134)
            {
                u8 s0 = iph6->saddr.in6_u.u6_addr8[0];
                u8 s1 = iph6->saddr.in6_u.u6_addr8[1];
                if (unlikely(s0 != 0xfe || (s1 & 0xc0) != 0x80))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }
            // NS (135) / NA (136): validate 16B inner target address against map_my_ip6.
            else
            {
                if (unlikely((void *)icmp6_hdr + 24 > data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }

                u32 zero = 0;
                u32 *ndp_enabled = bpf_map_lookup_elem(&map_ndp_enabled, &zero);

                if (ndp_enabled && *ndp_enabled)
                {
                    u128 ndp_target;
                    __builtin_memcpy(&ndp_target, (u8 *)icmp6_hdr + 8, sizeof(ndp_target));

                    if (!bpf_map_lookup_elem(&map_my_ip6, &ndp_target))
                    {
                        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                        return XDP_DROP;
                    }
                }
            }
        }
        // ---- Case B: Non-NDP ICMPv6 (Errors 1..4 & Echo 128/129) ----
        else
        {
            int valid_icmp6 =
                ((type == 128 || type == 129 || type == 2) && code == 0) ||
                (type == 1 && code <= 6) ||
                (type == 3 && code <= 1) ||
                (type == 4 && code <= 2);

            // Drop non-whitelisted types (130-133, 137-153, etc.), unspecified source (::),
            // or multicast destination (ff00::/8 ping sweeps).
            if (unlikely(!valid_icmp6 || src_ip6 == 0 ||
                            iph6->daddr.in6_u.u6_addr8[0] == 0xff))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // Ensure outer dst_ip6 is ours (or link-local fe80::/10) — required here
            // because Stage 1 skipped IPPROTO_ICMPV6!
            u8 d0 = iph6->daddr.in6_u.u6_addr8[0];
            u8 d1 = iph6->daddr.in6_u.u6_addr8[1];
            if (!(d0 == 0xfe && (d1 & 0xc0) == 0x80))
            {
                u32 zero = 0;
                u32 *ndp_enabled = bpf_map_lookup_elem(&map_ndp_enabled, &zero);

                if (ndp_enabled && *ndp_enabled &&
                    !bpf_map_lookup_elem(&map_my_ip6, &dst_ip6))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }

            // RFC 4443 §2.4(c): ICMPv6 Error (Type 1..4) must carry at least
            // 8B icmp6hdr + 40B offending ipv6hdr = 48B total.
            if (type <= 4 && unlikely((void *)icmp6_hdr + 48 > data_end))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }
    }
#endif


    // =========================================================================
    // Stage 5: TCP Stateless Pre-Filter
    // =========================================================================
#ifdef ENABLE_TCP_JUNK_FILTER
    if (!is_nonfirst_frag &&
        ((iph && iph->protocol == IPPROTO_TCP) ||
         (iph6 && iph6->nexthdr == IPPROTO_TCP)))
    {
        // RFC 7126: Legitimate internet TCP traffic never carries IPv4 Options (ihl > 5).
        if (unlikely(iph && iph->ihl != 5))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        struct tcphdr *tcph_j = iph
            ? (void *)iph + sizeof(struct iphdr)
            : (void *)iph6 + sizeof(struct ipv6hdr);

        if (likely((void *)tcph_j + sizeof(struct tcphdr) <= data_end))
        {
            // ---- Step 0a: TCP port 0 — IANA reserved ----
            if (tcph_j->source == 0 || tcph_j->dest == 0)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 0b: Fragmented SYN (RFC 1858) & TCP doff sanity ----
            if ((iph && tcph_j->syn && (iph->frag_off & htons(0x2000))) ||
                tcph_j->doff < 5 ||
                (void *)tcph_j + (tcph_j->doff * 4) > data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            u16 dport = ntohs(tcph_j->dest);
            u16 sport = ntohs(tcph_j->source);

            // ---- Step 0c: Junk destination ports ----
            // 注意本机 net.ipv4.ip_local_reserved_ports 需要预留高端口
            int junk_port = (
                dport == 20    ||                  // FTP data
                dport == 21    ||                  // FTP control
                dport == 631   ||                  // IPP/CUPS
                dport == 3418  ||                  // IoT M2M
                dport == 23    ||                  // Telnet — Mirai
                dport == 2323  ||                  // Telnet alt
                dport == 7547  ||                  // TR-069 CWMP
                dport == 8291  ||                  // MikroTik WinBox
                dport == 8728  ||                  // MikroTik API
                dport == 5555  ||                  // Android ADB
                dport == 2375  ||                  // Docker API
                dport == 9200  ||                  // Elasticsearch
                dport == 37215 ||                  // Huawei router scan
                dport == 53413 ||                  // Netis backdoor scan
                dport == 52869 ||                  // Realtek SDK scan
                dport == 55552 ||                  // Mirai variant
                dport == 81    ||                  // Webcam/Web admin
                dport == 8888  ||                  // Web admin scan
                dport == 10250 ||                  // Kubernetes kubelet
                (dport >= 135 && dport <= 139) ||  // MS-RPC/NetBIOS
                dport == 445   ||                  // SMB
                dport == 593   ||                  // MS-RPC HTTP
                dport == 7680  ||                  // Windows Delivery Optimization
                dport == 5357  ||                  // WSD
                dport == 5358  ||                  // WSD Secure
                (dport >= 49664 && dport <= 49670) || // WinRPC dynamic range
                dport == 3306  ||                  // MySQL
                dport == 5432  ||                  // PostgreSQL
                dport == 3389  ||                  // RDP
                0);

            if (junk_port)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 0d: Multicast/broadcast destination (invalid for TCP) ----
            int junk_dst = 0;
            if (iph)
            {
                u8 msb = *((u8 *)&iph->daddr);
                junk_dst = (msb >= 0xE0 && msb <= 0xEF) || (iph->daddr == 0xFFFFFFFF);
            }
#ifdef ENABLE_IPV6
            else if (iph6)
            {
                junk_dst = (iph6->daddr.in6_u.u6_addr8[0] == 0xff);
            }
#endif
            if (junk_dst)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 1: Illegal pure SYN (doff < 6, window == 0, oversized, or spoofed well-known sport) ----
            // 1. doff < 6: missing 4B MSS option = raw-socket flood (hping3/ZMap).
            // 2. window == 0: a brand-new SYN never advertises a 0 receive window.
            // 3. flen > ceil: oversized SYN beyond max TFO size (604B IPv4 / 624B IPv6).
            // 4. sport in {20,21,22,23,25,53,80,110,123,143,443}: external clients initiating
            //    a handshake never allocate privileged service ports as ephemeral source ports
            //    (catches `nmap -g 53` / `nmap -g 80` / `hping3 -s 80` source-port spoofing).
            if (tcph_j->syn && !tcph_j->ack && !tcph_j->fin &&
                !tcph_j->rst && !tcph_j->psh && !tcph_j->urg)
            {
                u16 flen = data_end - data;
                u16 ceil = iph ? 604 : 624;
                int spoofed_syn_sport = (
                    sport == 20 || sport == 21 || sport == 22  || sport == 23  ||
                    sport == 25 || sport == 53 || sport == 80  || sport == 110 ||
                    sport == 123 || sport == 143 || sport == 443
                );

                if (tcph_j->doff < 6 || tcph_j->window == 0 ||
                    flen > ceil || spoofed_syn_sport)
                {
#if JUNK_FILTER_BLOCK_TIME > 0
                    junk_block_src(iph, iph6, &src_ip6, now);
#endif
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }

            // ---- Step 2: Illegal SYN flag combos & SYN+ACK reflection to privileged ports ----
            // 1. SYN + FIN/RST/PSH/URG is always illegal.
            // 2. SYN+ACK targeting dport < 1024 (e.g. 22/80/443): our outbound connections
            //    always use ephemeral ports (>= 1024), so an incoming SYN+ACK to < 1024 is
            //    100% a spoofed SYN-ACK reflection/amplification attack!
            if (tcph_j->syn &&
                (tcph_j->fin || tcph_j->rst || tcph_j->psh || tcph_j->urg ||
                    (tcph_j->ack && dport < 1024)))
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 3: NULL scan (all 6 flags clear) ----
            if (!tcph_j->syn && !tcph_j->ack && !tcph_j->fin &&
                !tcph_j->rst && !tcph_j->psh && !tcph_j->urg)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 4: Stealth scan (FIN/PSH/URG without SYN or ACK) ----
            if (!tcph_j->syn && !tcph_j->ack && !tcph_j->rst &&
                (tcph_j->fin || tcph_j->psh || tcph_j->urg))
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 5a: RST combined with FIN, PSH, or URG; or URG=1 with urg_ptr==0 ----
            // RST aborts immediately and never carries FIN, PSH, or URG.
            // RFC 9293: URG=1 requires a non-zero urgent pointer offset.
            if ((tcph_j->rst && (tcph_j->fin || tcph_j->psh || tcph_j->urg)) ||
                (tcph_j->urg && tcph_j->urg_ptr == 0))
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 5b: Illegal CWR on handshake packets (RFC 3168 §6.1.1) ----
            if (tcph_j->syn && tcph_j->cwr && (tcph_j->ack || !tcph_j->ece))
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }
    }
#endif

    // =========================================================================
    // Stage 6: UDP Stateless Pre-Filter
    // =========================================================================
#ifdef ENABLE_UDP_JUNK_FILTER
    if (!is_nonfirst_frag &&
        ((iph && iph->protocol == IPPROTO_UDP) ||
         (iph6 && iph6->nexthdr == IPPROTO_UDP)))
    {
        // RFC 7126: Drop UDP packets carrying IPv4 Options (ihl > 5).
        if (unlikely(iph && iph->ihl != 5))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        struct udphdr *udph_j = iph
            ? (void *)iph + sizeof(struct iphdr)
            : (void *)iph6 + sizeof(struct ipv6hdr);

        if (likely((void *)udph_j + sizeof(struct udphdr) <= data_end))
        {
            // ---- Step A: UDP length field sanity ----
            {
                u16 udp_len = ntohs(udph_j->len);
                u16 l3_len = 0;
                int frag = 0;

                if (iph)
                {
                    frag = (iph->frag_off & htons(0x3FFF)) != 0;
                    l3_len = ntohs(iph->tot_len) - sizeof(struct iphdr);
                }
#ifdef ENABLE_IPV6
                else if (iph6)
                {
                    l3_len = ntohs(iph6->payload_len);
                }
#endif
                if (udp_len < 8 || (!frag && udp_len > l3_len))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }

            u16 dport = ntohs(udph_j->dest);
            u16 sport = ntohs(udph_j->source);

            // ---- Step B: Port 0 is never valid ----
            if (dport == 0 || sport == 0)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step C: UDP checksum mandatory on IPv6 (RFC 8200 §8.1) ----
            if (iph6 && udph_j->check == 0)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step D: UDP Reflection / Amplification Source Ports (sport) ----
            // Intercept volumetric amplification floods from protocols this VPS never
            // queries as a client, plus DNS replies (sport==53) targeting privileged
            // ports (dport < 1024). Do NOT call junk_block_src here so spoofed
            // reflector IPs do not thrash map_block LRU.
            int amp_sport = (
                sport == 17    ||                  // QOTD (~100x amp)
                sport == 19    ||                  // Chargen (~358x amp)
                sport == 68    ||                  // DHCP client
                sport == 69    ||                  // TFTP
                sport == 111   ||                  // rpcbind/Portmapper
                (sport >= 137 && sport <= 138) ||  // NetBIOS
                sport == 161   ||                  // SNMP
                sport == 389   ||                  // CLDAP (~56-70x amp)
                sport == 520   ||                  // RIP
                sport == 623   ||                  // IPMI
                sport == 1434  ||                  // MS-SQL Browser
                sport == 1900  ||                  // UPnP/SSDP
                sport == 3702  ||                  // WS-Discovery
                sport == 5353  ||                  // mDNS
                sport == 5355  ||                  // LLMNR
                sport == 5683  ||                  // CoAP
                sport == 11211 ||                  // Memcached (~50000x amp)
                (sport == 53 && dport < 1024)      // DNS amplification to non-ephemeral port
            );

            if (amp_sport)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step E: Junk destination ports (dport) ----
            // 注意本机 net.ipv4.ip_local_reserved_ports 需要预留高端口
            int junk_port = (
                dport == 3418  ||                  // IoT M2M
                dport == 1434  ||                  // MS-SQL Browser
                dport == 623   ||                  // IPMI
                dport == 520   ||                  // RIP
                dport == 53413 ||                  // Netis
                dport == 17185 ||                  //VxWorks WDB / IoT worm
                dport == 27015 ||                  // Steam/Source Engine query
                dport == 64738 ||                  // Mumble
                dport == 5353  ||                  // mDNS
                dport == 1900  ||                  // UPnP/SSDP
                dport == 5355  ||                  // LLMNR
                dport == 5060  ||                  // SIP
                dport == 161   ||                  // SNMP
                dport == 389   ||                  // CLDAP
                dport == 17    ||                  // QOTD
                dport == 5683  ||                  // CoAP/LwM2M
                dport == 69    ||                  // TFTP
                dport == 19    ||                  // chargen
                dport == 111   ||                  // rpcbind/Portmapper
                (dport >= 137 && dport <= 138) ||  // NetBIOS
                dport == 67    ||                  // DHCP server
                dport == 21027 ||                  // Syncthing
                dport == 1968  ||                  // Cisco SLA / scan
                dport == 4466  ||                  // Common scan port
                dport == 33445 ||                  // Tailscale
                dport == 11211 ||                  // memcached
                // ↓ Uncomment if not running these services:
                // dport == 123   ||                // NTP
                // dport == 53    ||                // DNS
                0);

            if (junk_port)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step F: Multicast/broadcast destination ----
            int junk_dst = 0;
            if (iph)
            {
                // 224.0.0.0/4 multicast: MSB byte in [0xE0, 0xEF].
                // 255.255.255.255 limited broadcast: all-ones (same in any byte order).
                u8 msb = *((u8 *)&iph->daddr);
                junk_dst = (msb >= 0xE0 && msb <= 0xEF) || (iph->daddr == 0xFFFFFFFF);
            }
#ifdef ENABLE_IPV6
            else if (iph6)
            {
                // IPv6 multicast = ff00::/8.
                junk_dst = (iph6->daddr.in6_u.u6_addr8[0] == 0xff);
            }
#endif
            if (junk_dst)
            {
#if defined(ENABLE_ARP_FILTER) || defined(ENABLE_NDP_FILTER)
                int is_loopback = 0;

#ifdef ENABLE_ARP_FILTER
                if (iph)
                {
                    u32 saddr;
                    __builtin_memcpy(&saddr, &iph->saddr, sizeof(saddr));
                    u8 *local = bpf_map_lookup_elem(&map_my_ip, &saddr);
                    is_loopback = (local != NULL);
                }
#endif
#if defined(ENABLE_NDP_FILTER) && defined(ENABLE_IPV6)
                else if (iph6)
                {
                    u8 *local6 = bpf_map_lookup_elem(&map_my_ip6, &src_ip6);
                    is_loopback = (local6 != NULL);
                }
#endif
                if (!is_loopback)
                {
#if JUNK_FILTER_BLOCK_TIME > 0
                    junk_block_src(iph, iph6, &src_ip6, now);
#endif
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
#else
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
#endif
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

    if (!is_nonfirst_frag)
    {

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

    // Check allow cache — skip filter loop if this flow was recently allowed.
    // Requires L4 headers parsed above (tcph/udph from ENABLE_FILTERS block).
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
    {
        u16 sport, dport;
        u8 proto;
        int has_l4 = 0;

        if (tcph)
        {
            sport = tcph->source;
            dport = tcph->dest;
            proto = IPPROTO_TCP;
            has_l4 = 1;
        }
        else if (udph)
        {
            sport = udph->source;
            dport = udph->dest;
            proto = IPPROTO_UDP;
            has_l4 = 1;
        }

        if (has_l4)
        {
            if (iph)
            {
                allow_key4_t akey = {0};
                akey.src_ip   = iph->saddr;
                akey.dst_ip   = iph->daddr;
                akey.src_port = sport;
                akey.dst_port = dport;
                akey.protocol = proto;

                u64 *allowed = bpf_map_lookup_elem(&map_allow, &akey);

                if (allowed && *allowed > now)
                {
                    int over_rate = 0;

#ifdef ENABLE_RL_FLOW
                    if ((ALLOW_CACHE_MAX_FLOW_PPS > 0 && flow_pps > ALLOW_CACHE_MAX_FLOW_PPS) ||
                        (ALLOW_CACHE_MAX_FLOW_BPS > 0 && flow_bps > ALLOW_CACHE_MAX_FLOW_BPS))
                    {
                        over_rate = 1;
                    }
#endif
#ifdef ENABLE_RL_IP
                    if ((ALLOW_CACHE_MAX_IP_PPS > 0 && ip_pps > ALLOW_CACHE_MAX_IP_PPS) ||
                        (ALLOW_CACHE_MAX_IP_BPS > 0 && ip_bps > ALLOW_CACHE_MAX_IP_BPS))
                    {
                        over_rate = 1;
                    }
#endif
                    if (over_rate)
                    {
                        bpf_map_delete_elem(&map_allow, &akey);
                    }
                    else
                    {
                        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
                        return XDP_PASS;
                    }
                }
            }
#ifdef ENABLE_IPV6
            else if (iph6)
            {
                allow_key6_t akey6 = {0};
                akey6.src_ip6   = src_ip6;
                akey6.dst_ip6   = dst_ip6;
                akey6.src_port  = sport;
                akey6.dst_port  = dport;
                akey6.protocol  = proto;

                u64 *allowed6 = bpf_map_lookup_elem(&map_allow6, &akey6);

                if (allowed6 && *allowed6 > now)
                {
                    int over_rate = 0;

#ifdef ENABLE_RL_FLOW
                    if ((ALLOW_CACHE_MAX_FLOW_PPS > 0 && flow_pps > ALLOW_CACHE_MAX_FLOW_PPS) ||
                        (ALLOW_CACHE_MAX_FLOW_BPS > 0 && flow_bps > ALLOW_CACHE_MAX_FLOW_BPS))
                    {
                        over_rate = 1;
                    }
#endif
#ifdef ENABLE_RL_IP
                    if ((ALLOW_CACHE_MAX_IP_PPS > 0 && ip_pps > ALLOW_CACHE_MAX_IP_PPS) ||
                        (ALLOW_CACHE_MAX_IP_BPS > 0 && ip_bps > ALLOW_CACHE_MAX_IP_BPS))
                    {
                        over_rate = 1;
                    }
#endif
                    if (over_rate)
                    {
                        bpf_map_delete_elem(&map_allow6, &akey6);
                    }
                    else
                    {
                        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
                        return XDP_PASS;
                    }
                }
            }
#endif
        }
    }

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
            else if (iph6)
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
        // Cache this flow (5-tuple) to skip filter loop on future packets.
        if (rule.allow_time > 0 && (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP))
        {
            u16 sport, dport;
            u8 proto;
            int has_l4 = 0;

            if (tcph)
            {
                sport = tcph->source;
                dport = tcph->dest;
                proto = IPPROTO_TCP;
                has_l4 = 1;
            }
            else if (udph)
            {
                sport = udph->source;
                dport = udph->dest;
                proto = IPPROTO_UDP;
                has_l4 = 1;
            }

            if (has_l4)
            {
                int over_rate = 0;

#ifdef ENABLE_RL_FLOW
                if ((ALLOW_CACHE_MAX_FLOW_PPS > 0 && flow_pps > ALLOW_CACHE_MAX_FLOW_PPS) ||
                    (ALLOW_CACHE_MAX_FLOW_BPS > 0 && flow_bps > ALLOW_CACHE_MAX_FLOW_BPS))
                {
                    over_rate = 1;
                }
#endif
#ifdef ENABLE_RL_IP
                if ((ALLOW_CACHE_MAX_IP_PPS > 0 && ip_pps > ALLOW_CACHE_MAX_IP_PPS) ||
                    (ALLOW_CACHE_MAX_IP_BPS > 0 && ip_bps > ALLOW_CACHE_MAX_IP_BPS))
                {
                    over_rate = 1;
                }
#endif
                if (!over_rate)
                {
                    u64 expire = now + (rule.allow_time * NANO_TO_SEC);

                    if (iph)
                    {
                        allow_key4_t akey = {0};
                        akey.src_ip   = iph->saddr;
                        akey.dst_ip   = iph->daddr;
                        akey.src_port = sport;
                        akey.dst_port = dport;
                        akey.protocol = proto;

                        bpf_map_update_elem(&map_allow, &akey, &expire, BPF_ANY);
                    }
#ifdef ENABLE_IPV6
                    else if (iph6)
                    {
                        allow_key6_t akey6 = {0};
                        akey6.src_ip6  = src_ip6;
                        akey6.dst_ip6  = dst_ip6;
                        akey6.src_port = sport;
                        akey6.dst_port = dport;
                        akey6.protocol = proto;

                        bpf_map_update_elem(&map_allow6, &akey6, &expire, BPF_ANY);
                    }
#endif
                }
            }
        }

        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
    }

    return XDP_PASS;
#endif
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);
