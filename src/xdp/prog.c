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
        memcpy(&dst_ip6, iph6->daddr.in6_u.u6_addr32, sizeof(dst_ip6));    // ← 新增
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

#ifdef ENABLE_TCP_JUNK_FILTER
    // Drop TCP junk: multicast/broadcast destinations or known junk ports.
    // Self-contained — does not depend on tcph from ENABLE_FILTERS block.
    // No loopback exemption: TCP cannot legitimately target multicast/broadcast (RFC 793).

    // Non-first fragments carry no TCP header — their payload would be
    // misread as udphdr. Skip only the L4 checks; let the packet continue
    // into ENABLE_FILTERS so IP-level stats and rules still apply.
    // (First fragments offset==0 keep the header and are checked normally.)
    int skip_l4 = (iph && (ntohs(iph->frag_off) & 0x1FFF));
    if (!skip_l4 &&
        ((iph && iph->protocol == IPPROTO_TCP) ||
         (iph6 && iph6->nexthdr == IPPROTO_TCP)))
    {
        struct tcphdr *tcph_j = iph
            ? (void *)iph + (iph->ihl * 4)
            : (void *)iph6 + sizeof(struct ipv6hdr);

        if (likely((void *)tcph_j + sizeof(struct tcphdr) <= data_end))
        {

            // ---- Step 0a: IPv4 header sanity (ihl / tot_len) ----
            // ihl < 5 is a protocol violation and makes tcph_j point back
            // into the IP header — every later L4 check would read garbage.
            // tot_len < ihl*4 underflows u16 subtraction; both = malformed.
            if (iph && (iph->ihl < 5 ||
                        ntohs(iph->tot_len) < (iph->ihl * 4)))
            {
// src 不可信
// #if JUNK_FILTER_BLOCK_TIME > 0
//                 junk_block_src(iph, iph6, &src_ip6, now);
// #endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 0b: LAND attack — src == dst on external NIC ----
            // No legitimate packet received from an external interface has
            // identical source and destination; 100% spoofed. Cheap compare.
            {
                int is_land = 0;

                if (iph)
                {
                    is_land = (iph->saddr == iph->daddr);
                }
#ifdef ENABLE_IPV6
                else if (iph6)
                {
                    is_land = (__builtin_memcmp(&src_ip6, &dst_ip6,
                                                sizeof(src_ip6)) == 0);
                }
#endif

                if (is_land)
                {
// land 是自己的 ip
// #if JUNK_FILTER_BLOCK_TIME > 0
//                     junk_block_src(iph, iph6, &src_ip6, now);
// #endif
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }

            // ---- Step 0c: TCP port 0 — IANA reserved, no legal socket ----
            // Same rationale as UDP Step B; network-order compare is free.
            if (tcph_j->source == 0 || tcph_j->dest == 0)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 0d: Fragmented SYN — RFC 1858 tiny-fragment attack ----
            // A legit handshake SYN is tens of bytes, far under the minimum
            // IPv4 MTU (576B) — it can never legitimately be fragmented.
            // MF=1 + offset=0 on a SYN means the attacker's first fragment
            // carries the header and later fragments hide the real payload
            // from filters. IPv6 fragments never reach here (nexthdr=44).
            if (iph && tcph_j->syn &&
                (ntohs(iph->frag_off) & 0x2000))
            {
// src 不可信
// #if JUNK_FILTER_BLOCK_TIME > 0
//                 junk_block_src(iph, iph6, &src_ip6, now);
// #endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // port 防御

            u16 dport = ntohs(tcph_j->dest);
            // 注意本机 net.ipv4.ip_local_port_range 需要避开
            int junk_port = (
                dport == 20    ||                  // FTP data
                dport == 21    ||                  // FTP control
                dport == 631   ||                  // IPP/CUPS
                dport == 3418  ||                  // IoT M2M

                dport == 23    ||                  // Telnet — Mirai 系僵尸网络头号目标
                dport == 2323  ||                  // Telnet 替代端口，同上
                dport == 7547  ||                  // TR-069 CWMP — 全球路由器远程管理扫描量最大之一
                dport == 8291  ||                  // MikroTik WinBox
                dport == 8728  ||                  // MikroTik API
                dport == 5555  ||                  // Android ADB
                dport == 2375  ||                  // Docker API 未加密端口
                dport == 9200  ||                  // Elasticsearch
                dport == 37215 ||                  // 华为路由器远程代码执行扫描
                dport == 53413 ||                  // Netis 路由器后门扫描
                dport == 52869 ||                  // 芯片级/路由器固件扫描
                dport == 55552 ||                  // Mirai 变种
                dport == 81    ||                  // 常见摄像头/Web 管理口探测
                dport == 8888  ||                  // 宝塔面板/各类 Web admin 扫描
                dport == 10250 ||                  // Kubernetes kubelet

                (dport >= 135 && dport <= 139) ||  // MS-RPC/NetBIOS
                dport == 445   ||                  // SMB
                dport == 593   ||                  // MS-RPC HTTP
                dport == 7680  ||                  // Windows Delivery Optimization
                dport == 5357  ||                  // WSD
                dport == 5358  ||                  // WSD Secure
                (dport >= 49664 && dport <= 49670) ||  // WinRPC dynamic range
                dport == 3306 ||               // MySQL
                dport == 5432 ||               // PostgreSQL
                dport == 3389 ||                     // RDP (uncomment-safe on Linux VPS)
                // ↓ Uncomment if not running these services:
                // dport == 6379 ||               // Redis
                // dport == 1433 ||               // MSSQL
                // dport == 27017                 // MongoDB
                0);

            if (junk_port)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // Multicast/broadcast destination — always invalid for TCP.
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

#if defined(ENABLE_ARP_FILTER)
            // ---- Step 1: Illegal SYN (doff + frame length, IPv4/IPv6) ----
            // SYN=1, all other flags=0 — the only legit shapes are pure SYN and
            // SYN+ACK, so this branch only sees pure-SYN candidates.
            //
            // doff < 6: every real OS carries at least the 4-byte MSS option in
            // a handshake SYN (TCP header >= 24B, doff >= 6). A pure SYN with
            // doff == 5 has no options at all = crafted packet (hping3, scapy,
            // ZMap-style tools). This also catches payload-padded bare SYN
            // floods (e.g. hping3 -S -d 100) that a frame-length lower bound
            // would miss, since padding changes flen but not doff.
            //
            // flen > ceiling: SYN frames beyond the TFO-cookie size (~589B IPv4)
            // have no legitimate reason to exist. Ceiling is 604 on IPv4 and
            // 624 on IPv6 (fixed 40B v6 header vs 20B v4, +20 offset).
            //
            // doff < 6: unconditional — no dst check needed, the shape cannot
            // exist in legitimate traffic regardless of destination.
            // flen > ceiling: scoped to packets addressed to our own IPs
            // (map_my_ip / map_my_ip6), same scope as the original rules.
            if (tcph_j->syn && !tcph_j->ack && !tcph_j->fin &&
                !tcph_j->rst && !tcph_j->psh && !tcph_j->urg)
            {

                // doff < 6: protocol violation, no map needed.
                if (tcph_j->doff < 6)
                {
#if JUNK_FILTER_BLOCK_TIME > 0
                    junk_block_src(iph, iph6, &src_ip6, now);
#endif
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }

                // Oversized SYN: only for our own IPs.
                u16 flen = data_end - data;
                u16 ceil = iph ? 604 : 624;

                if (flen > ceil)
                {
                    int is_own = 0;

                    if (iph)
                    {
                        u32 daddr_j;
                        __builtin_memcpy(&daddr_j, &iph->daddr, sizeof(daddr_j));
                        is_own = (bpf_map_lookup_elem(&map_my_ip, &daddr_j) != NULL);
                    }
#if defined(ENABLE_NDP_FILTER) && defined(ENABLE_IPV6)
                    else if (iph6)
                    {
                        is_own = (bpf_map_lookup_elem(&map_my_ip6, &dst_ip6) != NULL);
                    }
#endif

                    if (is_own)
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

            // ---- Step 2: Illegal SYN flag combos ----
            // Legitimate SYN-bearing packets: pure SYN or SYN+ACK (plus
            // ECN variants). SYN + FIN/RST/PSH/URG has no legal meaning on
            // ANY port or destination — scan probe by definition.
            // No dst-IP scoping needed: unlike the length check, this is a
            // protocol violation, not a heuristic.
            if (tcph_j->syn &&
                (tcph_j->fin || tcph_j->rst || tcph_j->psh || tcph_j->urg))
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // Step 3: NULL scan — all six flags clear is never valid TCP.
            // nmap -sN sends exactly this; no legit stack emits it.
            if (!tcph_j->syn && !tcph_j->ack && !tcph_j->fin &&
                !tcph_j->rst && !tcph_j->psh && !tcph_j->urg)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // Step 4: Stealth scan — FIN/PSH/URG without SYN or ACK.
            // Post-handshake packets always carry ACK; RST is excluded
            // because RST-without-ACK is the legit "port closed" reply.
            // Xmas (FIN+PSH+URG) and FIN-only scans land here.
            if (!tcph_j->syn && !tcph_j->ack && !tcph_j->rst &&
                (tcph_j->fin || tcph_j->psh || tcph_j->urg))
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }


            // ---- Step 5a: FIN+RST simultaneously ----
            // Mutually exclusive states (graceful close vs. abort); no real
            // stack emits both. Classic scanner fingerprint (nmap variants).
            if (tcph_j->fin && tcph_j->rst)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step 5b: CWR on handshake packets ----
            // RFC 3168: CWR is only valid on data/ACK packets after ECN
            // negotiation. SYN or SYN+ACK with CWR=1 is a protocol violation.
            // NOTE: SYN+ACK with ECE=1 and CWR=0 is LEGITIMATE (ECN setup) —
            // do not flag ECE alone.
            if (tcph_j->cwr && tcph_j->syn)
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

#ifdef ENABLE_UDP_JUNK_FILTER
    // Drop UDP junk: multicast/broadcast destinations or known junk ports.
    // Self-contained — does not depend on udph from ENABLE_FILTERS block.

    // Non-first fragments carry no UDP header — their payload would be
    // misread as udphdr. Skip only the L4 checks; let the packet continue
    // into ENABLE_FILTERS so IP-level stats and rules still apply.
    // (First fragments offset==0 keep the header and are checked normally.)
    int skip_l4 = (iph && (ntohs(iph->frag_off) & 0x1FFF));
    if (!skip_l4 &&
        ((iph && iph->protocol == IPPROTO_UDP) ||
         (iph6 && iph6->nexthdr == IPPROTO_UDP)))
    {
        struct udphdr *udph_j = iph
            ? (void *)iph + (iph->ihl * 4)
            : (void *)iph6 + sizeof(struct ipv6hdr);

        if (likely((void *)udph_j + sizeof(struct udphdr) <= data_end))
        {
            // ---- Step A: UDP length field sanity ----
            // udphdr.len = UDP header (8B) + payload; must equal the actual
            // L3 payload length. Mismatch = crafted packet.
            // Only checked on UNFRAGMENTED packets: on a first fragment,
            // udph->len is the pre-fragmentation datagram size and is
            // legitimately larger than this fragment's tot_len.
            // (Non-first fragments already returned above.)
            {
                u16 udp_len = ntohs(udph_j->len);
                u16 l3_len;
                int frag = 0;

                if (iph)
                {
                    // Malformed ihl/tot_len — drop before the u16
                    // subtraction can underflow.
                    if (iph->ihl < 5 ||
                        ntohs(iph->tot_len) < (iph->ihl * 4))
                    {
#if JUNK_FILTER_BLOCK_TIME > 0
                        junk_block_src(iph, iph6, &src_ip6, now);
#endif

                        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                        return XDP_DROP;
                    }

                    // MF flag (0x2000) or offset (0x1FFF) set = fragmented.
                    frag = (ntohs(iph->frag_off) & 0x3FFF) != 0;

                    // IPv4: total_length - ihl*4 = L4 segment size.
                    l3_len = ntohs(iph->tot_len) - (iph->ihl * 4);
                }
#ifdef ENABLE_IPV6
                else if (iph6)
                {
                    // IPv6: payload_length covers the L4 segment directly.
                    // (Fragmented v6 packets have nexthdr=44 and never
                    // reach this block, so no frag check needed here.)
                    l3_len = ntohs(iph6->payload_len);
                }
#endif
                // Legit cases that must NOT be dropped:
                //   udp_len < 8        — malformed, always drop
                //   udp_len > l3_len   — only meaningful when unfragmented
                //   udp_len < l3_len   — padding (Etherpad min frame), legal
                if (udp_len < 8 || (!frag && udp_len > l3_len))
                {
#if JUNK_FILTER_BLOCK_TIME > 0
                    junk_block_src(iph, iph6, &src_ip6, now);
#endif
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }

            // Multicast/broadcast short-circuits first; only non-multicast
            // packets reach the port checks.
            u16 dport = ntohs(udph_j->dest);
            u16 sport = ntohs(udph_j->source);

            // ---- Step B: port 0 is never valid ----
            // IANA reserves port 0; no legitimate socket binds to or sends
            // to port 0. Both directions checked cheaply.
            if (dport == 0 || sport == 0)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step C: UDP checksum mandatory on IPv6 (RFC 2460 §8.1) ----
            // check == 0 means "no checksum" — legal on IPv4, a protocol
            // violation on IPv6. Tunnels that legitimately use zero-checksum
            // UDP on v6 (VXLAN etc.) are encapsulated, not seen here.
            if (iph6 && udph_j->check == 0
                // maybe needed somehow ?
                // &&
                // dport != 4789 &&   // VXLAN
                // dport != 6081)     // GENEVE
                )
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // junk port check
            // 注意本机 net.ipv4.ip_local_port_range 需要避开
            int junk_port = (
                dport == 3418  ||                  // IoT M2M

                dport == 1434  ||                   // MS-SQL Browser — 反射放大源
                dport == 623   ||                   // IPMI — 服务器带外管理，VPS 没有
                dport == 520   ||                   // RIP 路由协议
                dport == 53413 ||                   // Netis
                dport == 17185 ||                   // 一些 IoT 蠕虫常用端口
                dport == 27015 ||                   // Steam/游戏服务器探测（不跑游戏服务可丢）
                dport == 64738 ||                   // Mumble — 常被扫

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
                dport == 11211 ||                // memcached
                // ↓ Uncomment if not running these services:
                // dport == 123   ||                // NTP
                // dport == 53    ||                // DNS
                0);

            // Junk ports — unconditional drop, no map lookup needed.
            if (junk_port)
            {
#if JUNK_FILTER_BLOCK_TIME > 0
                junk_block_src(iph, iph6, &src_ip6, now);
#endif
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

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
            // Multicast/broadcast destination — check loopback before dropping.
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
#ifdef ENABLE_NDP_FILTER
#ifdef ENABLE_IPV6
                else if (iph6)
                {
                    u8 *local6 = bpf_map_lookup_elem(&map_my_ip6, &src_ip6);
                    is_loopback = (local6 != NULL);
                }
#endif
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
                // No loopback check available — drop but don't block,
                // since the source could be our own IP.
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

    // Do not parse L4 on non-first fragments — payload would be misread
    // as TCP/UDP/ICMP headers. tcph/udph/icmph stay NULL; rules that
    // require L4 fields simply won't match, IP-level rules still apply.
    int is_nonfirst_frag = (iph && (ntohs(iph->frag_off) & 0x1FFF));

    if (iph && !is_nonfirst_frag)
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
                }
            }
        }
#endif

        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
    }

    return XDP_PASS;
#endif
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);
