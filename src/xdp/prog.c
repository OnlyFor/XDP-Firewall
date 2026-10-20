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

#ifdef ENABLE_IPV6
// UAPI <linux/ipv6.h> does not expose struct frag_hdr (it lives in kernel-internal
// <net/ipv6.h>), so define it locally here with standard kernel field names.
struct frag_hdr {
    u8     nexthdr;
    u8     reserved;
    __be16 frag_off;
    __be32 identification;
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
    // ARP filter: strictly validate Ethernet/IPv4 ARP and only allow ARP targeting our IP.
    if (eth->h_proto == htons(ETH_P_ARP))
    {
        struct arphdr *arp = data + sizeof(struct ethhdr);

        // Ethernet ARP = arphdr(8) + SHA(6) + SPA(4) + THA(6) + TPA(4) = 28 bytes.
        if (unlikely((void *)arp + sizeof(struct arphdr) + 2 * ETH_ALEN + 2 * 4 > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // Strict RFC 826 sanity: Ethernet(1), IPv4(0x0800), hln=6, pln=4, op in {1, 2}.
        u16 op = arp->ar_op;
        if (unlikely(arp->ar_hrd != htons(ARPHRD_ETHER) ||
                        arp->ar_pro != htons(ETH_P_IP) ||
                        arp->ar_hln != ETH_ALEN ||
                        arp->ar_pln != 4 ||
                        (op != htons(1) && op != htons(2))))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // Check if ARP filter is enabled (my_ips_cnt > 0).
        u32 zero = 0;
        u32 *arp_enabled = bpf_map_lookup_elem(&map_arp_enabled, &zero);

        if (arp_enabled && *arp_enabled)
        {
            // Sender IP (SPA): offset 14B; Target IP (TPA): offset 24B.
            u32 ar_sip, ar_tip;
            // __builtin_memcpy(&ar_sip, (u8 *)arp + sizeof(struct arphdr) + ETH_ALEN, 4);
            // __builtin_memcpy(&ar_tip, (u8 *)arp + sizeof(struct arphdr) + ETH_ALEN + 4 + ETH_ALEN, 4);

            // 1. Target IP must be one of our own IPs in map_my_ip.
            // if (!bpf_map_lookup_elem(&map_my_ip, &ar_tip))
            if (!bpf_map_lookup_elem(&map_my_ip, (u8 *)arp + 24))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // 2. Anti-ARP-Spoofing: external host must never claim our own IP as Sender IP.
            // if (unlikely(bpf_map_lookup_elem(&map_my_ip, &ar_sip) != NULL))
            if (unlikely(bpf_map_lookup_elem(&map_my_ip, (u8 *)arp + 14) != NULL))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }

        // Valid ARP packet — return XDP_PASS here so the L2 check below can
        // safely drop all non-IPv4 / non-IPv6 L2 junk frames.
        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
        return XDP_PASS;
    }
#else
    if (eth->h_proto == htons(ETH_P_ARP))
    {
        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
        return XDP_PASS;
    }
#endif

    // Check Ethernet protocol: drop all remaining non-IPv4 / non-IPv6 L2 noise
    // (STP BPDUs, LLDP, CDP, Loopback keepalive, etc.).
#ifdef ENABLE_IPV6
    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
#else
    if (unlikely(eth->h_proto != htons(ETH_P_IP)))
#endif
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
        return XDP_DROP;
    }

    // Initialize IP headers and unified fragmentation / L4 tracking variables.
    // Declared unconditionally so downstream expressions compile cleanly
    // regardless of whether ENABLE_IPV6 is enabled or disabled.
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    u128 src_ip6 = 0;
    u128 dst_ip6 = 0;

    int   is_nonfirst_frag = 0;    // 1 if UDP non-first fragment (offset > 0)
    int   is_frag_pkt      = 0;    // 1 if multi-part UDP fragment (offset > 0 or MF/M == 1)
    u8    nexthdr6         = 0;    // Effective IPv6 L4 protocol (unwrapped if nexthdr == 44)
    void *l4_hdr6          = NULL; // Effective IPv6 L4 header pointer (+40B normal, +48B if frag_hdr)

    // =========================================================================
    // Stage 1: L3 Header Parsing, Sanity, Fragment Integrity & "Not-My-IP" Filter
    // =========================================================================
    if (eth->h_proto == htons(ETH_P_IP))
    {
        iph = data + sizeof(struct ethhdr);

        if (unlikely((void *)(iph + 1) > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // 1. Version MUST be 4, and IHL MUST be >= 5 (20 bytes).
        if (unlikely(iph->version != 4 || iph->ihl < 5))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        u16 ihl_bytes = (u16)iph->ihl * 4;
        if (unlikely((void *)iph + ihl_bytes > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // 2. Total length MUST be at least the IPv4 header + minimum 8B L4 payload.
        //    (Do NOT check iph + tot_len > data_end because KVM virtio_net GRO/GSO
        //    and multi-buffer SKBs place coalesced payload beyond linear data_end.)
        u16 tot_len = ntohs(iph->tot_len);
        if (unlikely(tot_len < ihl_bytes + 8))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // 3. Bogon source IPv4 filter, LAND attack, and protocol 58 (ICMPv6-in-IPv4):
        u8 src_msb = *((u8 *)&iph->saddr);
        if (unlikely(src_msb == 0 || src_msb == 127 || src_msb >= 224 ||
                        iph->saddr == iph->daddr ||
                        iph->protocol == IPPROTO_ICMPV6))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // 4. RFC 3514 "Evil Bit" & IPv4 Fragmentation Integrity Check:
        u16 frag = ntohs(iph->frag_off);
        if (unlikely(frag & 0x8000))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        u16 frag_off_bytes = (frag & 0x1FFF) << 3;
        int mf = (frag & 0x2000) != 0;
        int df = (frag & 0x4000) != 0;

        if (frag_off_bytes != 0 || mf)
        {
            is_frag_pkt = 1;
            is_nonfirst_frag = (frag_off_bytes != 0);

            u16 frag_payload = tot_len - ihl_bytes;

            if (unlikely(iph->protocol != IPPROTO_UDP ||
                            df ||
                            frag_payload == 0 ||
                            (u32)frag_off_bytes + (u32)frag_payload > 65535 ||
                            (mf && (frag_payload & 7) != 0) ||
                            (!is_nonfirst_frag && frag_payload < 256) ||
                            (is_nonfirst_frag && frag_off_bytes < 256)))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }

#ifdef ENABLE_ARP_FILTER
        // 5. Global IPv4 Destination Filter:
        //    Drop all packets not addressed to our VPS IP(s) in map_my_ip.
        {
            u32 zero = 0;
            u32 *arp_enabled = bpf_map_lookup_elem(&map_arp_enabled, &zero);
            if (arp_enabled && *arp_enabled)
            {
                if (!bpf_map_lookup_elem(&map_my_ip, &iph->daddr))
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

        if (unlikely((void *)(iph6 + 1) > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // 1. Version MUST be 6, and payload length MUST be at least 8 bytes.
        //    (Do NOT check (iph6 + 1) + plen > data_end to preserve KVM GRO/GSO packets.)
        u16 plen = ntohs(iph6->payload_len);
        if (unlikely(iph6->version != 6 || plen < 8))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        memcpy(&src_ip6, iph6->saddr.in6_u.u6_addr32, sizeof(src_ip6));
        memcpy(&dst_ip6, iph6->daddr.in6_u.u6_addr32, sizeof(dst_ip6));    // ← 新增

        // 2. Source IPv6 MUST NOT be multicast (ff00::/8), unspecified (::),
        //    loopback (::1), or equal to destination (LAND attack).
        u8 s6_msb = iph6->saddr.in6_u.u6_addr8[0];
        if (unlikely(s6_msb == 0xff || src_ip6 == 0 ||
                        src_ip6 == dst_ip6 ||
                        (iph6->saddr.in6_u.u6_addr32[0] == 0 &&
                        iph6->saddr.in6_u.u6_addr32[1] == 0 &&
                        iph6->saddr.in6_u.u6_addr32[2] == 0 &&
                        iph6->saddr.in6_u.u6_addr32[3] == htonl(1))))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        nexthdr6 = iph6->nexthdr;
        l4_hdr6  = (void *)(iph6 + 1);

        // 3. IPv6 Fragment Header (nexthdr == 44) Unwrapping & Integrity Check:
        if (unlikely(nexthdr6 == IPPROTO_FRAGMENT))
        {
            struct frag_hdr *fhdr = (struct frag_hdr *)l4_hdr6;

            if (unlikely((void *)(fhdr + 1) > data_end || plen < sizeof(struct frag_hdr) + 8))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            u16 frag_info = ntohs(fhdr->frag_off);
            u16 frag_off_bytes = frag_info & 0xFFF8;
            int more_frags = (frag_info & 0x0001);
            u16 frag_payload = plen - sizeof(struct frag_hdr);

            if (unlikely(fhdr->reserved != 0 || (frag_info & 0x0006) != 0))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            nexthdr6 = fhdr->nexthdr;
            l4_hdr6  = (void *)(fhdr + 1);

            if (frag_off_bytes != 0 || more_frags)
            {
                is_frag_pkt = 1;
                is_nonfirst_frag = (frag_off_bytes != 0);

                if (unlikely(nexthdr6 != IPPROTO_UDP ||
                                frag_payload == 0 ||
                                (u32)frag_off_bytes + (u32)frag_payload > 65535 ||
                                (more_frags && (frag_payload & 7) != 0) ||
                                (!is_nonfirst_frag && frag_payload < 256) ||
                                (is_nonfirst_frag && frag_off_bytes < 256)))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }
        }

#ifdef ENABLE_NDP_FILTER
        // 4. Global IPv6 Destination Filter (TCP / UDP / Non-ICMPv6):
        //    Since both our global IPv6 and specific link-local fe80::xxxx are
        //    configured in map_my_ip6, check map_my_ip6 directly without any
        //    blanket fe80::/10 exemption.
        if (nexthdr6 != IPPROTO_ICMPV6)
        {
            u32 zero = 0;
            u32 *ndp_enabled = bpf_map_lookup_elem(&map_ndp_enabled, &zero);
            if (ndp_enabled && *ndp_enabled)
            {
                if (!bpf_map_lookup_elem(&map_my_ip6, &dst_ip6))
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
    // Stage 3: Pure L3 Protocol Whitelist (TCP / UDP / ICMP / ICMPv6 only)
    // =========================================================================
    if ((iph && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP &&
            iph->protocol != IPPROTO_ICMP) ||
        (iph6 && nexthdr6 != IPPROTO_TCP && nexthdr6 != IPPROTO_UDP &&
            nexthdr6 != IPPROTO_ICMPV6))
    {
        // // Drop known invalid/scan/flood L3 protocols on a public VPS:
        // //   - IPv4 protocol 0 (zero-init flood), 2 (IGMP), 88 (EIGRP), 89 (OSPF),
        // //     103 (PIM), 112 (VRRP), 144..255 (IANA unassigned/experimental/reserved)
        // //   - IPv6 nexthdr 0 (Hop-by-Hop DoS), 43 (Routing Header), 144..255
        // if ((iph && (iph->protocol == 0 || iph->protocol == 2 ||
        //                 iph->protocol == 88 || iph->protocol == 89 ||
        //                 iph->protocol == 103 || iph->protocol == 112 ||
        //                 iph->protocol >= 144)) ||
        //     (iph6 && (iph6->nexthdr == 0 || iph6->nexthdr == 43 ||
        //                 iph6->nexthdr >= 144)))
        // {
        //     inc_pkt_stats(stats, STATS_TYPE_DROPPED);
        //     return XDP_DROP;
        // }
        // inc_pkt_stats(stats, STATS_TYPE_PASSED);
        // return XDP_PASS;
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
        return XDP_DROP;
    }

    // =========================================================================
    // Stage 4: ICMPv4 & ICMPv6 / NDP Pre-Filters
    // Note: Stage 1 already dropped all multi-part fragmented ICMP/ICMPv6 packets,
    // so every ICMP/ICMPv6 packet reaching Stage 4 is guaranteed unfragmented!
    // =========================================================================

    if (iph && iph->protocol == IPPROTO_ICMP)
    {
        if (unlikely(iph->ihl != 5))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        struct icmphdr *icmph_err = (void *)iph + sizeof(struct iphdr);
        if (unlikely((void *)(icmph_err + 1) > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        u8 type = icmph_err->type;
        u8 code = icmph_err->code;

        // Strict RFC whitelist for ICMPv4 types & codes:
        //   - Type 0/8 (Echo Reply/Request): code MUST be 0 (non-zero = Nmap/Sing OS probe)
        //   - Type 3   (Dest Unreachable):   code 0..15 (includes Code 4 PMTUD)
        //   - Type 11  (Time Exceeded):      code 0..1
        //   - Type 12  (Parameter Problem):  code 0..2
        // Drops Timestamp (13/14), Info (15/16), Address Mask (17/18), Redirect (5), Source Quench (4)
        if (type == 0 || type == 8)
        {
            if (unlikely(code != 0))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }
        // ICMPv4 Error (Type 3, 11, 12): >= 36B, and inner offending iphdr must match our IP.
        else if (type == 3 || type == 11 || type == 12)
        {
            if (unlikely((type == 3 && code > 15) ||
                            (type == 11 && code > 1) ||
                            (type == 12 && code > 2)))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            if (unlikely((void *)icmph_err + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8 > data_end))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            struct iphdr *inner_iph = (struct iphdr *)(icmph_err + 1);
            if (unlikely(inner_iph->version != 4 || inner_iph->ihl < 5 ||
                            inner_iph->saddr != iph->daddr))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }
        else
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }
    }

#ifdef ENABLE_IPV6
    if (iph6 && nexthdr6 == IPPROTO_ICMPV6)
    {
        struct icmp6hdr *icmp6_hdr = (struct icmp6hdr *)l4_hdr6;

        if (unlikely((void *)(icmp6_hdr + 1) > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        u8 type = icmp6_hdr->icmp6_type;
        u8 code = icmp6_hdr->icmp6_code;

        // Case A: NDP Messages (Types 133..137) — RFC 4861 §6.1.1/6.1.2/7.1.1/7.1.2:
        //   All NDP messages MUST have hop_limit == 255 and icmp6_code == 0.
        if (type >= 133 && type <= 137)
        {
            if (unlikely(iph6->hop_limit != 255 || code != 0))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // Drop RS (133, VPS is not a router) and Redirect (137, MITM vector).
            if (type == 133 || type == 137)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // RA (134): RFC 4861 §6.1.2 requires source address to be Link-Local (fe80::/10),
            // and minimum RA length is 16 bytes.
            if (type == 134)
            {
                u8 b0 = iph6->saddr.in6_u.u6_addr8[0];
                u8 b1 = iph6->saddr.in6_u.u6_addr8[1];
                if (unlikely(b0 != 0xfe || (b1 & 0xc0) != 0x80 ||
                                (void *)icmp6_hdr + 16 > data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }

                inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
                return XDP_PASS;
            }

            // NS (135) & NA (136) — minimum 24 bytes (8B icmp6hdr + 16B target address).
            if (type == 135 || type == 136)
            {
                if (unlikely((void *)icmp6_hdr + 24 > data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }

#ifdef ENABLE_NDP_FILTER
                u32 zero = 0;
                u32 *ndp_enabled = bpf_map_lookup_elem(&map_ndp_enabled, &zero);

                if (ndp_enabled && *ndp_enabled)
                {
                    if (type == 135)
                    {
                        // Incoming NS (135): Someone is asking "Who has <ndp_target>?"
                        // <ndp_target> MUST be one of our configured IPv6s (global or fe80::xxxx) in map_my_ip6.
                        // u128 ndp_target;
                        // __builtin_memcpy(&ndp_target, (u8 *)icmp6_hdr + 8, sizeof(ndp_target));

                        // u8 *found = bpf_map_lookup_elem(&map_my_ip6, &ndp_target);
                        if (!bpf_map_lookup_elem(&map_my_ip6, (u8 *)icmp6_hdr + 8))
                        {
                            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                            return XDP_DROP;
                        }
                    }
                    else
                    {
                        // Incoming NA (136): Gateway is replying "I am <ndp_target>" to OUR VPS!
                        // Here <ndp_target> is the gateway's IP, so we check that the outer
                        // destination (dst_ip6) is in map_my_ip6 (global or our fe80::xxxx).
                        // u8 *found = bpf_map_lookup_elem(&map_my_ip6, &dst_ip6);
                        if (!bpf_map_lookup_elem(&map_my_ip6, &dst_ip6))
                        {
                            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                            return XDP_DROP;
                        }
                    }
                }
#endif
                inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
                return XDP_PASS;
            }
        }

        // Case B: Non-NDP ICMPv6 (Echo 128/129 & Error 1/2/3/4):
        //   Outer dst_ip6 MUST be in map_my_ip6 (global or our fe80::xxxx).
#ifdef ENABLE_NDP_FILTER
        {
            u32 zero = 0;
            u32 *ndp_enabled = bpf_map_lookup_elem(&map_ndp_enabled, &zero);
            if (ndp_enabled && *ndp_enabled)
            {
                // u8 *found6 = bpf_map_lookup_elem(&map_my_ip6, &dst_ip6);
                if (!bpf_map_lookup_elem(&map_my_ip6, &dst_ip6))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                    return XDP_DROP;
                }
            }
        }
#endif

        if (type == 128 || type == 129)
        {
            if (unlikely(code != 0))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }
        else if (type >= 1 && type <= 4)
        {
            if (unlikely((type == 1 && code > 6) ||
                            (type == 2 && code != 0) ||
                            (type == 3 && code > 1) ||
                            (type == 4 && code > 2)))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            if (unlikely((void *)icmp6_hdr + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) > data_end))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            struct ipv6hdr *inner_iph6 = (struct ipv6hdr *)(icmp6_hdr + 1);
            u128 inner_src6 = 0;
            __builtin_memcpy(&inner_src6, inner_iph6->saddr.in6_u.u6_addr32, sizeof(inner_src6));

            if (unlikely(inner_iph6->version != 6 || inner_src6 != dst_ip6))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }
        }
        else
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }
    }
#endif

    // =========================================================================
    // Stage 5: TCP Stateless Pre-Filter
    // Note: Stage 1 already dropped all multi-part fragmented TCP packets,
    // so every TCP packet reaching Stage 5 is guaranteed unfragmented!
    // =========================================================================
#ifdef ENABLE_TCP_JUNK_FILTER
    if ((iph && iph->protocol == IPPROTO_TCP) ||
        (iph6 && nexthdr6 == IPPROTO_TCP))
    {
        // RFC 7126: Drop TCP packets carrying IPv4 Options (ihl > 5).
        if (unlikely(iph && iph->ihl != 5))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        struct tcphdr *tcph_j = iph
            ? (void *)iph + sizeof(struct iphdr)
            : l4_hdr6;

        // Guard Clause: TCP packet MUST contain full 20B header AND full options (doff * 4).
        if (unlikely((void *)tcph_j + sizeof(struct tcphdr) > data_end ||
                        tcph_j->doff < 5 ||
                        (void *)tcph_j + (tcph_j->doff * 4) > data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // ---- Step 0a: TCP port 0 — IANA reserved ----
        if (tcph_j->source == 0 || tcph_j->dest == 0)
        {
#if JUNK_FILTER_BLOCK_TIME > 0
            junk_block_src(iph, iph6, &src_ip6, now);
#endif
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        u16 dport = ntohs(tcph_j->dest);
        u16 sport = ntohs(tcph_j->source);

        // ---- Step 0b: Junk destination ports ----
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

        // ---- Step 0c: Multicast/broadcast destination (invalid for TCP) ----
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

        // ---- Step 1: Illegal SYN flag combos & SYN+ACK reflection to privileged ports ----
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

        // ---- Step 2: Illegal pure SYN (doff < 6, window == 0, oversized, or spoofed sport) ----
        // (fin/rst/psh/urg are already guaranteed 0 here because Step 1 ran first.)
        if (tcph_j->syn && !tcph_j->ack)
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

        // ---- Step 5a: RST combined with FIN/PSH/URG, or URG=1 with urg_ptr==0 ----
        // if ((tcph_j->rst && (tcph_j->fin || tcph_j->psh || tcph_j->urg)) ||
        if ((tcph_j->rst && (tcph_j->fin || tcph_j->urg)) ||
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
#endif

    // =========================================================================
    // Stage 6: UDP Stateless Pre-Filter (Covers Both First & Non-First Fragments!)
    // =========================================================================
#ifdef ENABLE_UDP_JUNK_FILTER
    if ((iph && iph->protocol == IPPROTO_UDP) ||
        (iph6 && nexthdr6 == IPPROTO_UDP))
    {
        // ---- L3-level UDP checks (apply to ALL fragments, including is_nonfirst_frag == 1) ----
        // 1. RFC 7126: Drop UDP packets carrying IPv4 Options (ihl > 5).
        if (unlikely(iph && iph->ihl != 5))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
            return XDP_DROP;
        }

        // 2. Multicast/broadcast destination check (with loopback exemption).
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
                // u32 saddr;
                // __builtin_memcpy(&saddr, &iph->saddr, sizeof(saddr));
                // u8 *local = bpf_map_lookup_elem(&map_my_ip, &saddr);
                u8 *local = bpf_map_lookup_elem(&map_my_ip, &iph->saddr);
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

        // ---- L4-level UDP header checks (for unfragmented & first fragments) ----
        if (!is_nonfirst_frag)
        {
            struct udphdr *udph_j = iph
                ? (void *)iph + sizeof(struct iphdr)
                : l4_hdr6;

            // RFC 7112 / Guard Clause: first/unfragmented UDP packet must contain full 8B UDP header.
            if (unlikely((void *)udph_j + sizeof(struct udphdr) > data_end))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
            }

            // ---- Step A: UDP length field sanity (Both sides of is_frag_pkt closed!) ----
            //   - Unfragmented (!is_frag_pkt): udp_len must not exceed l3_len.
            //   - First fragment (is_frag_pkt, MF=1): total udp_len MUST exceed first
            //     fragment's l3_len (otherwise MF=1 is a lie / fake fragmentation attack!).
            u16 udp_len = ntohs(udph_j->len);
            u16 l3_len  = 0;

            if (iph)
            {
                l3_len = ntohs(iph->tot_len) - sizeof(struct iphdr);
            }
#ifdef ENABLE_IPV6
            else if (iph6)
            {
                u16 ext_len = (u16)((void *)l4_hdr6 - (void *)(iph6 + 1));
                l3_len = ntohs(iph6->payload_len) - ext_len;
            }
#endif
            if (unlikely(udp_len < 8 ||
                            (!is_frag_pkt && udp_len > l3_len) ||
                            (is_frag_pkt  && udp_len <= l3_len)))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                return XDP_DROP;
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
                // (sport == 53 && dport < 1024)  ||      // DNS amplification to non-ephemeral port
                0);

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
                dport == 17185 ||                  // VxWorks WDB / IoT worm
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
                0);

            if (junk_port)
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

    // Only parse L4 headers on first fragment or unfragmented packets (is_nonfirst_frag == 0).
    // Non-first UDP fragments keep udph == NULL so payload bytes are never misread as ports,
    // while IP-level rate limiting (update_ip_stats) and IP rules still execute below!
    if (!is_nonfirst_frag)
    {

        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = (void *)iph + (iph->ihl * 4);

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end ||
                                tcph->doff < 5 ||
                                (void *)tcph + (tcph->doff * 4) > data_end))
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
                udph = (void *)iph + (iph->ihl * 4);

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
                icmph = (void *)iph + (iph->ihl * 4);

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
        // Use unwrapped nexthdr6 and l4_hdr6 (supports IPv6 Fragment Header 44 seamlessly).
        protocol = nexthdr6;

        if (!is_nonfirst_frag)
        {
            switch (nexthdr6)
            {
                case IPPROTO_TCP:
                    // Scan TCP header.
                    tcph = l4_hdr6;

                    // Check TCP header.
                    if (unlikely(tcph + 1 > (struct tcphdr *)data_end ||
                                 tcph->doff < 5 ||
                                 (void *)tcph + (tcph->doff * 4) > data_end))
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
                    udph = l4_hdr6;

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

                case IPPROTO_ICMPV6:
                    // Scan ICMPv6 header.
                    icmp6h = l4_hdr6;

                    // Check ICMPv6 header.
                    if (unlikely(icmp6h + 1 > (struct icmp6hdr *)data_end))
                    {
                        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
                        return XDP_DROP;
                    }

                    break;
            }
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
