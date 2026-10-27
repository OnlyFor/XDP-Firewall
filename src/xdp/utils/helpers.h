#pragma once

#include <common/all.h>

#include <linux/bpf.h>

#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

#ifdef __LIBXDP_STATIC__
#include <bpf_helpers.h>
#else
#include <bpf/bpf_helpers.h>
#endif

#include <xdp/utils/maps.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(x) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline int is_ip_in_range(u32 src_ip, u32 net_ip, u8 cidr);

#ifdef ENABLE_IP_RANGE_DROP
static __always_inline int check_ip_range_drop(u32 ip);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "helpers.c"

// 前置 Junk 过滤器拉黑原因码（在日志事件中以负数 filter_id = -reason 传递）
#define JUNK_REASON_TCP_PORT0          1   // TCP 源或目的端口为 0
#define JUNK_REASON_TCP_JUNK_PORT      2   // TCP 扫描常见高危/垃圾端口
#define JUNK_REASON_TCP_MCAST_DST      3   // TCP 目的地址为组播/广播
#define JUNK_REASON_TCP_SYN_COMBO      4   // TCP 非法 SYN 标志组合或 SYN+ACK 反射
#define JUNK_REASON_TCP_BAD_SYN        5   // TCP 畸形 SYN (doff<6 / win=0 / 超长 / 伪造源端口)
#define JUNK_REASON_TCP_NULL_SCAN      6   // TCP NULL 扫描 (全标志位为 0)
#define JUNK_REASON_TCP_STEALTH_SCAN   7   // TCP 慢速隐蔽扫描 (无 SYN/ACK/RST 的 FIN/PSH/URG)
#define JUNK_REASON_TCP_BAD_FLAGS      8   // TCP 非法 RST/FIN/URG 组合或 URG_PTR=0
#define JUNK_REASON_TCP_BAD_CWR        9   // TCP 非法 SYN+CWR 握手包
#define JUNK_REASON_UDP_MCAST_DST      10  // UDP 外部发往组播/广播地址
#define JUNK_REASON_UDP_PORT0          11  // UDP 源或目的端口为 0
#define JUNK_REASON_UDP_V6_ZERO_CSUM   12  // UDP IPv6 零校验和 (违反 RFC 8200)
#define JUNK_REASON_UDP_JUNK_PORT      13  // UDP 扫描常见反射/垃圾端口

#if defined(ENABLE_UDP_JUNK_FILTER) || defined(ENABLE_TCP_JUNK_FILTER)
#if JUNK_FILTER_BLOCK_TIME > 0
static __always_inline void junk_block_src(struct iphdr* iph, struct ipv6hdr* iph6, u128* src_ip6, u64 now, u16 sport, u16 dport, int reason)
{
    int did_block = 0;

    if (iph)
    {
        u8 src_msb = *((u8 *)&iph->saddr);

        int is_private = (src_msb == 10) ||                                              // 10/8
                         (src_msb == 100 && (*((u8 *)&iph->saddr + 1) >= 64) && (*((u8 *)&iph->saddr + 1) <= 127)) ||  // 100.64/10 CGNAT
                         (src_msb == 127) ||                                              // 127/8
                         (src_msb == 169 && (*((u8 *)&iph->saddr + 1) == 254)) ||        // 169.254/16 link-local/metadata
                         (src_msb == 172 && (*((u8 *)&iph->saddr + 1) >= 16) && (*((u8 *)&iph->saddr + 1) <= 31)) ||  // 172.16/12
                         (src_msb == 192 && (*((u8 *)&iph->saddr + 1) == 168));          // 192.168/16

        if (!is_private && src_msb < 224 && iph->saddr != 0)
        {
#if defined(ENABLE_ARP_FILTER)
            // u32 saddr_j;
            // __builtin_memcpy(&saddr_j, &iph->saddr, sizeof(saddr_j));
            // u8 *own = bpf_map_lookup_elem(&map_my_ip, &saddr_j);
            if (!bpf_map_lookup_elem(&map_my_ip, &iph->saddr))
#endif
            {
                u64 *allow_exp = bpf_map_lookup_elem(&map_allow_ip, &iph->saddr);
                if (!allow_exp || *allow_exp <= now)
                {
                    // u32 saddr_b;
                    // __builtin_memcpy(&saddr_b, &iph->saddr, sizeof(saddr_b));  // ← 栈上拷贝
                    u64 expire = now + (JUNK_FILTER_BLOCK_TIME * NANO_TO_SEC);
                    // bpf_map_update_elem(&map_block, &saddr_b, &expire, BPF_ANY);  // ← 用栈变量
                    bpf_map_update_elem(&map_block, &iph->saddr, &expire, BPF_ANY);  // ← 用栈变量
                    did_block = 1;
                }
            }
        }
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
        u8 s6_msb = iph6->saddr.in6_u.u6_addr8[0];

        if (s6_msb != 0 && s6_msb < 0xfc)
        {
#if defined(ENABLE_NDP_FILTER)
            // u8 *own6 = bpf_map_lookup_elem(&map_my_ip6, src_ip6);
            if (!bpf_map_lookup_elem(&map_my_ip6, src_ip6))
#endif
            {
                u64 *allow_exp6 = bpf_map_lookup_elem(&map_allow_ip6, src_ip6);
                if (!allow_exp6 || *allow_exp6 <= now)
                {
                    u64 expire = now + (JUNK_FILTER_BLOCK_TIME * NANO_TO_SEC);
                    bpf_map_update_elem(&map_block6, src_ip6, &expire, BPF_ANY);  // src_ip6 已是栈变量，OK
                    did_block = 1;
                }
            }
        }
    }
#endif

#if defined(ENABLE_FILTERS) && defined(ENABLE_FILTER_LOGGING)
    if (did_block)
    {
        filter_log_event_t *e = bpf_ringbuf_reserve(&map_filter_log, sizeof(*e), 0);
        if (e)
        {
            e->ts = now;
            e->filter_id = -reason;
            e->src_port = htons(sport);
            e->dst_port = htons(dport);
            e->ip_pps = 0;
            e->ip_bps = 0;
            e->flow_pps = 0;
            e->flow_bps = 0;

            if (iph)
            {
                e->src_ip = iph->saddr;
                e->dst_ip = iph->daddr;
                e->src_ip6[0] = 0;
                e->src_ip6[1] = 0;
                e->src_ip6[2] = 0;
                e->src_ip6[3] = 0;
                e->dst_ip6[0] = 0;
                e->dst_ip6[1] = 0;
                e->dst_ip6[2] = 0;
                e->dst_ip6[3] = 0;
                e->protocol = iph->protocol;
                e->length = (int)ntohs(iph->tot_len) + 14;
            }
#ifdef ENABLE_IPV6
            else if (iph6)
            {
                e->src_ip = 0;
                e->dst_ip = 0;
                __builtin_memcpy(e->src_ip6, iph6->saddr.in6_u.u6_addr32, sizeof(e->src_ip6));
                __builtin_memcpy(e->dst_ip6, iph6->daddr.in6_u.u6_addr32, sizeof(e->dst_ip6));
                e->protocol = (iph6->nexthdr == 44) ? IPPROTO_UDP : iph6->nexthdr;
                e->length = (int)ntohs(iph6->payload_len) + 54;
            }
#endif
            bpf_ringbuf_submit(e, 0);
        }
    }
#endif
}
#endif
#endif
