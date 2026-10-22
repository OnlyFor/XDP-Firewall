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


#if defined(ENABLE_UDP_JUNK_FILTER) || defined(ENABLE_TCP_JUNK_FILTER)
#if JUNK_FILTER_BLOCK_TIME > 0
static __always_inline void junk_block_src(struct iphdr* iph, struct ipv6hdr* iph6, u128* src_ip6, u64 now)
{
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
                // u32 saddr_b;
                // __builtin_memcpy(&saddr_b, &iph->saddr, sizeof(saddr_b));  // ← 栈上拷贝
                u64 expire = now + (JUNK_FILTER_BLOCK_TIME * NANO_TO_SEC);
                // bpf_map_update_elem(&map_block, &saddr_b, &expire, BPF_ANY);  // ← 用栈变量
                bpf_map_update_elem(&map_block, &iph->saddr, &expire, BPF_ANY);  // ← 用栈变量
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
                u64 expire = now + (JUNK_FILTER_BLOCK_TIME * NANO_TO_SEC);
                bpf_map_update_elem(&map_block6, src_ip6, &expire, BPF_ANY);  // src_ip6 已是栈变量，OK
            }
        }
    }
#endif
}
#endif
#endif
