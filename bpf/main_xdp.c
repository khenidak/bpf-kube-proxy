#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ptrace.h>
#include <stdbool.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <stdbool.h>

#include <linux/bpf.h>


#ifndef __section
# define __section(NAME) \
  __attribute__((section(NAME), used))
#endif



#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)     __builtin_bswap16(x)
# define __bpf_htons(x)     __builtin_bswap16(x)
# define __bpf_constant_ntohs(x)  ___constant_swab16(x)
# define __bpf_constant_htons(x)  ___constant_swab16(x)
# define __bpf_ntohl(x)     __builtin_bswap32(x)
# define __bpf_htonl(x)     __builtin_bswap32(x)
# define __bpf_constant_ntohl(x)  ___constant_swab32(x)
# define __bpf_constant_htonl(x)  ___constant_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)     (x)
# define __bpf_htons(x)     (x)
# define __bpf_constant_ntohs(x)  (x)
# define __bpf_constant_htons(x)  (x)
# define __bpf_ntohl(x)     (x)
# define __bpf_htonl(x)     (x)
# define __bpf_constant_ntohl(x)  (x)
# define __bpf_constant_htonl(x)  (x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x)        \
  (__builtin_constant_p(x) ?    \
   __bpf_constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x)        \
  (__builtin_constant_p(x) ?    \
   __bpf_constant_ntohs(x) : __bpf_ntohs(x))
#define bpf_htonl(x)        \
  (__builtin_constant_p(x) ?    \
   __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)        \
  (__builtin_constant_p(x) ?    \
   __bpf_constant_ntohl(x) : __bpf_ntohl(x))



static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *) BPF_FUNC_trace_printk;
// TODO: FIGURE THIS OUT. Adding debug messages breaks verifer

#define bpf_debug(fmt, ...)						\
						({							\
						 	char ____fmt[] = fmt;				\
							bpf_trace_printk(____fmt, sizeof(____fmt),	\
							##__VA_ARGS__);			\
						 })

// we dont want to do htons for each packet, so this is ETH_P_IPV6 and
// // ETH_P_IP in be format
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

/*
static int (*bpf_csum_diff)(void *from, int from_size, void *to, int to_size, int seed) =
    (void *) BPF_FUNC_csum_diff;


__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i ++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void *data_start, int data_size,  __u64 *csum) {
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv4_csum_inline(void *iph, __u64 *csum) {
    __u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
        *csum += *next_iph_u16++;
    }
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv4_l4_csum(void *data_start, int data_size,
                                __u64 *csum, struct iphdr *iph) {
    __u32 tmp = 0;
    *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
    *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
    tmp = __builtin_bswap32((__u32)(iph->protocol));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    tmp = __builtin_bswap32((__u32)(data_size));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv6_csum(void *data_start, int data_size,
                             __u64 *csum, struct ipv6hdr *ip6h) {
    // ipv6 pseudo header
    __u32 tmp = 0;
    *csum = bpf_csum_diff(0, 0, &ip6h->saddr, sizeof(struct in6_addr), *csum);
    *csum = bpf_csum_diff(0, 0, &ip6h->daddr, sizeof(struct in6_addr), *csum);
    tmp = __builtin_bswap32((__u32)(data_size));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    tmp = __builtin_bswap32((__u32)(ip6h->nexthdr));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    // sum over payload
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}


*/

// Checksum utilities
__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i ++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

// Update checksum following RFC 1624 (Eqn. 3): https://tools.ietf.org/html/rfc1624
//     HC' = ~(~HC + ~m + m')
// Where :
//   HC  - old checksum in header
//   HC' - new checksum in header
//   m   - old value
//   m'  - new value
__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result !
    *csum = csum_fold_helper(*csum);
}


__attribute__((__always_inline__))
static inline int update_udp_checksum(__u64 cs, __be32 old_addr, __be32 new_addr) {
    update_csum(&cs , old_addr, new_addr);
    return cs;
}

__attribute__((__always_inline__))
static inline void update_ip_checksum(struct iphdr *iph, __be32 old_addr, __be32 new_addr) {
    __u64 cs = iph->check;
    update_csum(&cs, old_addr, new_addr);
    iph->check = cs;
}

// TODO this needs to be ethhdr not custom struct
struct eth_hdr {
    unsigned char eth_dest[ETH_ALEN];
    unsigned char eth_source[ETH_ALEN];
    unsigned short  eth_proto;
};


static inline int route_packet(struct xdp_md *ctx)
{

    int offset = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    offset = sizeof(struct ethhdr);
    if (data + offset > data_end) {
        bpf_debug("packet drop: ethernet header too big");
        return XDP_PASS;
    }

    struct iphdr *ip = data + offset  ;
    offset += sizeof(struct iphdr) ;
    if (data + offset > data_end) {
        bpf_debug("packet drop: ip header too big \n");
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP ) {
        struct udphdr *udph = data + offset;
        offset += sizeof(struct udphdr); // if we work with more headers then we need to +1;
        if (data + offset > data_end) {
            bpf_debug("packet drop: udp header too big\n");
            return XDP_PASS;
        }

        // bpf_debug("IP SRC %d DEST %d \n",  bpf_ntohl(ip->saddr),  bpf_ntohl(ip->daddr));
        // bpf_debug("PORT SRC %d DEST %d \n",  udph->source, udph->dest);

				bpf_debug("packet %d:%d\n",   bpf_ntohs(udph->source), bpf_ntohs(udph->dest));

				// if going to 8.8.8.8:53
        if( ip->daddr == bpf_htonl(134744072) &&  udph->dest == bpf_htons(53) ) {
            bpf_debug("packet\n");
            __be32 old_daddr = ip->daddr;
            ip->daddr  = bpf_htonl(16843009); // 1.1.1.1
           // update_ip_checksum(ip,  old_daddr, ip->daddr);
						// udph->check = update_udp_checksum(udph->check, old_daddr, ip->daddr);

            return XDP_PASS;
        }else{
				bpf_debug("not packet\n");
				}
    }
    return XDP_PASS;

    /*
            struct iphdr *iph = data + nh_off;
            __be32 dest = iph->daddr;
            int protocol =  iph->protocol;



            // TODO
            // find an existing flow
            // if a flow exists: use dest to set dest IP (SHOULD WE SET ON IP AND HIGHER LEVEL PROTO?)
            // IF not: lookup map using IP + Proto to find dest
            // (SHOULD WE SET ON IP AND HIGHER LEVEL PROTO?)

            if (protocol == IPPROTO_UDP) {
                // bpf_debug("got udp");
                if (dest == htons(1684300)) { // 1.1.1.1
                    return XDP_DROP;
                }
            }

            return XDP_PASS;
    */
}


__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
				/*
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth = data;

    __u32 eth_proto;
    __u32 nh_off;
    nh_off = sizeof(struct eth_hdr);

    if (data + nh_off > data_end) {
        // bad packet
        // TODO: add counter
        return XDP_DROP;
    }

    eth_proto = eth->eth_proto;

    // pass anything that is not IPv4 || IPv6
    if (eth_proto != BE_ETH_P_IP && eth_proto != BE_ETH_P_IPV6) {
        // TODO: add counter
        //  bpf_debug("packet drop: not ipv4 or ipvy \n");
        return XDP_PASS;
    }
		*/
    return route_packet(ctx);
}

char __license[] __section("license") = "GPL";

