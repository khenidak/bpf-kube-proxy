#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>


#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "kbpf_types.h"

#ifndef ____KBPF_COMMON_H____
#define ____KBPF_COMMON_H____

// hton/lton funcs inspired by facebook's katran
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


// section attribute
#ifndef __section
# define __section(NAME) \
  __attribute__((section(NAME), used))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif



// bpf maps funcs
static void* (*bpf_map_lookup_elem)(uint64_t map, void* key) = (void*)BPF_FUNC_map_lookup_elem;

static void*(*bpf_map_update_elem)(uint64_t map, void *key, void *value, int flags) = (void *) BPF_FUNC_map_update_elem;

// trace func
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *) BPF_FUNC_trace_printk;

// skb funcs
static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) = (void *) BPF_FUNC_skb_load_bytes;

static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) = (void *) BPF_FUNC_skb_store_bytes;


static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) = (void *) BPF_FUNC_l3_csum_replace;

static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) = (void *) BPF_FUNC_l4_csum_replace;

#define bpf_debug(fmt, ...)						\
						({							\
						 	char ____fmt[] = fmt;				\
							bpf_trace_printk(____fmt, sizeof(____fmt),	\
							##__VA_ARGS__);			\
						 })

// avoid using htons for l2 proto comparison
#define ETH_PROTO_IP 8
#define ETH_PROTO_IPV6 56710

// packet offset
#define OFFSET_ETH_L2_PROTO offsetof(struct ethhdr, h_proto)
#define OFFSET_BASE_ETH sizeof(struct ethhdr)

// l3 for ipv4
#define OFFSET_IPV4_SRC_IP OFFSET_BASE_ETH + offsetof(struct iphdr, saddr)
#define OFFSET_IPV4_DEST_IP OFFSET_BASE_ETH + offsetof(struct iphdr, daddr)
#define OFFSET_IPV4_L4_PROTO OFFSET_BASE_ETH  +  offsetof(struct iphdr, protocol)

// l4 for ipv4
#define OFFSET_BASE_IPV4 OFFSET_BASE_ETH + sizeof(struct iphdr)

#define OFFSET_IPV4_UDP_END OFFSET_BASE_IPV4 + sizeof(struct udphdr)
#define OFFSET_IPV4_UDP_DEST_PORT OFFSET_BASE_IPV4 + offsetof(struct udphdr, dest)
#define OFFSET_IPV4_UDP_SRC_PORT OFFSET_BASE_IPV4 + offsetof(struct udphdr, source)
#define OFFSET_IPV4_UDP_CHECK OFFSET_BASE_IPV4 + offsetof(struct udphdr, check)

#define OFFSET_IPV4_TCP_END OFFSET_BASE_IPV4 + sizeof(struct tcphdr)
#define OFFSET_IPV4_TCP_SRC_PORT OFFSET_BASE_IPV4 + offsetof(struct tcphdr, source)
#define OFFSET_IPV4_TCP_DEST_PORT OFFSET_BASE_IPV4 + offsetof(struct tcphdr, dest)
#define OFFSET_IPV4_TCP_CHECK OFFSET_BASE_IPV4 + offsetof(struct tcphdr, check)

//TODO
#define OFFSET_IPV4_SCTP_SRC_PORT OFFSET_BASE_IPV4 + offsetof(struct sctphdr, source)
#define OFFSET_IPV4_SCTP_DEST_PORT OFFSET_BASE_IPV4 + offsetof(struct sctphdr, dest)

//ipv6
#define OFFSET_IPV6_SRC_IP OFFSET_BASE_ETH + offsetof(struct ipv6hdr, saddr)
#define OFFSET_IPV6_DEST_IP OFFSET_BASE_ETH + offsetof(struct ipv6hdr, daddr)
#define OFFSET_IPV6_L4_PROTO OFFSET_BASE_ETH +  offsetof(struct ipv6hdr, nexthdr)

//l4 for ipv6
#define OFFSET_BASE_IPV6 OFFSET_BASE_ETH + sizeof(struct ipv6hdr)

#define OFFSET_IPV6_UDP_END OFFSET_BASE_IPV6 + sizeof(struct udphdr)
#define OFFSET_IPV6_UDP_DEST_PORT OFFSET_BASE_IPV6 + offsetof(struct udphdr, dest)
#define OFFSET_IPV6_UDP_SRC_PORT OFFSET_BASE_IPV6 + offsetof(struct udphdr, source)
#define OFFSET_IPV6_UDP_CHECK OFFSET_BASE_IPV6 + offsetof(struct udphdr, check)

#define OFFSET_IPV6_TCP_END OFFSET_BASE_IPV6 + sizeof(struct tcphdr)
#define OFFSET_IPV6_TCP_DEST_PORT OFFSET_BASE_IPV6 + offsetof(struct tcphdr, dest)
#define OFFSET_IPV6_TCP_SRC_PORT OFFSET_BASE_IPV6 + offsetof(struct tcphdr, source)
#define OFFSET_IPV6_TCP_CHECK OFFSET_BASE_IPV6 + offsetof(struct tcphdr, CHECK)

#define OFFSET_IPV6_SCTP_DEST_PORT OFFSET_BASE_IPV6 + offsetof(struct sctphdr, dest)
#define OFFSET_IPV6_SCTP_SRC_PORT OFFSET_BASE_IPV6 + offsetof(struct sctphdr, source)


static inline int skb_get_l2_proto(struct __sk_buff *skb, __be16 *l2_proto) {
    if(skb->data_end < (skb->data + OFFSET_BASE_ETH) ) return -1;

    return bpf_skb_load_bytes(skb, OFFSET_ETH_L2_PROTO, l2_proto, sizeof(__be16));
}

static inline int skb_get_ipv4_src_ip(struct __sk_buff *skb, __be32 *src_ip) {
    if(skb->data_end < (skb->data + OFFSET_BASE_IPV4) ) return -1;

    return bpf_skb_load_bytes(skb, OFFSET_IPV4_SRC_IP, src_ip, sizeof(__be32));
}

static inline int skb_get_ipv6_src_ip(struct __sk_buff *skb, struct in6_addr *src_ipv6) {
    if(skb->data_end < (skb->data + OFFSET_BASE_IPV6 ) ) return -1;

    return bpf_skb_load_bytes(skb, OFFSET_IPV6_SRC_IP, src_ipv6, sizeof(struct in6_addr));
}

static inline int skb_get_src_ip(struct __sk_buff *skb, struct kbpf_ip *src_ip) {
    if (src_ip->l2_proto == ETH_PROTO_IP) return skb_get_ipv4_src_ip(skb, &(src_ip->ipv4));

    return skb_get_ipv6_src_ip(skb,  &(src_ip->ipv6));
}

static inline int skb_get_ipv4_dest_ip(struct __sk_buff *skb, __be32 *dest_ip) {
    if(skb->data_end < (skb->data + OFFSET_BASE_IPV4) ) return -1;

    return bpf_skb_load_bytes(skb, OFFSET_IPV4_DEST_IP, dest_ip, sizeof(__be32));
}

static inline int skb_get_ipv6_dest_ip(struct __sk_buff *skb, struct in6_addr *dest_ipv6) {
    if(skb->data_end < (skb->data + OFFSET_BASE_IPV6 ) ) return -1;

    return bpf_skb_load_bytes(skb, OFFSET_IPV6_DEST_IP, dest_ipv6, sizeof(struct in6_addr));
}

static inline int skb_get_dest_ip(struct __sk_buff *skb, struct kbpf_ip *dest_ip) {
    if (dest_ip->l2_proto == ETH_PROTO_IP) return skb_get_ipv4_dest_ip(skb, &(dest_ip->ipv4));

    return skb_get_ipv6_dest_ip(skb,  &(dest_ip->ipv6));
}

static inline int skb_get_l4_proto(struct __sk_buff *skb, __be16 l2_proto, __u8 *l4_proto) {
    // we  call this after we asserted the size of the packet for both ipv4/ipv6
    if (l2_proto == ETH_PROTO_IP) {
        return bpf_skb_load_bytes(skb,OFFSET_IPV4_L4_PROTO, l4_proto, sizeof(__u8));
    }

    return bpf_skb_load_bytes(skb,OFFSET_IPV6_L4_PROTO, l4_proto, sizeof(__u8));
}

static inline int skb_get_dest_port(struct __sk_buff *skb, __be16 l2_proto, __u8 l4_proto, __be16 *dest_port) {
    int end_offset = 0;
    int field_offset = 0;
    if (l2_proto == ETH_PROTO_IP) {
        switch(l4_proto) {
        case IPPROTO_UDP:
            end_offset = OFFSET_IPV4_UDP_END;
            field_offset = OFFSET_IPV4_UDP_DEST_PORT;
            break;
        case IPPROTO_TCP:
            end_offset = OFFSET_IPV4_TCP_END;
            field_offset = OFFSET_IPV4_TCP_DEST_PORT;
            break;
//				case IPPROTO_SCTP:
//						 end_offset += sizeof(struct sctphdr);
//						 field_offset = OFFSET_IPV4_SCTP_DEST_PORT;
        default:
            return -1; // TODO: SCTP
            break;
        }
    } else {
        switch(l4_proto) {
        case IPPROTO_UDP:
            end_offset = OFFSET_IPV6_UDP_END;
            field_offset = OFFSET_IPV6_UDP_DEST_PORT;
            break;
        case IPPROTO_TCP:
            end_offset = OFFSET_IPV6_TCP_END;
            field_offset = OFFSET_IPV6_TCP_DEST_PORT;
            break;
//				case IPPROTO_SCTP:
//						 end_offset += sizeof(struct sctphdr);
//						 field_offset = OFFSET_IPV6_SCTP_DEST_PORT;
        default:
            return -1; // TODO: SCTP
            break;
        }
    }

    if (skb->data_end < end_offset) return -1; // bad packet

    return bpf_skb_load_bytes(skb, field_offset, &dest_port, sizeof(__be16));
}

static inline int skb_get_src_port(struct __sk_buff *skb, __be16 l2_proto, __u8 l4_proto, __be16 *src_port) {
    int end_offset = 0;
    int field_offset = 0;
    if (l2_proto == ETH_PROTO_IP) {
        switch(l4_proto) {
        case IPPROTO_UDP:
            end_offset = OFFSET_IPV4_UDP_END;
            field_offset = OFFSET_IPV4_UDP_DEST_PORT;
            break;
        case IPPROTO_TCP:
            end_offset = OFFSET_IPV4_TCP_END;
            field_offset = OFFSET_IPV4_TCP_DEST_PORT;
            break;
        default:
            return -1; // TODO: SCTP
            break;
        }
    } else {
        switch(l4_proto) {
        case IPPROTO_UDP:
            end_offset = OFFSET_IPV6_UDP_END;
            field_offset = OFFSET_IPV6_UDP_DEST_PORT;
            break;
        case IPPROTO_TCP:
            end_offset = OFFSET_IPV6_TCP_END;
            field_offset = OFFSET_IPV6_TCP_DEST_PORT;
            break;
        default:
            return -1; // TODO: SCTP
            break;
        }
    }

    if (skb->data_end < end_offset) return -1; // bad packet
    return bpf_skb_load_bytes(skb, field_offset, &src_port, sizeof(__be16));
}

// dnats a packet and updates the checksum
static inline int skb_dnat(struct __sk_buff *skb, __u8 l4_proto, struct kbpf_ip  *old_dest_ip, struct kbpf_ip  *new_dest_ip, __be16 dest_port, __be16 *backend_port) {

    uint64_t offset_dest_port = 0;
    // l4
    if (dest_port != *backend_port) {
        if(old_dest_ip->l2_proto == ETH_PROTO_IP) {
            //no default cause we assert protos early on
            switch (l4_proto ) {
            case IPPROTO_UDP:
                offset_dest_port = OFFSET_IPV4_UDP_DEST_PORT;
                break;
            case  IPPROTO_TCP:
                offset_dest_port =	OFFSET_IPV4_TCP_DEST_PORT;
                break;
            }
        } else {
            switch (l4_proto ) {
            case IPPROTO_UDP:
                offset_dest_port = OFFSET_IPV6_UDP_DEST_PORT;
                break;
            case  IPPROTO_TCP:
                offset_dest_port =	OFFSET_IPV6_TCP_DEST_PORT;
                break;
            }
        }
        // write the new backend port
        if(0 >  bpf_skb_store_bytes(skb, offset_dest_port, backend_port, sizeof(__be16), BPF_F_RECOMPUTE_CSUM)) return -1;
    }

    // original ip != new dest ip, so we always set it
    // assuming that BPF_F_RECOMPUTE_CSUM actually computes all hashes
    if(old_dest_ip->l2_proto == ETH_PROTO_IP) {
        if(0 >  bpf_skb_store_bytes(skb, OFFSET_IPV4_DEST_IP, &(new_dest_ip->ipv4), sizeof(__be32), BPF_F_RECOMPUTE_CSUM)) return -1;
    } else {
        if(0 >  bpf_skb_store_bytes(skb, OFFSET_IPV6_DEST_IP,  &(new_dest_ip->ipv6), sizeof(struct in6_addr ), BPF_F_RECOMPUTE_CSUM)) return -1;
    }

    return 1;
}
// snats a packet and updates the checksum
static inline int skb_snat(struct __sk_buff *skb, __u8 l4_proto, struct kbpf_ip  *old_src_ip, struct kbpf_ip  *new_src_ip, __be16 src_port, __be16 *service_port) {

    uint64_t offset_src_port = 0;
    // l4
    if (src_port != *service_port) {
        if(old_src_ip->l2_proto == ETH_PROTO_IP) {
            //no default cause we assert protos early on
            switch (l4_proto ) {
            case IPPROTO_UDP:
                offset_src_port = OFFSET_IPV4_UDP_SRC_PORT;
                break;
            case  IPPROTO_TCP:
                offset_src_port =	OFFSET_IPV4_TCP_SRC_PORT;
                break;
                //TODO SCTP
            }
        } else {
            switch (l4_proto ) {
            case IPPROTO_UDP:
                offset_src_port = OFFSET_IPV6_UDP_SRC_PORT;
                break;
            case  IPPROTO_TCP:
                offset_src_port =	OFFSET_IPV6_TCP_SRC_PORT;
                break;
                //TODO SCTP
            }
        }
        // write the new backend port
        if(0 >  bpf_skb_store_bytes(skb, offset_src_port, service_port, sizeof(__be16), BPF_F_RECOMPUTE_CSUM)) return -1;
    }

    // original ip != new dest ip, so we always set it
    // assuming that BPF_F_RECOMPUTE_CSUM actually computes all hashes
    if(old_src_ip->l2_proto == ETH_PROTO_IP) {
        if(0 >  bpf_skb_store_bytes(skb, OFFSET_IPV4_SRC_IP, &(new_src_ip->ipv4), sizeof(__be32), BPF_F_RECOMPUTE_CSUM)) return -1;
    } else {
        if(0 >  bpf_skb_store_bytes(skb, OFFSET_IPV6_SRC_IP,  &(new_src_ip->ipv6), sizeof(struct in6_addr ), BPF_F_RECOMPUTE_CSUM)) return -1;
    }

    return 1;
}

// state management
static inline int get_service_by_service_ip(struct kbpf_ip *ip, struct kbpf_service **service) {
    // get service key for that service ip
    kbpf_service_key *key  = bpf_map_lookup_elem((uint64_t) &backend_service, ip);
    if (key == NULL) return -1;

    // get service details for that key
    struct kbpf_service *found_service = bpf_map_lookup_elem((uint64_t) &services, key);
    if(found_service == NULL) return -1;

    *service = found_service;
    return 1;
}

// a packet going to an service.ip:port .. find an endpoint port
static inline int get_backend_port_by_service_port(struct kbpf_service *service, __be16 dest_port, __u8 l4_proto, __be16 **endpoint_port) {
    struct kbpf_port_key port_key = {0};
    port_key.key       = service->key;
    port_key.port = dest_port;
    port_key.l4_proto  = l4_proto;


    __be16 *port = bpf_map_lookup_elem((uint64_t) &service_port_to_backend_port, &port_key);
    if (port == NULL) return -1;

    *endpoint_port = port;
    return 1;
}

// a packet coming from a pod
static inline int get_service_port_by_backend_port(struct kbpf_service *service, __be16 src_port, __u8 l4_proto, __be16 **out_port) {
    struct kbpf_port_key port_key = {0};

    port_key.key       = service->key;
    port_key.port = src_port;
    port_key.l4_proto  = l4_proto;


    __be16 *port = bpf_map_lookup_elem((uint64_t) &backend_port_to_service_port, &port_key);
    if (port == NULL) return -1;

    *out_port = port;
    return 1;
}

static inline int find_flow(struct kbpf_service *service, __u8 l4_proto, struct kbpf_ip *src_ip, __be16 src_port, struct kbpf_ip **new_ip) {
    struct kbpf_flow_key flow_key = {0};

    flow_key.key = service->key;
    flow_key.src_ip = *src_ip;
    flow_key.src_port = src_port;
    flow_key.l4_proto = l4_proto;

    struct kbpf_flow *flow  = bpf_map_lookup_elem((uint64_t) &flows, &flow_key);
    if (flow == NULL) return -1;

    // found a flow. Write ip to new_ip
    *new_ip =  &(flow->dest_ip);

    // add hit
    __sync_fetch_and_add(&(flow->hit), 1);

    return 1;
}


static inline int load_balance(struct kbpf_service *service, __u8 l4_proto, struct kbpf_ip *src_ip, __be16 src_port, struct kbpf_ip **new_ip) {
// load balancing logic. need to be deterministic, as long as total backend endpoints
// didn't change between every call
// + for services without affinity we use proto |  src_port | ip
// + for service with affinity we use src_ip
//

// we can do rot13 or something like that. something better. But that should be enough for at least inital testing
    __u64 idx = 0;

    if (service->has_affinity != 0) {
        if(src_ip->l2_proto == ETH_PROTO_IP) {
            idx = ( ((__u64) l4_proto << 56) |
                    ((__u64) src_port << 48)  |
                    ((__u64) src_ip->ipv4 << 32) ) % service->total_endpoints;
        } else {

            idx = ( ((__u64) l4_proto << 56) |
                    ((__u64) src_port << 48) |
                    ((__u64) src_ip->ipv6.in6_u.u6_addr32[0]) |
                    ((__u64) src_ip->ipv6.in6_u.u6_addr32[2]) ) % service->total_endpoints;
        }
    } else {

        if(src_ip->l2_proto == ETH_PROTO_IP) {
            idx = ( ((__u64)src_port << 48) |
                    ((__u64) src_ip->ipv4 << 32) ) % service->total_endpoints;
        } else {
            idx = ( ((__u64) l4_proto << 56) |
                    ((__u64) src_port << 48) |
                    ((__u64) src_ip->ipv6.in6_u.u6_addr32[0]) |
                    ((__u64) src_ip->ipv6.in6_u.u6_addr32[2]) ) % service->total_endpoints;
        }
    }

    // we have an index, let us find an ip for it./
    struct kbpf_service_backend_key backend_key = {0};
    backend_key.key = service->key;
    backend_key.index = idx; // index of this endpoint
    backend_key.l2_proto = src_ip->l2_proto;

    struct kbpf_ip *target_ip = bpf_map_lookup_elem((uint64_t) &service_backends, &backend_key);
    if(target_ip == NULL) return -1;
    *new_ip = target_ip;

    return 0;
}

static inline int create_affinity(struct kbpf_service *service, struct kbpf_ip *src_ip, struct kbpf_ip *new_ip) {
    struct affinity_key aff_key = {0};
    aff_key.client_ip = *src_ip; //client ip
    aff_key.service = service->key; // target service

    struct affinity aff_data = {0};
    aff_data.hit = 1;
    // verifier needs this assertion
    if (new_ip != NULL)  memcpy(&aff_data.ip, new_ip, sizeof(struct kbpf_ip));

    if (0 >  bpf_map_update_elem((uint64_t) &affinity,  &aff_key, &aff_data, BPF_ANY)) return -1;

    return 1;
}

static inline int create_flow(struct kbpf_service *service, __u8 l4_proto,  struct kbpf_ip *src_ip, __be16 src_port, struct kbpf_ip *new_ip) {

    struct kbpf_flow_key flow_key = {0};
    flow_key.key = service->key;
    flow_key.src_ip = *src_ip;
    flow_key.src_port = src_port;
    flow_key.l4_proto = l4_proto;

    struct  kbpf_flow flow_data = {0};
    flow_data.hit = 1;

    // verifer needs this.
    if(new_ip != NULL) memcpy(&flow_data.dest_ip, new_ip, sizeof(struct kbpf_ip));

    //create flow
    if (0 >  bpf_map_update_elem((uint64_t) &flows, &flow_key, &flow_data, BPF_ANY)) return -1;

    return 1;
}

// finds a target destination (backend) for a service+src_ip:port+l4_proto
// if a flow is not there, it will create one
// if an affinity is not there and service needs it it will create one
static inline int lb_create_flow_affinity(struct kbpf_service *service, __u8 l4_proto, struct kbpf_ip *src_ip, __be16 src_port, struct kbpf_ip **new_ip) {
    // find a backend (pod) for this
    if(0 > load_balance(service,l4_proto, src_ip, src_port, new_ip)) {
        return -1;
    }

    // create flow
    if(0 > create_flow(service, l4_proto, src_ip, src_port, *new_ip)) return -1;

    //service does not use affinity
    if(service->has_affinity == 0) return 0;

    // create the affinity
    return create_affinity(service, src_ip,  *new_ip);
}

// finds affinity
static inline int find_affinity(struct kbpf_service *service,struct kbpf_ip *src_ip, struct kbpf_ip **new_ip) {
    struct affinity_key aff_key = {0};
    aff_key.client_ip = *src_ip; //client ip
    aff_key.service = service->key; // target service

    struct affinity *aff = bpf_map_lookup_elem((uint64_t) &affinity, &aff_key);
    if(aff == NULL) return -1;

    // copy the dest ip for this affinity
    *new_ip = &(aff->ip);

    __sync_fetch_and_add(&(aff->hit), 1);
    return 1;
}
#endif // ____KBPF_COMMON_H____
