#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ptrace.h>
#include <stdbool.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#ifndef ____PACKET____
#define	____PACKET____

// when working creating a metadata, stop at which layer?
#define PACKET_METADATA_L4 4
#define PACKET_METADATA_L3 3
#define PACKET_METADATA_L2 2

// short cut to avoid calling ntoh to check ip proto
#define ETH_PROTO_IP 8
#define ETH_PROTO_IPV6 56710


// packet metadata represent an indexer over a packet
// it is a minimal data structure and is meant to stay
// on stack.
struct packet_metadata {
    struct ethhdr *eth;
    union  {
        struct iphdr *ip;
        struct ipv6hdr *ip6;
    };

    union  {
        struct udphdr *udp;
        struct tcphdr *tcp;
    };
};



/// parses the packet from bottom layer upward. success == returning layer requested
// target_layer: max top layer to process.
// meta: set to target layer or less if process failed to parse layers
// data and data_end: __sk_buff or xdp_md data and data end members
 __attribute__((__always_inline__))
int inline packet_metadata_create(int target_layer, struct packet_metadata *meta, __u32 data, __u32 data_end) {
    int offset = 0;

    void *start = (void *)(long) data;
		void *end =  (void *)(long) data_end;


    offset = sizeof(struct ethhdr);
    if (start + offset > end) {
        //TODO bpf_debug("packet drop: ethernet header too big");
        return PACKET_METADATA_L2;
    }

    meta->eth = (struct ethhdr *) start;

    // stop?
    if(target_layer == PACKET_METADATA_L2) return PACKET_METADATA_L2;

    // we don't operate on anything ther than ipv4 and ipv6
    if(meta->eth->h_proto != ETH_PROTO_IP && meta->eth->h_proto == ETH_PROTO_IPV6) {
        //TODO: log
        return PACKET_METADATA_L2;
    }
    if(meta->eth->h_proto == ETH_PROTO_IP) {
        offset += sizeof(struct iphdr);
        if (start + offset > end) {
            // TODO: bpf_debug("packet drop: ip header too big \n");
            return PACKET_METADATA_L2;
        }
        meta->ip = (struct iphdr *) start + offset;
    } else {
        // ipv6
        offset += sizeof(struct ipv6hdr);
        if(start + offset > end) {
            // TODO: bpf_debug("packet drop: ip header too big \n");
            return PACKET_METADATA_L2;
        }
        meta->ip6 = (struct ipv6hdr *) start + offset;
    }

    if(target_layer == PACKET_METADATA_L3) return PACKET_METADATA_L3;

    //l4
    bool is_udp = meta->eth->h_proto == ETH_PROTO_IP ?
                  meta->ip->protocol == IPPROTO_UDP :
                  meta->ip6->nexthdr == IPPROTO_UDP; //TODO: will that work extention headers?
    if (is_udp) {
				 offset += sizeof(struct udphdr);
        if (start + offset > end) return PACKET_METADATA_L3; //TODO LOG
        meta->udp = (struct udphdr *) start + offset;

    } else {
        // process as tcp
				offset += sizeof(struct udphdr);
        if (start + offset > end) return PACKET_METADATA_L3; //TODO LOG
        meta->tcp = (struct tcphdr *) start + offset;
    }
    return PACKET_METADATA_L4;
}
#endif /* ____PACKET____ */
