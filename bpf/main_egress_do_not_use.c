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
#include <linux/pkt_cls.h>

#include "kbpf_types.h"
#include "kbpf_common.h"


__section("egress")
static inline int route_packet_egress(struct __sk_buff  *skb)
{
    int offset = 0;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // packet
    struct ethhdr *eth;
    struct iphdr *ip;
    struct ipv6hdr *ipv6;
    struct udphdr *udp;
    struct tcphdr *tcp;

    eth = data;
    offset = sizeof(struct ethhdr);
    if (data + offset > data_end) {
        bpf_debug("packet drop: ethernet header too big");
        return TC_ACT_OK;
    }

    if(eth->h_proto != ETH_PROTO_IP && eth->h_proto == ETH_PROTO_IPV6) {
        //TODO: log
        return TC_ACT_OK;
    }


    if (eth->h_proto == ETH_PROTO_IP) {
        ip = data + offset;
        offset += sizeof(struct iphdr) ;

        if (data + offset > data_end) {
            bpf_debug("packet drop: ip header too big \n");
            return TC_ACT_OK;
        }
    } else {
        //ipv6
        ipv6 = data + offset;
        offset += sizeof(struct ipv6hdr);

        if (data + offset > data_end) {
            bpf_debug("packet drop: ip header too big \n");
            return TC_ACT_OK;
        }
    }

		__u8 proto = (eth->h_proto == ETH_PROTO_IP) ? ip->protocol : ipv6->nexthdr;
    switch (proto) {
    case IPPROTO_UDP:
        udp = data + offset;
				
        offset += sizeof(struct udphdr); // if we work with more headers then we need to +1;
        if (data + offset > data_end) {
            bpf_debug("packet drop: udp header too big\n");
            return TC_ACT_OK;
        }
        break;
    case IPPROTO_TCP:

        tcp = data + offset;
			
        offset += sizeof(struct tcphdr); // if we work with more headers then we need to +1;
        if (data + offset > data_end) {
            bpf_debug("packet drop: udp header too big\n");
            return TC_ACT_OK;
        }
        break;

defaut:
        return TC_ACT_OK; // TODO SCTP
        break;
    }
    /*
		egress:
			find by flow {IP_VER, SRC_IP, SRC_PORT, PROTO}
			if found:
				dnat to flow's {DEST_IP, DEST_PORT}
				increase flow hit
			else
				find by affinity {IP_VER, SRC_IP, DEST_IP, DEST_PORT, PROTO};
				if found:
					dnat to {DEST_IP, DEST_PORT}
					find or create flow
					increament affinity
					return
				end if
				// new packet no flow.. no affinity
				find by KEY{IP_VER, DEST_IP, DEST_PORT,PROTO};
				if found:
					dnat packet to IP/PORT
					create flow
					create affinity if needed
				else
					<DROP>

		ingress:
			find flow by {SRC_IP, SRC_PORT, DEST_IP, DEST_PORT, VER, PROTO
			if found
				snat to service ip:port

		data structures optimized for o(1):
		service map key{IP,PORT,PROTO,IP_VER} DATA:{SESSION_AFFINITY, TOTAL_endpoints}
		service_endpoints map {<service key>, idx<unique for each service list>} {endpoint_key>} // need index allow LBs by hashing
		endpoints map  key{IP,PORT,PROTO,IP_VER} data:{<service key>}

		flow map: {IP_VER, SRC_IP, SRC_PORT, PROTO} {endpoint-key}
		affinity map:{IP_VER, SRC_IP, DEST_IP, DEST_PORT, PROTO} {endpoint-key}

		// ***



    if (ip->protocol == IPPROTO_UDP ) {
    struct udphdr *udph = data + offset;
    offset += sizeof(struct udphdr); // if we work with more headers then we need to +1;
    if (data + offset > data_end) {
        bpf_debug("packet drop: udp header too big\n");
        return TC_ACT_OK;
    }


    // if going to 8.8.8.8:53
    if( ip->daddr == bpf_htonl(  134744072 ) &&  udph->dest == bpf_htons(53) ) {
        bpf_debug("packet\n");
        __be32  old_ip;
        __be32 new_ip = 134744072; // == (8.8.8.8)   ||  16843009 ==  1.1.1.1
        int ret;
        int flags = IS_PSEUDO;

        flags |= BPF_F_MARK_MANGLED_0;
        if (0 > (ret = bpf_skb_load_bytes(skb,  IP_DST_OFF, &old_ip, 4))) {
            bpf_debug("bpf_skb_load_bytes failed: %d\n", ret);
            return BPF_DROP;
        }

        if(0 > (ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) +  IP_DST_OFF, &new_ip, sizeof(new_ip), 0))) {
            bpf_debug("bpf_skb_store_bytes() failed: %d\n", ret);
            return BPF_DROP;

        }


        if(0 > (ret = bpf_l4_csum_replace(skb, UDP_CSUM_OFF, old_ip, new_ip, flags | sizeof(new_ip)))) {
            bpf_debug("bpf_l4_csum_replace failed: %d\n");
            return BPF_DROP;
        }


        if(0 > (ret = bpf_l3_csum_replace(skb,  IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip)))) {
            bpf_debug("bpf_l3_csum_replace failed: %d\n", ret);
            return BPF_DROP;
        }

        return TC_ACT_OK;
    }
    }
    */
    return TC_ACT_OK;


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
char __license[] __section("license") = "GPL";

