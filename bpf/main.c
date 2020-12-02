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
static inline int route_egress(struct __sk_buff  *skb)
{
    // read from packet
    struct kbpf_ip src_ip = {};
    struct kbpf_ip dest_ip = {};
    __be16 src_port =0;
    __be16 dest_port = 0;
    __u8 l4_proto = 0; //udp..tcp..etc

    // read from the state
    struct kbpf_service *service = NULL;
    struct kbpf_ip *new_ip = NULL;
    __be16 *backend_port = NULL;


    // get l2 proto
    if (0 > skb_get_l2_proto(skb, &src_ip.l2_proto)) {
        bpf_debug("failed packet: can not read eth header\n");
        return TC_ACT_OK;
    }

    // operate only on ipv4 and ipv6
    if (src_ip.l2_proto != ETH_PROTO_IP && src_ip.l2_proto != ETH_PROTO_IPV6) {
        bpf_debug("failed packet: not ipv4 or ipv6\n");
        return TC_ACT_OK;
    }

    // sync l2 proto for dest/src
    dest_ip.l2_proto = src_ip.l2_proto;

    // get dest ip
    if(0 > skb_get_dest_ip(skb, &dest_ip)) {
        bpf_debug("failed packet: failed to get destt ip\n");
        return TC_ACT_OK;
    }

    // before going any further. let us check if the packet
    // is destined to any of our services
    if(0 > get_service_by_service_ip(&dest_ip, &service)) {
        return TC_ACT_OK;
    }

    if(0 > skb_get_l4_proto(skb, src_ip.l2_proto, &l4_proto)) {
        bpf_debug("failed packet: can't read l4 protocol \n");
        return TC_ACT_OK;
    }

    // we operate on udp,tcp, sctp (todo)
    if(l4_proto != IPPROTO_UDP && l4_proto != IPPROTO_TCP /* && l4_proto != IPPROTO_SCTP */) {
        bpf_debug("failed packet: packet is not udp or tcp or sctp \n");
        return TC_ACT_OK; // we may as well drop it
    }

    // ensure that dest port maps to a pod port
    // get dest port
    if(0 > skb_get_dest_port(skb, dest_ip.l2_proto, l4_proto, &dest_port)) {
        bpf_debug("failed packet: failed to read dest port \n");
        return TC_ACT_OK;
    }

    // if service port (dest ip) not going to a port that is mapped to a pod
    if (0 > get_backend_port_by_service_port(service,  dest_port, l4_proto, &backend_port)) {
        bpf_debug("failed packet: unknown dest port \n");
        return TC_ACT_SHOT; // this packet will not go any where
    }

    // at this point, all the next steps require source ip:port
    if(0 > skb_get_src_ip(skb, &src_ip)) {
        bpf_debug("failed packet: failed to get src ip \n");
        return TC_ACT_OK;
    }

    if(0 > skb_get_src_port(skb, src_ip.l2_proto, l4_proto, &src_port)) {
        bpf_debug("failed packet: failed to get src port \n");
        return TC_ACT_OK;
    }

    // find an existing flow
    if (find_flow(service, l4_proto, &src_ip, src_port,  &new_ip)) {
        if(new_ip == NULL) return TC_ACT_SHOT;// verifier
        if( 0 > skb_dnat(skb, l4_proto, &dest_ip, new_ip,  dest_port, backend_port)) {
            bpf_debug("failed packet: failed to dnat based on flow \n");
            return TC_ACT_SHOT;
        }

        return  TC_ACT_OK;
    }

    // no existing flow. Let try finding an existing affinity
    if(find_affinity(service, &src_ip, &new_ip)) {
        // create flow based on the affinity
        if(new_ip == NULL) return TC_ACT_SHOT;// verifier
        if(0 > create_flow(service, l4_proto, &src_ip, src_port, new_ip)) {
            bpf_debug("failed packet: failed to create flow \n");
            return TC_ACT_SHOT;
        }

        // dnat the packet
        if( 0 > skb_dnat(skb, l4_proto, &dest_ip, new_ip,  dest_port, backend_port)) {
            bpf_debug("failed packet: failed to dnat based on AFFINITY \n");
            return TC_ACT_SHOT;
        }
        return  TC_ACT_OK;
    }

    // loadbalance, create a new flow and affinity if needed
    if(lb_create_flow_affinity(service, l4_proto,  &src_ip, src_port, &new_ip)) {
        bpf_debug("failed packet: faild to lb or create flow or create affinity \n");
        TC_ACT_SHOT;
    }

    // dnat
    if( 0 > skb_dnat(skb, l4_proto, &dest_ip, new_ip,  dest_port, backend_port)) {
        bpf_debug("failed packet: failed to dnat based on LB \n");
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

__section("ingress")
static inline int route_ingress(struct __sk_buff  *skb)
{
    // read from packet
    struct kbpf_ip src_ip = {};
    struct kbpf_ip dest_ip = {};
    __be16 src_port =0;
    __be16 dest_port = 0;
    __u8 l4_proto = 0; //udp..tcp..etc

    // read from the state
    struct kbpf_service *service = NULL;
    struct kbpf_ip *new_ip = NULL;
    __be16 *service_port = NULL;


    // get l2 proto
    if (0 > skb_get_l2_proto(skb, &src_ip.l2_proto)) {
        bpf_debug("failed packet: can not read eth header\n");
        return TC_ACT_OK;
    }

    // operate only on ipv4 and ipv6
    if (src_ip.l2_proto != ETH_PROTO_IP && src_ip.l2_proto != ETH_PROTO_IPV6) {
        bpf_debug("failed packet: not ipv4 or ipv6\n");
        return TC_ACT_OK;
    }

    // sync l2 proto for dest/src
    dest_ip.l2_proto = src_ip.l2_proto;

    // get dest ip
    if(0 > skb_get_src_ip(skb, &src_ip)) {
        bpf_debug("failed packet: failed to get src ip\n");
        return TC_ACT_OK;
    }

    // before going any further. let us check if the packet
    // is destined to any of our services
    if(0 > get_service_by_service_ip(&src_ip, &service)) {
        bpf_debug("failed packet: no service \n");
        return TC_ACT_OK;
    }

    if(0 > skb_get_l4_proto(skb, src_ip.l2_proto, &l4_proto)) {
        bpf_debug("failed packet: can't read l4 protocol \n");
        return TC_ACT_OK;
    }

    // we operate on udp,tcp, sctp (todo)
    if(l4_proto != IPPROTO_UDP && l4_proto != IPPROTO_TCP /* && l4_proto != IPPROTO_SCTP */) {
        bpf_debug("failed packet: packet is not udp or tcp or sctp \n");
        return TC_ACT_OK; // we may as well drop it
    }

    // ensure that dest port maps to a pod port
    // get dest port
    if(0 > skb_get_src_port(skb, src_ip.l2_proto, l4_proto, &src_port)) {
        bpf_debug("failed packet: failed to read src port \n");
        return TC_ACT_OK;
    }

    // if service port (dest ip) not going to a port that is mapped to a pod
    if (0 > get_service_port_by_backend_port(service, src_port, l4_proto, &service_port)) {
        bpf_debug("failed packet: unknown dest port \n");
        return TC_ACT_SHOT; // this packet will not go any where
    }

/////////////////
    // at this point, all the next steps require source ip:port
    if(0 > skb_get_dest_ip(skb, &dest_ip)) {
        bpf_debug("failed packet: failed to get src ip \n");
        return TC_ACT_OK;
    }

    if(0 > skb_get_dest_port(skb, src_ip.l2_proto, l4_proto, &dest_port)) {
        bpf_debug("failed packet: failed to get src port \n");
        return TC_ACT_OK;
    }

    // find an existing flow
    if (find_flow(service, l4_proto, &dest_ip, dest_port,  &new_ip)) {
        if(new_ip == NULL) return TC_ACT_SHOT;// verifier
        if( 0 > skb_snat(skb, l4_proto, &src_ip, new_ip,  src_port, service_port)) {
            bpf_debug("failed packet: failed to dnat based on flow \n");
            return TC_ACT_SHOT;
        }
        return  TC_ACT_OK;
    }
		// packet has no flow. So it must not be snatted
    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";

