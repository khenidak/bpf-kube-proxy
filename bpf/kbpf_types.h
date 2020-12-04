#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ptrace.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <linux/bpf.h>

#ifndef ____KBPF_TYPES_H____
#define ____KBPF_TYPES_H____


#define PIN_GLOBAL_NS        2


#define MAX_SERVICE_COUNT 1024
#define MAX_IP_PER_SERVICE 16 // ipv4, ipv6 + 14 possible external/lb/whatever
#define MAX_PORTS_PER_SERVICE 16

//TODO MOVE to helpers
#define SEC(NAME) __attribute__((section(NAME), used))
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
		__u32 id;
			__u32 pinning;
};

// service key is expected to be created by userspace driver app
// typically hashof(<namespace/name>)+random byte
typedef __u64 kbpf_service_key;
typedef char kbpf_service_name[512];


// ipv4 or ipv6 ip
struct kbpf_ip {
    union {
        __be32 ipv4;
        struct in6_addr ipv6;
    };
    __be16 l2_proto;
};

// affinity is maps service->src->dest for all ports and protocols
// that means the client will always communicate with the same backend
// for any port offered on the backend
struct affinity_key {
    struct kbpf_ip client_ip; //client ip
    kbpf_service_key service; // target service
};

struct affinity {
    struct kbpf_ip ip; // backend ip
    uint64_t hit;
};

struct kbpf_service {
		kbpf_service_key key;
    // total # of backends (IMPORTANT: count of backend, not count IPs of backend)
    __u16 total_endpoints;
    // service has affinity or not
    __u16 has_affinity;
};

struct kbpf_service_backend_key {
   kbpf_service_key key;
   __be16 l2_proto;
   __u64 index; // index of this endpoint
};

struct kbpf_port_key {
    kbpf_service_key key;
    __be16 port;
    __u8 l4_proto;
};

struct kbpf_flow_key {
    kbpf_service_key key;
    // client ip
    struct kbpf_ip src_ip;
    __be16 src_port;
    __u8 l4_proto;
};

struct  kbpf_flow {
    struct kbpf_ip dest_ip;
    uint64_t hit;
};

// note:
// 1. In every turn we favor more memory than more processing
// 2. except hit counters map entries MUST be immutable.
//

// maps service name to service key. All code uses
// service key. This map is *only* used by userspace
// controller.
struct bpf_map_def SEC("maps") services_name_key = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(kbpf_service_name),
    .value_size = sizeof(kbpf_service_key),
    .max_entries = MAX_SERVICE_COUNT,
		.pinning = PIN_GLOBAL_NS,
};



// map: services {key: service details};
struct bpf_map_def SEC("maps") services = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(kbpf_service_key),
    .value_size = sizeof(struct kbpf_service),
    .max_entries = MAX_SERVICE_COUNT,
		.pinning = PIN_GLOBAL_NS,
};
// map: {service backend key (id, l2_proto, index) : ip
struct bpf_map_def SEC("maps") service_backends = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct kbpf_service_backend_key),
    .value_size = sizeof(struct kbpf_ip),
    .max_entries = MAX_SERVICE_COUNT * MAX_IP_PER_SERVICE,
		.pinning = PIN_GLOBAL_NS,
};

// map: {an ip (cluster ip, lb, external IP) : service}
struct bpf_map_def SEC("maps") service_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct kbpf_ip),
    .value_size = sizeof(kbpf_service_key),
    .max_entries = MAX_SERVICE_COUNT * MAX_IP_PER_SERVICE,
		.pinning = PIN_GLOBAL_NS,
};

// map: maps  {service port : pod port}
struct bpf_map_def SEC("maps") service_port_to_backend_port = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct kbpf_port_key),
    .value_size = sizeof(__be16),
    .max_entries = MAX_SERVICE_COUNT * MAX_PORTS_PER_SERVICE,
		.pinning = PIN_GLOBAL_NS,
};

// map: maps {pod port: service port}
struct bpf_map_def SEC("maps") backend_port_to_service_port = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct kbpf_port_key),
    .value_size = sizeof(__be16),
    .max_entries = MAX_SERVICE_COUNT * MAX_PORTS_PER_SERVICE,
		.pinning = PIN_GLOBAL_NS,
};

// map: maps a {endpoint (IP): service}
struct bpf_map_def SEC("maps") endpoints_service_key = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct kbpf_ip),
    .value_size = sizeof(kbpf_service_key),
    .max_entries = MAX_SERVICE_COUNT * MAX_PORTS_PER_SERVICE,
		.pinning = PIN_GLOBAL_NS,
};

// map: affinities
struct bpf_map_def SEC("maps") affinity = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct affinity_key),
    .value_size = sizeof(struct affinity),
    .max_entries = MAX_SERVICE_COUNT, // * max flow count?
		.pinning = PIN_GLOBAL_NS,
};

// map: flows
struct bpf_map_def SEC("maps") flows = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct kbpf_flow_key),
    .value_size = sizeof(struct kbpf_flow),
    .max_entries = MAX_SERVICE_COUNT, // * max flow count?
		.pinning = PIN_GLOBAL_NS,
};
#endif // ____KBPF_TYPES_H____
