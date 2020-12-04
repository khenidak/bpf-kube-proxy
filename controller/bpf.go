package controller

/*
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef uint64_t  kbpf_service_key;
typedef char kbpf_service_name[512];



struct kbpf_service {
		kbpf_service_key key;
    // total # of pods (IMPORTANT: count of pods, not count IPs of pods)
    uint16_t total_endpoints;
    // service has affinity or not
    uint16_t has_affinity;
};

struct kbpf_port_key {
    kbpf_service_key key;
    uint16_t port;
    uint8_t l4_proto;
};

struct kbpf_ip {
	  // note: this is defined as union. we changed it to make it
	  // easier to handle it with golang
    uint32_t ip[4];
    uint16_t l2_proto;
};

//hton-ed eth l2 protos
#define ETH_PROTO_IP 8
#define ETH_PROTO_IPV6 56710

*/
import "C"

//import "fmt"

import (
	"net"
	"sync"
	"unsafe"

	// this should be replaced with a simpler version
	// that only wraps the functions we need
	"github.com/dropbox/goebpf"
)

// --- IMPORTANT ---------------//
//(1)  Types here are a mirror of kbpf_types.h
// some data types has changed to get away from kernel own data types
// we are just using types that maps to these.

// (2) all functions must be called with service.lock held
//----------------------------------------------

const kbpf_service_name_length = 512 // MUST BE SYNCED TO TYPES AND IN C CODE HERE IN THIS FILE

const map_path_service_name_key string = "/sys/fs/bpf/tc/globals/services_name_key"
const map_path_services string = "/sys/fs/bpf/tc/globals/services"
const map_path_service_port_to_backend_port = "/sys/fs/bpf/tc/globals/service_port_to_backend_port"
const map_path_backend_port_to_service_port = "/sys/fs/bpf/tc/globals/backend_port_to_service_port"
const map_path_service_ips_to_service = "/sys/fs/bpf/tc/globals/service_ips"
const map_path_backend_service = "/sys/fs/bpf/tc/globals/backend_service"

var bpfMaps map[string]*goebpf.EbpfMap
var bpfMapMu sync.Mutex

// funcs that are named Bpf* manages the data saved in bpf maps
// on kernel side. All network related data is hton before writing ntoh after reading

func bpfCloseAllMaps() {
	bpfMapMu.Lock()
	defer bpfMapMu.Unlock()

	for k, v := range bpfMaps {
		v.Close()
		delete(bpfMaps, k)
	}
}

func bpfGetMap(p string) (*goebpf.EbpfMap, error) {
	bpfMapMu.Lock()
	defer bpfMapMu.Unlock()
	if bpfMaps == nil {
		bpfMaps = make(map[string]*goebpf.EbpfMap)
	}
	// is it already open?
	if m, ok := bpfMaps[p]; ok {
		return m, nil
	}

	m, err := goebpf.NewMapFromExistingMapByPath(p)
	if err != nil {
		return nil, err
	}

	bpfMaps[p] = m

	return m, nil
}

func bpfInsertOrUpdateBackendToService(bpfId uint64, ip net.IP) error {
	mapBackendService, err := bpfGetMap(map_path_backend_service)
	if err != nil {
		return err
	}

	kbpfIP := *(ipToKbpfIP(ip))
	buff := make([]byte, C.sizeof_struct_kbpf_ip, C.sizeof_struct_kbpf_ip)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&kbpfIP), C.sizeof_struct_kbpf_ip)

	return mapBackendService.Upsert(buff, bpfId)
}

func bpfGetBackendsToService(bpfId uint64) ([]net.IP, error) {

	all := make([]net.IP, 0)
	mapBackendService, err := bpfGetMap(map_path_backend_service)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, C.sizeof_struct_kbpf_ip, C.sizeof_struct_kbpf_ip)
	C.memset(unsafe.Pointer(&buff[0]), 0, C.sizeof_struct_kbpf_port_key)

	for {
		buff, err = mapBackendService.GetNextKey(buff)
		if err != nil {
			return all, nil // error is returned when last key is read. // TODO find a better way
		}
		if len(buff) == 0 {
			return all, nil
		}
		buffBpfId, err := mapBackendService.Lookup(buff)
		if err != nil {
			return nil, err
		}

		savedBpfId := *(*uint64)(unsafe.Pointer(&buffBpfId[0]))

		if savedBpfId == bpfId {
			thisKey := *(*C.struct_kbpf_ip)(unsafe.Pointer(&buff[0]))
			all = append(all, kbpfIPToIP(&thisKey))
		}
	}

	return all, nil

}

func bpfDeleteBackendToService(bpfId uint64, ip net.IP) error {
	mapBackendService, err := bpfGetMap(map_path_backend_service)
	if err != nil {
		return err
	}

	kbpfIP := *(ipToKbpfIP(ip))
	buff := make([]byte, C.sizeof_struct_kbpf_ip, C.sizeof_struct_kbpf_ip)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&kbpfIP), C.sizeof_struct_kbpf_ip)

	return mapBackendService.Delete(buff)
}

// gets service info
func bpfGetServiceInfo(namespaceName string) (*trackedService, error) {
	mapServiceNameKey, err := bpfGetMap(map_path_service_name_key)
	if err != nil {
		return nil, err
	}

	mapServices, err := bpfGetMap(map_path_services)
	if err != nil {
		return nil, err
	}

	bpfServiceIdAsBytes, err := mapServiceNameKey.Lookup(namespaceName)
	if err != nil {
		return nil, err
	}

	bpfServiceId := *(*uint64)(unsafe.Pointer(&bpfServiceIdAsBytes[0]))

	serviceAsBytes, err := mapServices.Lookup(bpfServiceId)
	if err != nil {
		return nil, err
	}

	bpfService := (*C.struct_kbpf_service)(unsafe.Pointer(&serviceAsBytes[0]))

	return &trackedService{
		namespaceName:  namespaceName,
		bpfId:          bpfServiceId,
		affinitySec:    uint16(bpfService.has_affinity),
		totalEndpoints: uint16(bpfService.has_affinity),
	}, nil
}

// updates service affinity
func bpfUpdateServiceAffinity(tracked *trackedService, newAffinity uint16) error {
	if tracked.affinitySec == newAffinity {
		return nil
	}

	if tracked.totalEndpoints == 0 {
		saved, err := bpfGetServiceInfo(tracked.namespaceName)
		if err != nil {
			return err
		}

		tracked.totalEndpoints = saved.totalEndpoints
	}

	return bpfInsertOrUpdateServiceInfo(tracked)
}

// inserts service info
func bpfInsertOrUpdateServiceInfo(tracked *trackedService) error {
	mapServiceNameKey, err := bpfGetMap(map_path_service_name_key)
	if err != nil {
		return err
	}

	mapServices, err := bpfGetMap(map_path_services)
	if err != nil {
		return err
	}

	err = mapServiceNameKey.Upsert(tracked.namespaceName, tracked.bpfId)
	if err != nil {
		return err
	}

	bpfService := C.struct_kbpf_service{
		key:             C.ulong(tracked.bpfId),
		total_endpoints: C.ushort(tracked.totalEndpoints),
		has_affinity:    C.ushort(tracked.affinitySec),
	}

	// if we go beyond 512 goebpf pkg will catch it
	// we have to test on creation of tracked service
	buff := make([]byte, len(tracked.namespaceName), len(tracked.namespaceName))
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&tracked.namespaceName), C.ulong(len(tracked.namespaceName)))

	err = mapServiceNameKey.Upsert(buff, tracked.bpfId)
	if err != nil {
		return err
	}

	buff = make([]byte, C.sizeof_struct_kbpf_service, C.sizeof_struct_kbpf_service)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&bpfService), C.sizeof_struct_kbpf_service)

	return mapServices.Upsert(tracked.bpfId, buff)
}

func bpfInsertOrUpdateServiceIP(bpfId uint64, ip net.IP) error {
	mapServiceIPs, err := bpfGetMap(map_path_service_ips_to_service)
	if err != nil {
		return err
	}

	kbpfIP := *(ipToKbpfIP(ip))
	buff := make([]byte, C.sizeof_struct_kbpf_ip, C.sizeof_struct_kbpf_ip)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&kbpfIP), C.sizeof_struct_kbpf_ip)
	return mapServiceIPs.Upsert(buff, bpfId)
}

func bpfGetServiceIPs(bpfId uint64) ([]net.IP, error) {
	all := make([]net.IP, 0)
	mapServiceIPs, err := bpfGetMap(map_path_service_ips_to_service)
	if err != nil {
		return nil, err
	}

	buff := make([]byte, C.sizeof_struct_kbpf_ip, C.sizeof_struct_kbpf_ip)
	C.memset(unsafe.Pointer(&buff[0]), 0, C.sizeof_struct_kbpf_port_key)

	for {
		buff, err = mapServiceIPs.GetNextKey(buff)
		if err != nil {
			return all, nil // error is returned when last key is read. // TODO find a better way
		}
		if len(buff) == 0 {
			return all, nil
		}
		buffBpfId, err := mapServiceIPs.Lookup(buff)
		if err != nil {
			return nil, err
		}

		savedBpfId := *(*uint64)(unsafe.Pointer(&buffBpfId[0]))

		if savedBpfId == bpfId {
			thisKey := *(*C.struct_kbpf_ip)(unsafe.Pointer(&buff[0]))
			all = append(all, kbpfIPToIP(&thisKey))
		}
	}

	return all, nil
}

func bpfDeleteServiceIP(bpfId uint64, ip net.IP) error {
	mapServiceIPs, err := bpfGetMap(map_path_service_ips_to_service)
	if err != nil {
		return err
	}

	kbpfIP := *(ipToKbpfIP(ip))
	buff := make([]byte, C.sizeof_struct_kbpf_ip, C.sizeof_struct_kbpf_ip)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&kbpfIP), C.sizeof_struct_kbpf_ip)

	return mapServiceIPs.Delete(buff)
}

func bpfGetServiceToBackendPort(bpfId uint64, l4_proto uint8, servicePort uint16) (uint16, error) {
	return bpfGetPortFromPortMap(map_path_service_port_to_backend_port, bpfId, l4_proto, servicePort)
}

func bpfInsertOrUpdateServiceToBackendPort(bpfId uint64, l4_proto uint8, servicePort uint16, backendPort uint16) error {
	return bpfInsertOrUpdatePortInPortMap(map_path_service_port_to_backend_port, bpfId, l4_proto, servicePort, backendPort)
}

func bpfGetServiceToBackendPorts(bpfId uint64) (map[uint8]map[uint16]uint16, error) {
	return bpfGetPortsFromPortMap(map_path_service_port_to_backend_port, bpfId)
}

func bpfDeleteServiceToBackendPort(bpfId uint64, l4_proto uint8, servicePort uint16) error {
	return bpfDeletePortFromPortMap(map_path_service_port_to_backend_port, bpfId, l4_proto, servicePort)
}

func bpfGetBackendToServicePort(bpfId uint64, l4_proto uint8, backendPort uint16) (uint16, error) {
	return bpfGetPortFromPortMap(map_path_backend_port_to_service_port, bpfId, l4_proto, backendPort)
}

func bpfInsertOrUpdateBackendToServicePort(bpfId uint64, l4_proto uint8, backendPort uint16, servicePort uint16) error {
	return bpfInsertOrUpdatePortInPortMap(map_path_backend_port_to_service_port, bpfId, l4_proto, backendPort, servicePort)
}

func bpfGetBackEndToServicePorts(bpfId uint64) (map[uint8]map[uint16]uint16, error) {
	return bpfGetPortsFromPortMap(map_path_backend_port_to_service_port, bpfId)
}

func bpfDeleteBackendToServicePort(bpfId uint64, l4_proto uint8, backendPort uint16) error {
	return bpfDeletePortFromPortMap(map_path_backend_port_to_service_port, bpfId, l4_proto, backendPort)
}

func bpfGetPortFromPortMap(mapPath string, bpfId uint64, l4_proto uint8, fromPort uint16) (uint16, error) {
	thisMap, err := bpfGetMap(mapPath)
	if err != nil {
		return 0, err
	}

	bpfServicePort := C.struct_kbpf_port_key{
		key:      C.ulong(bpfId),
		port:     C.htons(C.ushort(fromPort)),
		l4_proto: C.uchar(C.htons(C.ushort(l4_proto)) >> 8),
	}

	buff := make([]byte, C.sizeof_struct_kbpf_port_key, C.sizeof_struct_kbpf_port_key)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&bpfServicePort), C.sizeof_struct_kbpf_port_key)

	toPort, err := thisMap.Lookup(buff)
	if err != nil {
		return 0, err
	}

	port := *(*uint16)(unsafe.Pointer(&toPort[0]))
	return uint16(C.ntohs(C.ushort(port))), nil
}

func bpfInsertOrUpdatePortInPortMap(mapPath string, bpfId uint64, l4_proto uint8, fromPort uint16, toPort uint16) error {
	thisMap, err := bpfGetMap(mapPath)
	if err != nil {
		return err
	}
	bpfServicePort := C.struct_kbpf_port_key{
		key:      C.ulong(bpfId),
		port:     C.htons(C.ushort(fromPort)),
		l4_proto: (C.uchar)(C.htons(C.ushort(l4_proto)) >> 8),
	}

	buff := make([]byte, C.sizeof_struct_kbpf_port_key, C.sizeof_struct_kbpf_port_key)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&bpfServicePort), C.sizeof_struct_kbpf_port_key)

	return thisMap.Upsert(buff, (uint16)(C.htons(C.ushort(toPort))))
}

// returns ports by proto
func bpfGetPortsFromPortMap(mapPath string, bpfId uint64) (map[uint8]map[uint16]uint16, error) {
	all := make(map[uint8]map[uint16]uint16)
	thisMap, err := bpfGetMap(mapPath)
	if err != nil {
		return nil, err
	}

	bpfServicePort := C.struct_kbpf_port_key{}
	buff := make([]byte, C.sizeof_struct_kbpf_port_key, C.sizeof_struct_kbpf_port_key)
	C.memset(unsafe.Pointer(&buff[0]), 0, C.sizeof_struct_kbpf_port_key)

	for {
		buff, err = thisMap.GetNextKey(buff)
		if err != nil {
			return all, nil // error is returned when last key is read. // TODO find a better way
		}
		if len(buff) == 0 {
			return all, nil
		}

		buffToPort, err := thisMap.Lookup(buff)
		if err != nil {
			return nil, err
		}

		bpfServicePort = *(*C.struct_kbpf_port_key)(unsafe.Pointer(&buff[0]))

		if uint64(bpfServicePort.key) == bpfId {
			proto := uint8(C.ntohs(C.ushort(bpfServicePort.l4_proto) << 8))
			toPort := *(*C.ushort)(unsafe.Pointer(&buffToPort[0]))

			if _, ok := all[proto]; !ok {
				all[proto] = make(map[uint16]uint16)
			}

			byProtoMap := all[proto]
			byProtoMap[uint16(C.ntohs(bpfServicePort.port))] = uint16(C.ntohs(toPort))
		}
	}

	return all, nil
}

func bpfDeletePortFromPortMap(mapPath string, bpfId uint64, l4_proto uint8, fromPort uint16) error {
	thisMap, err := bpfGetMap(mapPath)
	if err != nil {
		return err
	}
	bpfServicePort := C.struct_kbpf_port_key{
		key:      C.ulong(bpfId),
		port:     C.htons(C.ushort(fromPort)),
		l4_proto: C.uchar(C.htons(C.ushort(l4_proto)) >> 8),
	}

	buff := make([]byte, C.sizeof_struct_kbpf_port_key, C.sizeof_struct_kbpf_port_key)
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&bpfServicePort), C.sizeof_struct_kbpf_port_key)

	return thisMap.Delete(buff)
}

// converts an ip to ip struct used in various bpf maps
func ipToKbpfIP(from net.IP) *C.struct_kbpf_ip {
	kbpfIP := C.struct_kbpf_ip{}

	if isIPv6(from) {
		kbpfIP.l2_proto = C.ETH_PROTO_IPV6

		// hton every int
		for i := 0; i < 4; i++ {
			htoned := C.htonl(*(*C.uint)(unsafe.Pointer(&from[i*4])))
			C.memcpy(unsafe.Pointer(&kbpfIP.ip[i]), unsafe.Pointer(&htoned), 4)
		}
		return &kbpfIP
	}

	kbpfIP.l2_proto = C.ETH_PROTO_IP
	// process as ipv4
	asIPv4 := from.To4() //https://golang.org/src/net/ip.go?s=5275:5296#L189
	ipv4 := *(*uint32)(unsafe.Pointer(&asIPv4[0]))
	ipv4n := C.htonl((C.uint)(ipv4))
	kbpfIP.ip[0] = ipv4n

	return &kbpfIP
}

// the inverse of ipToKbpfIP
func kbpfIPToIP(from *C.struct_kbpf_ip) net.IP {
	var ip net.IP
	if from.l2_proto == C.ETH_PROTO_IPV6 {
		ip = net.ParseIP("::1") // just to allocate it
		for i := 0; i < 4; i++ {
			// ntoh in place
			from.ip[i] = C.ntohl(from.ip[i])
		}

		C.memcpy(unsafe.Pointer(&ip[0]), unsafe.Pointer(&from.ip), 16)
		return ip
	}

	// process as ipv4
	ipv4 := *(*C.uint)(unsafe.Pointer(&from.ip))
	ipv4 = C.ntohl(ipv4)
	ip = make(net.IP, 4)
	ip[0] = byte(ipv4)
	ip[1] = byte(ipv4 >> 8)
	ip[2] = byte(ipv4 >> 16)
	ip[3] = byte(ipv4 >> 24)

	return ip
}
func isIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil
}

//TODO
// Service backends
// flows and affinities
