package controller

/*
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t  kbpf_service_key;
typedef char kbpf_service_name[512];



struct kbpf_service {
		kbpf_service_key key;
    // total # of pods (IMPORTANT: count of pods, not count IPs of pods)
    uint16_t total_endpoints;
    // service has affinity or not
    uint16_t has_affinity;
};


*/
import "C"

import (
	// 	"net"
	"sync"
	"unsafe"

	"encoding/binary"

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

var bpfMaps map[string]*goebpf.EbpfMap
var bpfMapMu sync.Mutex

// funcs that are named Bpf* manages the data saved in bpf maps
// on kernel side.

func bpfCloseAllMaps() {
	// TODO
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

// gets service info
func bpfGetServiceInfo(namespaceName string) (*trackedService, error) {
	// first get the key
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

	bpfServiceId := binary.LittleEndian.Uint64(bpfServiceIdAsBytes)

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
	C.memcpy(unsafe.Pointer(&buff[0]), unsafe.Pointer(&bpfService), C.ulong(cap(buff)))

	return mapServices.Upsert(tracked.bpfId, buff)
}

/*

func bpfGetServiceToEndPorts(tracked *trackedService) (map[uint16]uint16, error) {
	// TODO
	return nil, nil
}

func bpfGetEndPointToServicePorts(tracked *trackedService) (map[uint16]uint16, error) {
	// TODO
	return nil, nil
}

func bpfAddOrUpdateServiceToEndpointPort(tracked *trackedService, from uint16, to uint16) error {
	// TODO
	return nil
}

func bpfAddOrUpdateEndpointToServicePort(tracked *trackedService, from uint16, to uint16) error {
	// TODO
	return nil
}

// Service IPs
func bpfGetServiceIPs(tracked *trackedService) ([]net.IP, error) {
	//TODO
	return nil, nil
}

// inserts or updates an ip for a service
func bpfAddOrUpdateServiceIP(tracked *trackedService, ip net.IP) error {
	//TODO
	return nil
}

func bpfDeleteServiceIP(tracked *trackedService, ip net.IP) error {
	//TODO
	return nil
}
*/
