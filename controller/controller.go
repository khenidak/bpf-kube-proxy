package controller

import (
	"hash/fnv"
	"math/rand"
	"sync"

	"time"
	// "fmt"
	// "net"
)

type trackedService struct {
	mu             sync.Mutex
	bpfId          uint64 // bpf operates on a smaller id not name, to avoid bigger stack
	namespaceName  string
	totalEndpoints uint16
	affinitySec    uint16
}
type ctrl struct {
	servicesMu sync.Mutex
	services   map[string]*trackedService
}

func (c *ctrl) TrackService(namespaceName string, affinitySec uint16) error {
	c.servicesMu.Lock()
	defer c.servicesMu.Unlock()

	// we have it.
	if tracked, ok := c.services[namespaceName]; ok {
		// update affinity
		bpfUpdateServiceAffinity(tracked, affinitySec)
		return nil
	}

	// we don't have this service
	// option 1: we have been restarted and data is inside a bpf map
	// but not in the controller's memory
	// try to get it
	tracked, err := bpfGetServiceInfo(namespaceName)
	if err != nil {
		return err
	}
	// service was found
	if tracked != nil {
		c.services[namespaceName] = tracked
		return nil
	}
	// option 2: this is an entirly new service
	// bpfid is 64bit of (hash(namespaceName)-random)
	hashed := hashServiceName(namespaceName)
	random := getRandomValue()
	bpfId := uint64(hashed) | (uint64(random) << 32)

	tracked = &trackedService{
		bpfId:       bpfId,
		affinitySec: affinitySec,
	}

	// insert it
	if err := bpfInsertOrUpdateServiceInfo(tracked); err != nil {
		return err
	}

	// keep it
	c.services[namespaceName] = tracked

	return nil
}

/*
// SyncServiceIPs synchronizes the list of ips {clusterIPs, externalIPs, LB IPs}
// that this service listens
func (c *ctrl) SyncServiceIPs(namespaceName string, ips []string) error {
	tracked := c.getServiceInfo(namespaceName)
	if tracked == nil {
		return fmt.Errorf("service %v is not tracked", namespaceName)
	}

	tracked.mu.Lock()
	defer tracked.mu.Unlock()

	ipsAsMap := stringSliceToMap(ips)
	errors := make([]error, 0)

	currentIPs, err := bpfGetServiceIPs(tracked)
	if err != nil {
		return err
	}

	for _, currentIP := range currentIPs {
		_, ok := ipsAsMap[currentIP.String()]
		if !ok {
			// delete it
		}
		delete(ipsAsMap, currentIP)
	}

	// the remaining are new IPs we need to add
	for ip, _ := range ipsAsMap {
		parsed := net.ParseIP(ip)
			if parsed == nil {
				errors = append(errors, fmt.Errorf("error adding %v: failed to parse", ip))
				continue
			}
		err := bpfAddOrUpdateServiceIP(tracked, &parsed)
		if err != nil {
			errors = append(errors, fmt.Errorf("error adding %v: %v", ip, err))
			continue
		}
	}
}

// SyncServicePorts maps service port to an endpoint port
func (c *ctrl) SyncServicePorts(namespaceName string, ports map[uint16]uint16) error {
	tracked := c.getServiceInfo(namespaceName)
	if tracked == nil {
		return fmt.Errorf("service %v is not tracked", namespaceName)
	}

	tracked.mu.Lock()
	defer tracked.mu.Unlock()

	serviceToEndPointPorts, err := bpfGetEndPointToServicePorts(tracked)
	if err != nil {
		return err
	}

	endpointToServicePorts, err := bpfGetEndPointToServicePorts(tracked)
	if err != nil {
		return
	}

	// both need to be synchronized before we can go ahead and sync them
	// with new ports. we consider service->endpoint port mapping as
	// authoritative

	errors := make([]error, 0)
	for servicePort, endPointPort := range serviceToEndPointPorts {
		hasEndpointPort, ok := endpointToServicePorts[endPointPort]
		if !ok || hasEndpointPort != endPointPort {
			// service->endpoint exist but not the other way. add it
			err := bpfAddOrUpdateEndpointToServicePort(trackedService, endPointPort, servicePort)
			if err != nil {
				errors = append(errors, err)
			}
			endpointToServicePorts[endPointPort] = servicePort
		}
	}
 ...
}
*/
func (c *ctrl) getServiceInfo(namespaceName string) *trackedService {
	c.servicesMu.Lock()
	defer c.servicesMu.Unlock()
	tracked, ok := c.services[namespaceName]
	if !ok {
		return nil
	}
	return tracked
}

// returns all IPs for a service
func hashServiceName(namespaceName string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(namespaceName))
	return h.Sum32()
}

func getRandomValue() uint32 {
	rand.Seed(time.Now().UnixNano())
	return rand.Uint32()
}

func stringSliceToMap(list []string) map[string]struct{} {
	asMap := make(map[string]struct{})
	for _, val := range list {
		asMap[val] = struct{}{}
	}
	return asMap
}
