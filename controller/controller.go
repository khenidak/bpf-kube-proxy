package controller

import (
	"hash/fnv"
	"math/rand"
	"net"
	"sync"
	"time"
)

const min_flow_expiration_sec = 5
const max_flow_expiration_sec = 20
const default_flow_expiration_sec = 7

type trackedService struct {
	mu             sync.Mutex
	bpfId          uint64 // bpf operates on a smaller id not name, to avoid bigger stack
	namespaceName  string
	totalEndpoints uint16
	affinitySec    uint16
}
type ctrl struct {
	servicesMu            sync.Mutex
	services              map[string]*trackedService
	flowExpireDurationSec uint8
	logWrite              func(format string, a ...interface{})
}

func NewController(logWriter func(format string, a ...interface{}), flowExpireDurationSec uint8) (Controller, error) {
	c := &ctrl{}

	// set flow expiration
	if flowExpireDurationSec > max_flow_expiration_sec ||
		flowExpireDurationSec < max_flow_expiration_sec {
		flowExpireDurationSec = default_flow_expiration_sec
	}

	// note:
	// for affinity we delete them iif
	// affinity expired (per service)
	// service removed
	c.services = make(map[string]*trackedService)
	c.logWrite = logWriter
	c.flowExpireDurationSec = flowExpireDurationSec
	err := c.buildInternalData()
	if err != nil {
		return nil, err
	}

	// TODO: start affinity and flows loops
	return c, nil
}

// data in maps can go slightly out of drift
// entries that no longer valid due to failed partial delete or insert
// this func make sure that the data in all maps are linked correctly
// to source of truth (name/key map)
func (c *ctrl) buildInternalData() error {
	c.logWrite("begin internal data sync")
	defer c.logWrite("end internal data sync")

	c.servicesMu.Lock()
	defer c.servicesMu.Unlock()

	allNameKeys, err := bpfGetAllServiceNameKey()
	if err != nil {
		return err
	}

	allServiceInfos, err := bpfGetAllServiceInfos()
	if err != nil {
		return err
	}

	// create a clean list of all name/keys
	// that map to infos. for orphan infos.. delete them
	for bpfId, tracked := range allServiceInfos {
		// because nameKeys is keyed using name, we will have to do it
		// this way
		for name, key := range allNameKeys {
			if key == bpfId {
				// set the name
				tracked.namespaceName = name
			}
		}
		if tracked.namespaceName == "" {
			err := bpfDeleteServiceInfo(bpfId)
			if err != nil {
				return err
			}
			continue
		}
		// servic has key and name.. keep
		c.services[tracked.namespaceName] = tracked
	}

	// TODO this can run concurrently

	// remove the rest of orphans
	// *always* remove serviceIPs first, because it is the very
	// first thing egress data path look at
	if err := c.removeOrphanedServiceIPs(); err != nil {
		return err
	}

	if err := c.removeOrphanedBackends(); err != nil {
		return err
	}

	if err := c.removeOrphanedIndexedBackend(); err != nil {
		return err
	}

	if err := c.removeOrphanedFlows(); err != nil {
		return err
	}

	if err := c.removeOrphanedAffinities(); err != nil {
		return err
	}

	if err := c.removeOrphanedPorts(); err != nil {
		return err
	}

	// TODO: loader
	// TODO: flows and affinities sync loops
	return nil
}

func (c *ctrl) removeOrphanedIndexedBackend() error {
	allIndexedBackends, err := bpfGetAllServiceToBackendIndxed()
	if err != nil {
		return err
	}

	for bpfId, ipIndex := range allIndexedBackends {
		if c.hasTrackedServiceByBpfId(bpfId) {
			continue
		}

		for ip, index := range ipIndex {
			err := bpfDeleteServiceToBackendIndexed(bpfId, index, net.ParseIP(ip))
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *ctrl) removeOrphanedPorts() error {
	servicePorts, err := bpfGetAllServiceToBackendPorts()
	if err != nil {
		return err
	}
	backendPorts, err := bpfGetAllBackEndToServicePorts()
	if err != nil {
		return err
	}
	// service => backend ports
	for bpfId, byProto := range servicePorts {
		if c.hasTrackedServiceByBpfId(bpfId) {
			continue
		}
		for proto, fromTo := range byProto {
			for from, _ := range fromTo {
				err := bpfDeleteServiceToBackendPort(bpfId, proto, from)
				if err != nil {
					return err
				}
			}
		}
	}

	for bpfId, byProto := range backendPorts {
		if c.hasTrackedServiceByBpfId(bpfId) {
			continue
		}
		for proto, fromTo := range byProto {
			for from, _ := range fromTo {
				err := bpfDeleteBackendToServicePort(bpfId, proto, from)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
func (c *ctrl) removeOrphanedBackends() error {
	allBackends, err := bpfGetAllBackendsToService()
	if err != nil {
		return nil
	}

	for bpfId, backends := range allBackends {
		if !c.hasTrackedServiceByBpfId(bpfId) {
			for _, backend := range backends {
				err := bpfDeleteBackendToService(bpfId, backend)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *ctrl) removeOrphanedServiceIPs() error {
	// remove orphan flows
	allServiceIPs, err := bpfGetAllServiceIPs()
	if err != nil {
		return err
	}

	for bpfId, serviceIPs := range allServiceIPs {
		if !c.hasTrackedServiceByBpfId(bpfId) {
			for _, serviceIP := range serviceIPs {
				err := bpfDeleteServiceIP(bpfId, serviceIP)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *ctrl) removeOrphanedFlows() error {
	// remove orphan flows
	allFlows, err := bpfGetAllFlows()
	if err != nil {
		return err
	}

	for bpfId, flows := range allFlows {
		if !c.hasTrackedServiceByBpfId(bpfId) {
			for _, flow := range flows {
				err := bpfDeleteFlow(bpfId, flow.srcIP, flow.srcPort, flow.l4_proto)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *ctrl) removeOrphanedAffinities() error {
	// remove orphan flows
	allAff, err := bpfGetAllAffinities()
	if err != nil {
		return err
	}

	for bpfId, affs := range allAff {
		if !c.hasTrackedServiceByBpfId(bpfId) {
			for _, aff := range affs {
				err := bpfDeleteAffinity(bpfId, aff.clientIP)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *ctrl) hasTrackedServiceByBpfId(bpfId uint64) bool {
	return (c.getTrackedServiceByBpfId(bpfId) != nil)
}
func (c *ctrl) getTrackedServiceByBpfId(bpfId uint64) *trackedService {
	for _, tracked := range c.services {
		if tracked.bpfId == bpfId {
			return tracked
		}
	}
	return nil
}

/*
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
*/
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
