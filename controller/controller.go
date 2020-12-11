package controller

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// proto
const IPPROTO_TCP = 6
const IPPROTO_UDP = 17
const IPPROTO_SCTP = 132

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
	servicesMu sync.Mutex
	// the following two maps index services using two different keys
	services              map[string]*trackedService
	servicesByBpfId       map[uint64]*trackedService
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
	c.servicesByBpfId = make(map[uint64]*trackedService)

	c.logWrite = logWriter
	c.flowExpireDurationSec = flowExpireDurationSec
	err := c.buildInternalData(true)
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
func (c *ctrl) buildInternalData(buildKeyNameList bool) error {
	c.logWrite("begin internal data sync")
	defer c.logWrite("end internal data sync")

	c.servicesMu.Lock()
	defer c.servicesMu.Unlock()
	if buildKeyNameList {
		allNameKeys, err := bpfGetAllServiceNameKey()
		if err != nil {
			return err
		}

		allServiceInfos, err := bpfGetAllServiceInfos()
		if err != nil {
			return err
		}

		// create a clean list of all name/keys
		// that map to infos. any map data that does not cleanly
		// map to a service we know of (in name/key) we orphan and remove
		// them
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
			c.servicesByBpfId[bpfId] = tracked
		}
	}

	// TODO this can run concurrently
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

// used only for test
func (c *ctrl) GetServiceBpfId(namespaceName string) uint64 {
	tracked := c.getTrackedServiceByName(namespaceName)
	if tracked == nil {
		return 0
	}

	tracked.mu.Lock()
	defer tracked.mu.Unlock()
	return tracked.bpfId

}
func (c *ctrl) AddService(namespaceName string, affinitySec uint16) error {
	c.servicesMu.Lock()
	defer c.servicesMu.Unlock()

	if len(namespaceName) > kbpf_service_name_length {
		return fmt.Errorf("service %v has a name longer than %v", namespaceName, kbpf_service_name_length)
	}

	if current, ok := c.services[namespaceName]; ok {
		if current.affinitySec != affinitySec {
			return c.UpdateService(namespaceName, affinitySec)
		}
		return nil // service exist
	}

	// create new bpf id for this service
	hashed := hashServiceName(namespaceName)
	random := getRandomValue()
	bpfId := uint64(hashed) | (uint64(random) << 32)

	c.logWrite("service %v now has bpfId of %v", namespaceName, bpfId)

	tracked := &trackedService{
		namespaceName: namespaceName,
		bpfId:         bpfId,
		affinitySec:   affinitySec,
	}

	if err := bpfInsertOrUpdateServiceInfo(tracked); err != nil {
		return err
	}

	// lock the service
	tracked.mu.Lock()
	defer tracked.mu.Unlock()

	c.services[namespaceName] = tracked
	c.servicesByBpfId[bpfId] = tracked

	return nil
}

func (c *ctrl) UpdateService(namespaceName string, affinitySec uint16) error {
	var tracked *trackedService
	// if not there, add it.
	if tracked = c.getTrackedServiceByName(namespaceName); tracked == nil {
		return c.AddService(namespaceName, affinitySec)
	}
	// service exist.
	if tracked.affinitySec == affinitySec {
		return nil // noting to update
	}

	// lock this service
	tracked.mu.Lock()
	defer tracked.mu.Unlock()
	// get current total endpoints

	saved, err := bpfGetServiceInfo(tracked.bpfId)
	if err != nil {
		return err
	}
	// must get current total endpoints
	tracked.totalEndpoints = saved.totalEndpoints
	tracked.affinitySec = affinitySec

	// now update it
	return bpfInsertOrUpdateServiceInfo(tracked)
}

func (c *ctrl) GetServices() map[string]uint16 {
	c.servicesMu.Lock()
	defer c.servicesMu.Unlock()
	all := make(map[string]uint16)
	for _, tracked := range c.services {
		all[tracked.namespaceName] = tracked.affinitySec
	}

	return all
}

func (c *ctrl) DeleteService(namespaceName string) error {
	deletefn := func() (*trackedService, error) {
		c.servicesMu.Lock()
		defer c.servicesMu.Unlock()
		tracked := c.services[namespaceName]
		if tracked != nil {
			err := bpfDeleteServiceInfo(tracked.bpfId)
			if err != nil {
				return nil, err
			}
			err = bpfDeleteServiceNameKey(tracked.namespaceName)
			if err != nil {
				return nil, err
			}
			delete(c.services, namespaceName)
			delete(c.servicesByBpfId, tracked.bpfId)
		}
		return tracked, nil
	}

	t, err := deletefn()
	if err != nil {
		return err
	}

	// service was deleted perform clean up
	if t != nil {
		return c.buildInternalData(false)
	}
	return nil
}

// syncs service backends. Max expected IPs per end point is 2 (two families)
func (c *ctrl) SyncServiceBackends(namespaceName string, backends map[string][]string) []error {
	tracked := c.getTrackedServiceByName(namespaceName)
	if tracked != nil {
		return []error{fmt.Errorf("service %v is not tracked", namespaceName)}
	}

	//******************************
	// TODO
	// we can do a lot better by creating lists of
	// modified, deleted, added similar to other map data
	// and that will take a bit of work. For now we will go with
	// delete all / add new
	//******************************
	// lock that service
	tracked.mu.Lock()
	defer tracked.mu.Unlock()
	errs := make([]error, 0)

	// create new list of with new indexes
	addBackends := make(map[uint64][]net.IP)
	count := uint64(0)
	for name, backendIPs := range backends {
		if len(backendIPs) > 2 {
			return []error{fmt.Errorf("backend %v has more than two ips%+v", name, backendIPs)} // TODO we should also check for dualstackness here
		}

		parsedIPs := make([]net.IP, 0)
		for _, ip := range backendIPs {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				return []error{fmt.Errorf("backend %v has an invalid ip %v", name, ip)}
			}
			parsedIPs = append(parsedIPs, parsedIP)
		}
		addBackends[count] = parsedIPs
		count++
	}

	// get current backends
	currentIndexedBackends, err := bpfGetServiceToBackendIndxed(tracked.bpfId)
	if err != nil {
		return []error{err} // can not do anything if we fail here
	}

	// delete current from indexed backends and backend->service map
	for ip, index := range currentIndexedBackends {
		parsedIP := net.ParseIP(ip)
		err := bpfDeleteServiceToBackendIndexed(tracked.bpfId, index, parsedIP)
		if err != nil {
			errs = append(errs, err)
		}
		err = bpfDeleteBackendToService(tracked.bpfId, parsedIP)
		if err != nil {
			errs = append(errs, err)
		}

		// TODO this make this better by having c.deleteFlowsAffinitiesForBackend(tracked, ***[]***parsedIP)
		// instead of looping for every ip, we do it all at once
		// **BUT** this needs to be done with the TODO above
		errsAffFlow := c.deleteFlowsAffinitiesForBackend(tracked, parsedIP)
		if len(errsAffFlow) > 0 {
			errs = append(errs, errsAffFlow...)
		}
	}

	if len(errs) > 0 {
		return errs
	}

	// add new
	for index, parsedIPs := range addBackends {
		for _, parsedIP := range parsedIPs {
			err := bpfInsertOrUpdateServiceToBackendIndexed(tracked.bpfId, index, parsedIP)
			if err != nil {
				errs = append(errs, err)
			}
			err = bpfInsertOrUpdateBackendToService(tracked.bpfId, parsedIP)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	// update total endpoints
	if tracked.totalEndpoints != uint16(len(backends)) {
		tracked.totalEndpoints = uint16(len(backends))
		err := bpfInsertOrUpdateServiceInfo(tracked)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func (c *ctrl) deleteFlowsAffinitiesForBackend(tracked *trackedService, ip net.IP) []error {
	errs := make([]error, 0)

	affs, err := bpfGetAffinityForService(tracked.bpfId)
	if err != nil {
		errs = append(errs, err)
	}

	flows, err := bpfGetFlowsForService(tracked.bpfId)
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errs
	}

	for _, f := range flows {
		if f.destIP.String() == ip.String() {
			err := bpfDeleteFlow(tracked.bpfId, ip, f.srcPort, f.l4_proto)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	for _, a := range affs {
		if a.destIP.String() == ip.String() {
			err := bpfDeleteAffinity(tracked.bpfId, a.clientIP)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}

func (c *ctrl) SyncServiceIPs(namespaceName string, ips []string) []error {
	tracked := c.getTrackedServiceByName(namespaceName)
	if tracked == nil {
		return []error{fmt.Errorf("service %v is not tracked", namespaceName)}
	}

	// local that service
	tracked.mu.Lock()
	defer tracked.mu.Unlock()

	ipsToAdd := make([]net.IP, 0)
	ipsToDelete := make([]net.IP, 0)
	errs := make([]error, 0)

	currentIPs, err := bpfGetServiceIPs(tracked.bpfId)
	if err != nil {
		return []error{err}
	}

	// ips to add
	for _, ip := range ips {
		found := false
		for _, currentIP := range currentIPs {
			if currentIP.String() == ip {
				found = true
				break
			}
		}
		if !found {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				return []error{fmt.Errorf("ip %v is invalid", ip)}
			}
			ipsToAdd = append(ipsToAdd, parsedIP)
		}
	}

	// ips to delete
	for _, currentIP := range currentIPs {
		found := false
		for _, ip := range ips {
			if currentIP.String() == ip {
				found = true
				break
			}
		}
		if !found {
			ipsToDelete = append(ipsToDelete, currentIP)
		}
	}

	// perform add first. if we failed to delete
	// worest case scenario it will be an IP that no body use
	// and will get updated to point to a different service when allocated
	for _, ipToAdd := range ipsToAdd {
		err := bpfInsertOrUpdateServiceIP(tracked.bpfId, ipToAdd)
		if err != nil {
			errs = append(errs, fmt.Errorf("%v: failed to add ip %v with err:%v", namespaceName, ipToAdd.String(), err))
		}
	}

	for _, ipToDelete := range ipsToDelete {
		err := bpfDeleteServiceIP(tracked.bpfId, ipToDelete)
		if err != nil {
			errs = append(errs, fmt.Errorf("%v:failed to delete ip %v with err:%v", namespaceName, ipToDelete.String(), err))
		}
	}
	return errs
}

// syncs service ports using a map of proto=>from:to
func (c *ctrl) SyncServicePorts(namespaceName string, ports map[string]map[uint16]uint16) []error {
	tracked := c.getTrackedServiceByName(namespaceName)
	if tracked == nil {
		return []error{fmt.Errorf("service %v is not tracked", namespaceName)}
	}

	// local that service
	tracked.mu.Lock()
	defer tracked.mu.Unlock()

	portsToAdd := make(map[uint8]map[uint16]uint16)
	portsToDelete := make(map[uint8]map[uint16]uint16)
	errs := make([]error, 0)
	// we use service->backend as source of truth and we sync all to it
	currentServiceToBackendPorts, err := bpfGetServiceToBackendPorts(tracked.bpfId)
	if err != nil {
		return []error{err}
	}

	// process ports to add
	for proto, byProto := range ports {
		nProto, err := protoNumber(proto)
		if err != nil {
			return []error{err}
		}
		if _, ok := portsToAdd[nProto]; !ok {
			portsToAdd[nProto] = make(map[uint16]uint16)
		}

		addByProto := portsToAdd[nProto]
		for from, to := range byProto {
			if currentTo, ok := currentServiceToBackendPorts[nProto][from]; !ok || to != currentTo {
				addByProto[from] = to
			}
		}
	}

	// process ports to delete
	for nProto, byProto := range currentServiceToBackendPorts {
		sProto := protoString(nProto)
		if _, ok := portsToDelete[nProto]; !ok {
			portsToDelete[nProto] = make(map[uint16]uint16)
		}
		for from, to := range byProto {
			if _, ok := ports[sProto][from]; !ok {
				portsToDelete[nProto][from] = to
			}
		}
	}

	// add ports
	for nProto, byProto := range portsToAdd {
		sProto := protoString(nProto)
		for from, to := range byProto {
			// add it to service->backend
			err := bpfInsertOrUpdateServiceToBackendPort(tracked.bpfId, nProto, from, to)
			if err != nil {
				errs = append(errs, fmt.Errorf("%v:failed to add service->backend port[%v]%v:%v err:%v", namespaceName, sProto, from, to, err))
			}
			// add it to backend->service
			err = bpfInsertOrUpdateBackendToServicePort(tracked.bpfId, nProto, to, from)
			if err != nil {
				errs = append(errs, fmt.Errorf("%v:failed to add backend->service port[%v]%v:%v err:%v", namespaceName, sProto, to, from, err))
			}
		}
	}

	// delete ports
	for nProto, byProto := range portsToDelete {
		sProto := protoString(nProto)
		for from, to := range byProto {
			// add it to service->backend
			err := bpfDeleteServiceToBackendPort(tracked.bpfId, nProto, from)
			if err != nil {
				errs = append(errs, fmt.Errorf("%v:failed to delete service->backend port[%v]%v:%v err:%v", namespaceName, sProto, from, to, err))
			}
			// add it to backend->service
			err = bpfDeleteBackendToServicePort(tracked.bpfId, nProto, to)
			if err != nil {
				errs = append(errs, fmt.Errorf("%v:failed to delete backend->service port[%v]%v:%v err:%v", namespaceName, sProto, to, from, err))
			}
		}
	}

	// if we have errors so far. then there is no point to sync
	if len(errs) > 0 {
		return errs
	}
	// we use service->backend as source of truth and we sync all to it
	// make sure that they are pointing at the same thing
	currentServiceToBackendPorts, err = bpfGetServiceToBackendPorts(tracked.bpfId)
	if err != nil {
		return []error{err}
	}
	currentBackendToServicePorts, err := bpfGetBackEndToServicePorts(tracked.bpfId)
	if err != nil {
		return []error{err}
	}

	for nProto, byProto := range currentServiceToBackendPorts {
		if _, ok := currentBackendToServicePorts[nProto]; !ok {
			// all these ports
			for _, to := range byProto {
				err = bpfDeleteBackendToServicePort(tracked.bpfId, nProto, to)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}

		for from, to := range byProto {
			if currentFrom, ok := currentBackendToServicePorts[nProto][to]; !ok || from != currentFrom {
				err = bpfDeleteBackendToServicePort(tracked.bpfId, nProto, to)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	return errs
}

///////////////
// helper funcs
///////////////
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
		if c.hasTrackedServiceByBpfId(bpfId) {
			continue
		}
		for _, backend := range backends {
			err := bpfDeleteBackendToService(bpfId, backend)
			if err != nil {
				return err
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
		if c.hasTrackedServiceByBpfId(bpfId) {
			continue
		}
		for _, serviceIP := range serviceIPs {

			err := bpfDeleteServiceIP(bpfId, serviceIP)
			if err != nil {
				return err
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
		if c.hasTrackedServiceByBpfId(bpfId) {
			continue
		}
		for _, flow := range flows {
			err := bpfDeleteFlow(bpfId, flow.srcIP, flow.srcPort, flow.l4_proto)
			if err != nil {
				return err
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
		if c.hasTrackedServiceByBpfId(bpfId) {
			continue
		}
		for _, aff := range affs {
			err := bpfDeleteAffinity(bpfId, aff.clientIP)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func (c *ctrl) hasTrackedServiceByBpfId(bpfId uint64) bool {
	return (c.getTrackedServiceByBpfId(bpfId) != nil)
}
func (c *ctrl) getTrackedServiceByBpfId(bpfId uint64) *trackedService {
	return c.servicesByBpfId[bpfId]
}

func (c *ctrl) getTrackedServiceByName(namespaceName string) *trackedService {
	c.servicesMu.Lock()
	defer c.servicesMu.Unlock()

	return c.services[namespaceName]

}

func protoNumber(proto string) (uint8, error) {
	sProto := strings.ToUpper(proto)
	switch sProto {
	case "TCP":
		return IPPROTO_TCP, nil
	case "UDP":
		return IPPROTO_UDP, nil
	case "SCTP":
		return IPPROTO_SCTP, nil
	default:
		return 0, fmt.Errorf("invalid proto %v", proto)
	}
}

func protoString(proto uint8) string {
	switch proto {
	case IPPROTO_TCP:
		return "TCP"
	case IPPROTO_UDP:
		return "UDP"
	case IPPROTO_SCTP:
		return "SCTP"
	default:
		return ""
	}
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
