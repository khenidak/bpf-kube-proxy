package controller

import (
	"fmt"
	"net"
	"testing"
)

// clears all the state (service top level name/key and ids)
func clearAll(t *testing.T) {
	t.Helper()
	// delete name->mapping
	// create a controller which automatically clears everything else
	// because it treats name->key as source of truth
	allNameKey, err := bpfGetAllServiceNameKey()
	if err != nil {
		t.Fatalf("failed tp delete name/keys %v", err)
	}

	for name, _ := range allNameKey {
		err := bpfDeleteServiceNameKey(name)
		if err != nil {
			t.Fatalf("failed to delete name,key with err:%v", err)
		}
	}
	_, err = NewController(t.Logf, 10)
	if err != nil {
		t.Fatalf("failed to clear data with err %v", err)
	}

}

func TestControllerCreate(t *testing.T) {
	serviceKeyName := map[uint64]string{
		uint64(1): "service1",
		uint64(2): "service2",
	}

	testTrackedServices := map[uint64]*trackedService{
		1: &trackedService{
			affinitySec:    11,
			totalEndpoints: 11,
		},
		2: &trackedService{
			affinitySec:    12,
			totalEndpoints: 12,
		},
		// should be orphaned
		3: &trackedService{
			affinitySec:    13,
			totalEndpoints: 13,
		},
	}

	testFlows := map[uint64][]flow{
		1: {
			{
				srcIP:    net.ParseIP("10.0.0.10"),
				srcPort:  5432,
				l4_proto: 1,
				destIP:   net.ParseIP("172.16.0.1"),
				hit:      10,
			},
			{
				srcIP:    net.ParseIP("10.0.0.10"),
				srcPort:  5433,
				l4_proto: 1,
				destIP:   net.ParseIP("172.16.0.1"),
				hit:      11,
			},
		},
		// flows that should be removed
		101: {
			{
				srcIP:    net.ParseIP("10.0.0.10"),
				srcPort:  5432,
				l4_proto: 1,
				destIP:   net.ParseIP("172.16.0.1"),
				hit:      10,
			},
			{
				srcIP:    net.ParseIP("10.0.0.10"),
				srcPort:  5433,
				l4_proto: 1,
				destIP:   net.ParseIP("172.16.0.1"),
				hit:      11,
			},
		},
	}
	testAffinities := map[uint64][]affinity{
		1: {
			{
				clientIP: net.ParseIP("10.0.0.10"),
				destIP:   net.ParseIP("11.0.0.10"),
				hit:      101,
			},
			{
				clientIP: net.ParseIP("2000::1"),
				destIP:   net.ParseIP("4000::1"),
				hit:      102,
			},
		},
		// should be orphaned
		102: {
			{
				clientIP: net.ParseIP("10.0.1.10"),
				destIP:   net.ParseIP("11.0.1.10"),
				hit:      101,
			},
			{
				clientIP: net.ParseIP("2001::1"),
				destIP:   net.ParseIP("4001::1"),
				hit:      102,
			},
		},
	}

	testServiceIPs := map[uint64][]net.IP{
		1: {
			net.ParseIP("10.0.1.10"),
			net.ParseIP("10.0.1.11"),
			net.ParseIP("10.0.1.12"),
		},
		102: {
			net.ParseIP("10.1.1.10"),
			net.ParseIP("10.1.1.11"),
			net.ParseIP("10.1.1.12"),
		},
	}

	testBackends := map[uint64][]net.IP{
		1: {
			net.ParseIP("12.0.1.10"),
			net.ParseIP("12.0.1.11"),
			net.ParseIP("12.0.1.12"),
		},
		102: {
			net.ParseIP("12.1.1.10"),
			net.ParseIP("12.1.1.11"),
			net.ParseIP("12.1.1.12"),
		},
	}

	portMap := map[uint64]map[uint8]map[uint16]uint16{
		1: {
			uint8(1): map[uint16]uint16{7270: 270, 8280: 280, 9290: 290},
			uint8(2): map[uint16]uint16{7270: 270, 8280: 280, 9290: 290},
			uint8(3): map[uint16]uint16{37370: 370, 3380: 380, 9390: 390},
		},
		102: {
			uint8(1): map[uint16]uint16{7270: 270, 8280: 280, 9290: 290},
			uint8(2): map[uint16]uint16{7270: 270, 8280: 280, 9290: 290},
			uint8(3): map[uint16]uint16{37370: 370, 3380: 380, 9390: 390},
		},
	}

	testIndexedBackends := map[uint64]map[string]uint64{
		1: {
			"10.0.0.1": 1,
			"2000::1":  1,

			"10.0.0.2": 2,
			"2000::2":  2,

			"10.0.0.3": 3,
			"2000::3":  3,
		},
		101: {
			"11.0.0.1": 1,
			"3000::1":  1,

			"11.0.0.2": 2,
			"3000::2":  2,

			"11.0.0.3": 3,
			"3000::3":  3,
		},
	}

	confirmBpfId := func(bpfId uint64) {
		t.Helper()
		if _, ok := serviceKeyName[bpfId]; !ok {
			t.Fatalf("bpf id does not exist in list of expected services %v", bpfId)
		}
	}

	clearAll(t)

	// insert key names
	for key, name := range serviceKeyName {
		err := bpfInsertOrUpdateServiceNameKey(name, key)
		if err != nil {
			t.Fatalf("failed to insert service %v:%v with error %v", name, key, err)
		}
	}

	// insert services
	for bpfId, tracked := range testTrackedServices {
		tracked.bpfId = bpfId
		err := bpfInsertOrUpdateServiceInfo(tracked)
		if err != nil {
			t.Fatalf("failed to insert %+v with error:%v", tracked, err)
		}
	}

	// insert flows
	for bpfId, testFlows := range testFlows {
		for _, test := range testFlows {
			err := bpfInsertOrUpdateFlow(bpfId, test.srcIP, test.srcPort, test.l4_proto, test.destIP, test.hit)
			if err != nil {
				t.Fatalf("error inserting a flow %+v err:%v", test, err)
			}
		}
	}

	//insert affinities
	for bpfId, affList := range testAffinities {
		for _, aff := range affList {
			err := bpfInsertOrUpdateAffinity(bpfId, aff.clientIP, aff.destIP, aff.hit)
			if err != nil {
				t.Fatalf("failed to insert affinity %+v with err: %v", aff, err)
			}
		}
	}

	// insert serviceIPs
	for bpfId, serviceIPs := range testServiceIPs {
		for _, serviceIP := range serviceIPs {
			err := bpfInsertOrUpdateServiceIP(bpfId, serviceIP)
			if err != nil {
				t.Fatalf("failed to insert service ip with error:%v", err)
			}
		}
	}
	// insert backends
	for bpfId, backends := range testBackends {
		for _, backend := range backends {
			err := bpfInsertOrUpdateBackendToService(bpfId, backend)
			if err != nil {
				t.Fatalf("failed to insert service backend  with error:%v", err)
			}
		}
	}

	// insert ports (we are using the same map for service=>backend and backend=>service)
	for bpfId, byProto := range portMap {
		for proto, fromTo := range byProto {
			for from, to := range fromTo {
				err := bpfInsertOrUpdateServiceToBackendPort(bpfId, proto, from, to)
				if err != nil {
					t.Fatalf("failed to insert service to backend port with err%v", err)
				}
				err = bpfInsertOrUpdateBackendToServicePort(bpfId, proto, to, from)
				if err != nil {
					t.Fatalf("failed to insert backend to service port with err%v", err)
				}
			}
		}
	}

	// insert indexed backends
	for bpfId, ipIndex := range testIndexedBackends {
		for ip, index := range ipIndex {
			err := bpfInsertOrUpdateServiceToBackendIndexed(bpfId, index, net.ParseIP(ip))
			if err != nil {
				t.Fatalf("failed to insert indexed backned with error:%v", err)
			}
		}
	}
	// *********************
	// create controller
	// *********************
	_, err := NewController(t.Logf, 10)
	if err != nil {
		t.Fatalf("failed to create controller with error:%v", err)
	}

	// now make sure that the remaining is not orphaned
	// our master is key name
	gotTracked, err := bpfGetAllServiceInfos()
	if err != nil {
		t.Fatalf("failed to get all services infos with err:%v", err)
	}
	for bpfId, _ := range gotTracked {
		confirmBpfId(bpfId)
	}
	// flows
	gotFlows, err := bpfGetAllFlows()
	if err != nil {
		t.Fatalf("failed to get flows with err:%v", err)
	}
	for bpfId, _ := range gotFlows {
		confirmBpfId(bpfId)
	}
	// affinities
	gotAffs, err := bpfGetAllAffinities()
	if err != nil {
		t.Fatalf("failed to get affinities with error:%v", err)
	}
	for bpfId, _ := range gotAffs {
		confirmBpfId(bpfId)
	}
	// serviceIPs
	gotServiceIPs, err := bpfGetAllServiceIPs()
	if err != nil {
		t.Fatalf("failed to get serviceIPs  with error:%v", err)
	}
	for bpfId, _ := range gotServiceIPs {
		confirmBpfId(bpfId)
	}
	// backends
	gotBackends, err := bpfGetAllBackendsToService()
	if err != nil {
		t.Fatalf("failed to get backends  with error:%v", err)
	}
	for bpfId, _ := range gotBackends {
		confirmBpfId(bpfId)
	}
	// service to backend ports
	gotServiceToBackendPorts, err := bpfGetAllServiceToBackendPorts()
	if err != nil {
		t.Fatalf("failed to get service=>backend ports with error:%v", err)
	}
	for bpfId, _ := range gotServiceToBackendPorts {
		confirmBpfId(bpfId)
	}

	// backend to service ports
	gotBackendToServicePorts, err := bpfGetAllBackEndToServicePorts()
	if err != nil {
		t.Fatalf("failed to get backend=>service ports with error:%v", err)
	}
	for bpfId, _ := range gotBackendToServicePorts {
		confirmBpfId(bpfId)
	}

	// indexed backends
	gotIndexedBackends, err := bpfGetAllServiceToBackendIndxed()
	if err != nil {
		t.Fatalf("failed to get all indexed backends with err %v", err)
	}
	for bpfId, _ := range gotIndexedBackends {
		confirmBpfId(bpfId)
	}
}

func TestSyncServiceIPs(t *testing.T) {
	serviceName := "namespace1/service1"
	serviceAffinity := uint16(0)

	testServiceIPs := map[string][]string{
		"r1": {
			"10.0.1.10",
			"10.0.1.11", // will be deleted
			"10.0.1.12",
		},
		"r2": {
			"10.0.0.20", // changed
			"10.1.1.12",
		},
	}

	c, err := NewController(t.Logf, 10)
	if err != nil {
		t.Fatalf("failed to create controller with err:%v", err)
	}

	compareIPSlices := func(with []string) {
		t.Helper()

		currentIPs, err := bpfGetServiceIPs(c.GetServiceBpfId(serviceName))
		failIfNeeded(t, []error{err}, "failed to read service IPS")
		if len(with) != len(currentIPs) {
			t.Fatalf("expected service ips != current service ips %+v!=%+v", with, currentIPs)
		}
		for _, ip := range with {
			found := false
			for _, currentIP := range currentIPs {
				if currentIP.String() == ip {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected service ips != current service ips %+v!=%+v", with, currentIPs)

			}
		}
	}

	err = c.AddService(serviceName, serviceAffinity)
	if err != nil {
		t.Fatalf("failed to create service with err %v", err)
	}

	for roundName, ips := range testServiceIPs {
		// first round
		errs := c.SyncServiceIPs(serviceName, ips)
		failIfNeeded(t, errs, fmt.Sprintf("failed to sync service ips %v:%v", roundName, ips))
		compareIPSlices(ips)
	}
}

func TestSyncPorts(t *testing.T) {
	serviceName := "namespace1/service1"
	serviceAffinity := uint16(0)

	c, err := NewController(t.Logf, 10)
	if err != nil {
		t.Fatalf("failed to create controller with err:%v", err)
	}

	rounds := map[string]map[string]map[uint16]uint16{
		"round1": {
			"TCP": {
				80: 8080,
				90: 9090,
			},
			"uDP": {
				60: 6060,
				50: 5060,
			},
			"SCTP": {
				40: 4040,
				30: 3030,
			},
		},
		"round2": {
			/* missing tcp is on purpose */
			"UDP": {
				61: 6160,
			},
			"ScTP": {
				40: 4040,
				31: 3130,
			},
		},
	}

	clearAll(t)

	err = c.AddService(serviceName, serviceAffinity)
	if err != nil {
		t.Fatalf("failed to create service with err %v", err)
	}

	comparePortList := func(source, with map[uint16]uint16, invert bool) {
		if !invert {
			for from, to := range source {
				if withTo, ok := with[from]; !ok || withTo != to {
					t.Fatalf("failed to find port [%v:%v]", from, to)
				}
			}
			return
		}
		// inverted
		for from, to := range source {
			if withFrom, ok := with[to]; !ok || withFrom != from {
				t.Fatalf("failed to find port [%v:%v]", from, to)
			}
		}
	}

	comparePorts := func(with map[string]map[uint16]uint16) {
		t.Helper()
		t.Logf("testing service->backend ports")
		currentServiceToBEPorts, err := bpfGetServiceToBackendPorts(c.GetServiceBpfId(serviceName))
		failIfNeeded(t, []error{err}, "failed to read service to backend ports")
		if len(with) != len(currentServiceToBEPorts) {
			t.Fatalf("expected svc->BE  ports != current svc->BE ports %+v!=%+v", with, currentServiceToBEPorts)
		}

		for nProto, portList := range currentServiceToBEPorts {
			comparePortList(with[protoString(nProto)], portList, false)
		}

		currentBEToServicePorts, err := bpfGetBackEndToServicePorts(c.GetServiceBpfId(serviceName))
		failIfNeeded(t, []error{err}, "failed to read backend to service ports")
		if len(with) != len(currentBEToServicePorts) {
			t.Fatalf("expected BE->svc != current BE-SVC  %+v!=%+v", with, currentBEToServicePorts)
		}

		for nProto, portList := range currentBEToServicePorts {
			comparePortList(with[protoString(nProto)], portList, true)
		}
	}

	for round, portsByProto := range rounds {
		errs := c.SyncServicePorts(serviceName, portsByProto)
		failIfNeeded(t, errs, fmt.Sprintf("failed to sync ports %v", round))
		comparePorts(portsByProto)
	}
}

func failIfNeeded(t *testing.T, errs []error, msg string) {
	t.Helper()
	if len(errs) > 0 && errs[0] != nil /* we just ship err as they are here */ {
		t.Fatalf("%v %+v", msg, errs)
	}
}
