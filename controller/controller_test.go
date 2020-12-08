package controller

import (
	"net"
	"testing"
)

// clears all the state (service top level name/key and ids)
func clearAll(t *testing.T) {
	t.Helper()
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
