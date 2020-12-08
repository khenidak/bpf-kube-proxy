package controller

import (
	"net"
	"testing"
)

func TestServiceNameKey(t *testing.T) {
	testData := map[string]uint64{
		"service1": uint64(1),
		"service2": uint64(2),
		"service3": uint64(3),
		"service4": uint64(4),
		"service5": uint64(5),
	}

	deleteTestData := []string{"service2", "service4"}

	comparer := func(expected, got map[string]uint64) {
		t.Helper()
		if len(expected) != len(got) {
			t.Fatalf("expected service name key %v!=%v %+v", len(expected), len(got), got)
		}
		for expectedName, expectedKey := range expected {
			gotKey, ok := got[expectedName]
			if !ok || gotKey != expectedKey {
				t.Fatalf("could not find service %v:%v in %+v", expectedName, expectedKey, got)
			}
		}
	}

	// insert
	for name, key := range testData {
		err := bpfInsertOrUpdateServiceNameKey(name, key)
		if err != nil {
			t.Fatalf("failed to insert service %v:%v with error %v", name, key, err)
		}
	}
	// get one by one
	for name, key := range testData {
		gotKey, err := bpfGetServiceKeyByName(name)
		if err != nil {
			t.Fatalf("failed to get service %v with err %v", name, err)
		}
		if gotKey != key {
			t.Fatalf("expected service key:%v for service:%v but got:%v", key, name, gotKey)
		}
	}
	// get all and compare
	allServiceNamekey, err := bpfGetAllServiceNameKey()
	if err != nil {
		t.Fatalf("failed to get all services namekey with error %v", err)
	}

	comparer(testData, allServiceNamekey)

	// delete
	for _, toDelete := range deleteTestData {
		delete(testData, toDelete)
		err := bpfDeleteServiceNameKey(toDelete)
		if err != nil {
			t.Fatalf("failed to delete service %v with err %v", toDelete, err)
		}
	}

	// re-get all and compare
	allServiceNamekey, err = bpfGetAllServiceNameKey()
	if err != nil {
		t.Fatalf("failed to get all services namekey with error %v", err)
	}

	comparer(testData, allServiceNamekey)

}

func TestServiceInfo(t *testing.T) {

	testData := map[uint64]*trackedService{
		1: &trackedService{
			affinitySec:    11,
			totalEndpoints: 11,
		},
		2: &trackedService{
			affinitySec:    12,
			totalEndpoints: 12,
		},
		3: &trackedService{
			affinitySec:    13,
			totalEndpoints: 13,
		},
		4: &trackedService{
			affinitySec:    14,
			totalEndpoints: 14,
		},
		5: &trackedService{
			affinitySec:    15,
			totalEndpoints: 15,
		},
	}

	toDeleteBpfIds := []uint64{1, 3}
	compareTracked := func(expected, got *trackedService) {
		t.Helper()
		if expected.affinitySec != got.affinitySec ||
			expected.bpfId != got.bpfId ||
			expected.namespaceName != got.namespaceName ||
			expected.totalEndpoints != got.totalEndpoints {
			t.Fatalf("expected(%+v)!=got(%+v)", expected, got)
		}
	}

	compareAll := func(expected, got map[uint64]*trackedService) {
		t.Helper()
		if len(expected) != len(got) {
			t.Fatalf("len(expected)!=len(got) %v!=%v %+v", len(expected), len(got), got)
		}
		for expectedKey, expectedVal := range expected {
			gotVal, ok := got[expectedKey]
			if !ok {
				t.Fatalf("expected to find key %v in %+v", expectedKey, got)
			}

			compareTracked(expectedVal, gotVal)
		}
	}
	// insert
	for bpfId, tracked := range testData {
		tracked.bpfId = bpfId
		err := bpfInsertOrUpdateServiceInfo(tracked)
		if err != nil {
			t.Fatalf("failed to insert %+v with error:%v", tracked, err)
		}
	}

	// get one by one
	for bpfId, tracked := range testData {
		gotTracked, err := bpfGetServiceInfo(bpfId)
		if err != nil {
			t.Fatalf("failed to get service with id:%v err:%v", bpfId, err)
		}

		if gotTracked == nil {
			t.Fatalf("failed to get service with id:%v", bpfId)
		}

		compareTracked(tracked, gotTracked)
	}

	// get all and compare
	allInfos, err := bpfGetAllServiceInfos()
	if err != nil {
		t.Fatalf("failed to get all service infos with err :%v", err)
	}
	compareAll(testData, allInfos)

	// delete
	for _, bpfId := range toDeleteBpfIds {
		delete(testData, bpfId)
		err := bpfDeleteServiceInfo(bpfId)
		if err != nil {
			t.Fatalf("failed to delete service with bpfId:%v with err:%v", bpfId, err)
		}
	}

	// get all and compare
	allInfos, err = bpfGetAllServiceInfos()
	if err != nil {
		t.Fatalf("failed to get all service infos with err :%v", err)
	}
	compareAll(testData, allInfos)
}

func TestServiceToBackendPorts(t *testing.T) {
	bpfId := uint64(123456)

	portMapByProto := map[uint8]map[uint16]uint16{
		uint8(1): map[uint16]uint16{270: 7270, 280: 8280, 290: 9290},
		uint8(2): map[uint16]uint16{270: 7270, 280: 8280, 290: 9290}, // we use same ports because ports key are (bpfId + proto + fromPort)
		uint8(3): map[uint16]uint16{370: 37370, 380: 3380, 390: 9390},
	}

	portsToDelete := map[uint8][]uint16{
		uint8(1): []uint16{280, 290},
		uint8(2): []uint16{270},
		uint8(3): []uint16{380},
	}

	// insert all ports
	for proto, portMap := range portMapByProto {
		for fromPort, toPort := range portMap {
			err := bpfInsertOrUpdateServiceToBackendPort(bpfId, proto, fromPort, toPort)
			if err != nil {
				t.Fatalf("failed to insert port bpfId:%v proto:%v from:%v to :%v err:%v", bpfId, proto, fromPort, toPort, err)
			}
		}
	}

	// compare what was saved to what we have
	savedPortMapByProto, err := bpfGetServiceToBackendPorts(bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)

	// let us get them one by one and make sure that they are there
	for proto, portMap := range portMapByProto {
		for fromPort, toPort := range portMap {
			savedToPort, err := bpfGetServiceToBackendPort(bpfId, proto, fromPort)
			if err != err {
				t.Fatalf("unexpected error getting backendport for a serviceport: %v", err)
			}

			if toPort != savedToPort {
				t.Fatalf("expected toPort:%v got:%v", toPort, savedToPort)
			}
		}
	}

	// perform delete
	for proto, fromPorts := range portsToDelete {
		for _, fromPort := range fromPorts {
			// delete from bpf map
			err := bpfDeleteServiceToBackendPort(bpfId, proto, fromPort)
			if err != nil {
				t.Fatalf("failed to delete port with error %v", err)
			}
			// remove it from source map
			portMap := portMapByProto[proto]
			delete(portMap, fromPort)
		}
	}
	// now let us re-get and compare
	savedPortMapByProto, err = bpfGetServiceToBackendPorts(bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)
}

func TestBackendToServicePorts(t *testing.T) {
	bpfId := uint64(1234567)

	portMapByProto := map[uint8]map[uint16]uint16{
		uint8(1): map[uint16]uint16{7270: 270, 8280: 280, 9290: 290},
		uint8(2): map[uint16]uint16{7270: 270, 8280: 280, 9290: 290},
		uint8(3): map[uint16]uint16{37370: 370, 3380: 380, 9390: 390},
	}

	portsToDelete := map[uint8][]uint16{
		uint8(1): []uint16{7270, 8280},
		uint8(2): []uint16{7270},
		uint8(3): []uint16{37370},
	}

	// insert all ports
	for proto, portMap := range portMapByProto {
		for fromPort, toPort := range portMap {
			err := bpfInsertOrUpdateBackendToServicePort(bpfId, proto, fromPort, toPort)
			if err != nil {
				t.Fatalf("failed to insert port bpfId:%v proto:%v from:%v to :%v err:%v", bpfId, proto, fromPort, toPort, err)
			}
		}
	}

	// compare what was saved to what we have
	savedPortMapByProto, err := bpfGetBackEndToServicePorts(bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)

	// let us get them one by one and make sure that they are there
	for proto, portMap := range portMapByProto {
		for fromPort, toPort := range portMap {
			savedToPort, err := bpfGetBackendToServicePort(bpfId, proto, fromPort)
			if err != err {
				t.Fatalf("unexpected error getting backendport for a serviceport: %v", err)
			}

			if toPort != savedToPort {
				t.Fatalf("expected toPort:%v got:%v", toPort, savedToPort)
			}
		}
	}

	// perform delete
	for proto, fromPorts := range portsToDelete {
		for _, fromPort := range fromPorts {
			// delete from bpf map
			err := bpfDeleteBackendToServicePort(bpfId, proto, fromPort)
			if err != nil {
				t.Fatalf("failed to delete port with error %v", err)
			}
			// remove it from source map
			portMap := portMapByProto[proto]
			delete(portMap, fromPort)
		}
	}
	// now let us re-get and compare
	savedPortMapByProto, err = bpfGetBackEndToServicePorts(bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)
}

func comparePortMaps(t *testing.T, expected, saved map[uint8]map[uint16]uint16) {
	t.Helper()
	if len(expected) != len(saved) {
		t.Fatalf("saved number of protos:%v != expected:%v", len(saved), len(expected))
	}

	for proto, portMap := range expected {
		savedByProto, ok := saved[proto]
		if !ok {
			t.Fatalf("proto %v was expected and was not found", proto)
		}
		// compare ports
		if len(savedByProto) != len(portMap) {
			t.Fatalf("saved number of ports:%v != expected:%v", len(savedByProto), len(portMap))
		}

		for fromPort, toPort := range portMap {
			savedToPort, ok := savedByProto[fromPort]
			if !ok {
				t.Fatalf("proto:%v port:%vwas expected and was not found", proto, fromPort)
			}

			if savedToPort != toPort {
				t.Fatalf("expected saved port %v for proto %v to be mapped to %v but was mapped %v",
					fromPort, proto, toPort, savedToPort)
			}
		}
	}
}

func TestIPRoundTripper(t *testing.T) {
	testData := []net.IP{
		net.ParseIP("1.2.3.4"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("10.0.0.11"),
		net.ParseIP("172.16.0.2"),
		net.ParseIP("2000::1"),
		net.ParseIP("2000::2"),
		net.ParseIP("2000::3"),
		net.ParseIP("2000::4"),
	}

	for _, ip := range testData {
		kbpfIP := *(ipToKbpfIP(ip))
		gotIP := kbpfIPToIP(&kbpfIP)

		if gotIP.String() != ip.String() {
			t.Fatalf("expected ip after round trip:%v got %v", ip, gotIP)
		}
	}
}

func TestServiceIPs(t *testing.T) {
	//	assert := assert.New(t)
	bpfId := uint64(1234569)

	testData := []net.IP{
		net.ParseIP("1.2.3.4"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("10.0.0.11"),
		net.ParseIP("172.16.0.2"),
		net.ParseIP("2000::1"),
		net.ParseIP("2000::2"),
		net.ParseIP("2000::3"),
		net.ParseIP("2000::4"),
	}

	ipsToDelete := []net.IP{
		net.ParseIP("172.16.0.2"),
		net.ParseIP("2000::1"),
	}

	// delete all
	allServiceIPs, err := bpfGetAllServiceIPs()
	if err != nil {
		t.Fatalf("failed to get all service IPs with err:%v", err)
	}
	for bpfId, serviceIPs := range allServiceIPs {
		for _, serviceIP := range serviceIPs {
			err := bpfDeleteServiceIP(bpfId, serviceIP)
			if err != nil {
				t.Fatalf("failed to delete service IP %v for %v with err %v", serviceIP, bpfId, err)
			}
		}
	}

	// insertion test
	for _, ip := range testData {
		err := bpfInsertOrUpdateServiceIP(bpfId, ip)
		if err != nil {
			t.Fatalf("failed to insert service ip:%v with error:%v", ip, err)
		}
	}

	// read them
	savedServiceIPs, err := bpfGetServiceIPs(bpfId)
	if err != nil {
		t.Fatalf("failed to get service IPs with error:%v", err)
	}

	compareIPList(t, testData, savedServiceIPs)

	// test delete function
	filtered := make([]net.IP, 0, len(testData)-len(ipsToDelete))
	for _, currentIP := range testData {
		add := true
		for _, toDeleteIP := range ipsToDelete {
			if currentIP.String() == toDeleteIP.String() {
				err := bpfDeleteServiceIP(bpfId, toDeleteIP)
				if err != nil {
					t.Fatalf("failed to delete ip:%v with err:%v", toDeleteIP, err)
				}
				add = false
			}
		}
		if add {
			filtered = append(filtered, currentIP)
		}
	}

	// get and recompare
	savedServiceIPs, err = bpfGetServiceIPs(bpfId)
	if err != nil {
		t.Fatalf("failed to get service IPs with error:%v", err)
	}

	compareIPList(t, filtered, savedServiceIPs)
}

func TestBackendIPs(t *testing.T) {
	bpfId := uint64(123458)

	testData := []net.IP{
		net.ParseIP("1.2.3.4"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("10.0.0.11"),
		net.ParseIP("172.16.0.2"),
		net.ParseIP("2000::1"),
		net.ParseIP("2000::2"),
		net.ParseIP("2000::3"),
		net.ParseIP("2000::4"),
	}

	ipsToDelete := []net.IP{
		net.ParseIP("172.16.0.2"),
		net.ParseIP("2000::1"),
	}
	// insertion test
	for _, ip := range testData {
		err := bpfInsertOrUpdateBackendToService(bpfId, ip)
		if err != nil {
			t.Fatalf("failed to insert service ip:%v with error:%v", ip, err)
		}
	}

	// read them
	savedBackendIPs, err := bpfGetBackendsToService(bpfId)
	if err != nil {
		t.Fatalf("failed to get service IPs with error:%v", err)
	}

	compareIPList(t, testData, savedBackendIPs)

	// test delete function
	filtered := make([]net.IP, 0, len(testData)-len(ipsToDelete))
	for _, currentIP := range testData {
		add := true
		for _, toDeleteIP := range ipsToDelete {
			if currentIP.String() == toDeleteIP.String() {
				err := bpfDeleteBackendToService(bpfId, toDeleteIP)
				if err != nil {
					t.Fatalf("failed to delete ip:%v with err:%v", toDeleteIP, err)
				}
				add = false
			}
		}
		if add {
			filtered = append(filtered, currentIP)
		}

	}
	// get and recompare
	savedBackendIPs, err = bpfGetBackendsToService(bpfId)
	if err != nil {
		t.Fatalf("failed to get service IPs with error:%v", err)
	}

	compareIPList(t, filtered, savedBackendIPs)
}

func TestIndexedBackend(t *testing.T) {
	trackedOne := &trackedService{
		namespaceName:  "serviceOne",
		affinitySec:    10,
		totalEndpoints: 10,
		bpfId:          123456,
	}

	trackedTwo := &trackedService{
		namespaceName:  "serviceTwo",
		affinitySec:    10,
		totalEndpoints: 10,
		bpfId:          6541,
	}

	testData := map[uint64]map[string]uint64{
		trackedOne.bpfId: {
			"10.0.0.1": 1,
			"2000::1":  1,

			"10.0.0.2": 2,
			"2000::2":  2,

			"10.0.0.3": 3,
			"2000::3":  3,
		},
		trackedTwo.bpfId: {
			"11.0.0.1": 1,
			"3000::1":  1,

			"11.0.0.2": 2,
			"3000::2":  2,

			"11.0.0.3": 3,
			"3000::3":  3,
		},
	}

	deleteData := map[uint64]map[string]uint64{
		trackedOne.bpfId: {
			"10.0.0.2": 2,
			"2000::2":  2,
		},
		trackedTwo.bpfId: {
			"11.0.0.3": 3,
			"3000::3":  3,
		},
	}

	// test saved data against data
	verifier := func(data map[uint64]map[string]uint64) {
		// get and check
		for bpfId, indexedIPs := range data {
			got, err := bpfGetServiceToBackendIndxed(bpfId)
			if err != nil {
				t.Fatalf("failed to get indexed backend for %v with error %v", bpfId, err)
			}
			// compare
			if len(got) != len(indexedIPs) {
				t.Fatalf("expected count of indexed ips:%v got:%v", len(indexedIPs), len(got))
			}

			for ip, index := range indexedIPs {
				savedIndex, ok := got[ip]
				if !ok || savedIndex != index {
					t.Fatalf("failed to find ip:%v with index:%v", ip, index)
				}
			}
		}
	}

	// insert all backends
	for bpfId, indexedIPs := range testData {
		for ip, index := range indexedIPs {
			err := bpfInsertOrUpdateServiceToBackendIndexed(bpfId, index, net.ParseIP(ip))
			if err != nil {
				t.Fatalf("failed to insert indexed backend ip:%v index:%v for:%v with error %v", ip, index, bpfId, err)
			}
		}
	}

	verifier(testData)
	// delete
	for bpfId, ipsToDelete := range deleteData {
		for ipToDelete, index := range ipsToDelete {
			delete(testData[bpfId], ipToDelete)
			err := bpfDeleteServiceToBackendIndexed(bpfId, index, net.ParseIP(ipToDelete))
			if err != nil {
				t.Fatalf("failed to delete ip:%v for:%v index:%v with err:%v", ipToDelete, bpfId, index, err)
			}
		}
	}
	//reverify
	verifier(testData)

}

func TestFlows(t *testing.T) {
	testData := map[uint64][]flow{
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
			{
				srcIP:    net.ParseIP("10.0.0.10"),
				srcPort:  5434,
				l4_proto: 1,
				destIP:   net.ParseIP("172.16.0.1"),
				hit:      12,
			},
			{
				srcIP:    net.ParseIP("2000::1"),
				srcPort:  5432,
				l4_proto: 1,
				destIP:   net.ParseIP("4000::1"),
				hit:      10,
			},
			{
				srcIP:    net.ParseIP("2000::1"),
				srcPort:  5433,
				l4_proto: 1,
				destIP:   net.ParseIP("4000::1"),
				hit:      11,
			},
			{
				srcIP:    net.ParseIP("2000::1"),
				srcPort:  5434,
				l4_proto: 1,
				destIP:   net.ParseIP("4000::1"),
				hit:      12,
			},
		},
		2: {
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
			{
				srcIP:    net.ParseIP("10.0.0.10"),
				srcPort:  5434,
				l4_proto: 1,
				destIP:   net.ParseIP("172.16.0.1"),
				hit:      12,
			},
			{
				srcIP:    net.ParseIP("2000::1"),
				srcPort:  5432,
				l4_proto: 1,
				destIP:   net.ParseIP("4000::1"),
				hit:      10,
			},
			{
				srcIP:    net.ParseIP("2000::1"),
				srcPort:  5433,
				l4_proto: 1,
				destIP:   net.ParseIP("4000::1"),
				hit:      11,
			},
			{
				srcIP:    net.ParseIP("2000::1"),
				srcPort:  5434,
				l4_proto: 1,
				destIP:   net.ParseIP("4000::1"),
				hit:      12,
			},
		},
	}

	verifier := func(expected []flow, got []flow) {
		if len(expected) != len(got) {
			t.Fatalf("expected and got are not the same length %v!=%v", len(expected), len(got))
		}
		for _, expectedOne := range expected {
			found := false
			for _, gotOne := range got {
				if expectedOne.srcIP.String() == gotOne.srcIP.String() &&
					expectedOne.srcPort == gotOne.srcPort &&
					expectedOne.l4_proto == gotOne.l4_proto &&
					expectedOne.destIP.String() == gotOne.destIP.String() &&
					expectedOne.hit == gotOne.hit {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("failed to find flow %v in %v", expectedOne, got)
			}
		}
	}
	// insert them
	for bpfId, testFlows := range testData {
		for _, test := range testFlows {
			err := bpfInsertOrUpdateFlow(bpfId, test.srcIP, test.srcPort, test.l4_proto, test.destIP, test.hit)
			if err != nil {
				t.Fatalf("error inserting a flow %+v err:%v", test, err)
			}
		}
	}

	gotFlows, err := bpfGetAllFlows()
	if err != nil {
		t.Fatalf("failed to get flows with error:%v", err)
	}

	// compare all
	for bpfId, flows := range gotFlows {
		testFlows, ok := testData[bpfId]
		if !ok {
			t.Fatalf("failed to find flow for %v", bpfId)
		}
		verifier(testFlows, flows)
	}

	// compare one
	flowsForOne, err := bpfGetFlowsForService(1)
	if err != nil {
		t.Fatalf("failed to get flows for one service %v", err)
	}
	verifier(testData[1], flowsForOne)

	// delete few flows
	flows := testData[1]
	for _, flow := range flows {
		err := bpfDeleteFlow(1, flow.srcIP, flow.srcPort, flow.l4_proto)
		if err != nil {
			t.Fatalf("failed to delete flow %+v", err)
		}
	}
	delete(testData, 1)

	// re-get and verify
	gotFlows, err = bpfGetAllFlows()
	if err != nil {
		t.Fatalf("failed to get flows with error:%v", err)
	}

	// compare all
	for bpfId, flows := range gotFlows {
		testFlows, ok := testData[bpfId]
		if !ok {
			t.Fatalf("failed to find flow for %v", bpfId)
		}
		verifier(testFlows, flows)
	}
}

func TestAffinity(t *testing.T) {
	testData := map[uint64][]affinity{
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
		2: {
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

	verifier := func(expected []affinity, got []affinity) {
		t.Helper()
		if len(expected) != len(got) {
			t.Fatalf("expected and got are not the same length %v!=%v", len(expected), len(got))
		}
		for _, expectedOne := range expected {
			found := false
			for _, gotOne := range got {
				if expectedOne.clientIP.String() == gotOne.clientIP.String() &&
					expectedOne.destIP.String() == gotOne.destIP.String() &&
					expectedOne.hit == gotOne.hit {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("failed to find flow %v in %v", expectedOne, got)
			}
		}
	}

	// must clear affinities
	allAff, err := bpfGetAllAffinities()
	if err != nil {
		t.Fatalf("failed to clear affs with err:%v", err)
	}
	for bpfId, affs := range allAff {
		for _, aff := range affs {
			err := bpfDeleteAffinity(bpfId, aff.clientIP)
			if err != nil {
				t.Fatalf("failed to clear affs for %v with err:%v", bpfId, err)
			}
		}
	}

	// insert affinities
	for bpfId, affList := range testData {
		for _, aff := range affList {
			err := bpfInsertOrUpdateAffinity(bpfId, aff.clientIP, aff.destIP, aff.hit)
			if err != nil {
				t.Fatalf("failed to insert affinity %+v with err: %v", aff, err)
			}
		}
	}

	// get one
	for bpfId, affList := range testData {
		got, err := bpfGetAffinityForService(bpfId)
		if err != nil {
			t.Fatalf("failed get affinities for %v with error:%v", bpfId, err)
		}
		verifier(affList, got)
	}

	// get all
	allAff, err = bpfGetAllAffinities()
	if err != nil {
		t.Fatalf("failed to get affinities with err:%v", err)
	}

	for bpfId, affList := range allAff {
		expectedAff, ok := testData[bpfId]
		if !ok {
			t.Fatalf("failed to find affinities for %v", bpfId)
		}
		verifier(expectedAff, affList)
	}

	afflist := testData[1]
	for _, aff := range afflist {
		err := bpfDeleteAffinity(1, aff.clientIP)
		if err != nil {
			t.Fatalf("failed to delete affinity %+v with err:%v", aff, err)
		}
	}

	delete(testData, 1)
	// get all and recompare
	allAff, err = bpfGetAllAffinities()
	if err != nil {
		t.Fatalf("failed to get affinities with err:%v", err)
	}

	for bpfId, affList := range allAff {
		expectedAff, ok := testData[bpfId]
		if !ok {
			t.Fatalf("failed to find affinities for %v", bpfId)
		}
		verifier(expectedAff, affList)
	}
}

func compareIPList(t *testing.T, expected []net.IP, got []net.IP) {
	if len(expected) != len(got) {
		t.Fatalf("count of ips:%v does not equal expected:%v gotIPs:%v", len(got), len(expected), got)
	}

	for _, expectedIP := range expected {
		found := false
		for _, gotIP := range got {
			if expectedIP.String() == gotIP.String() {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("couldn't find IP:%v in %v", expectedIP, got)
		}
	}
}
