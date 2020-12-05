package controller

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceInfo(t *testing.T) {
	assert := assert.New(t)

	serviceName := "testService"
	tracked := &trackedService{
		namespaceName:  serviceName,
		affinitySec:    10,
		totalEndpoints: 10,
		bpfId:          123456,
	}

	err := bpfInsertOrUpdateServiceInfo(tracked)
	assert.NoErrorf(err, "failed to insert service info with error %v", err)

	readTracked, err := bpfGetServiceInfo(serviceName)

	assert.NoErrorf(err, "failed to read service info %v", err)
	assert.NotNil(readTracked, "service %v should be in bpf map, it was not", serviceName)

	assert.Equal(readTracked.bpfId, tracked.bpfId, "bpfid should be the same")
	assert.Equal(readTracked.totalEndpoints, tracked.totalEndpoints, "endpoint count should be the same")
	assert.Equal(readTracked.affinitySec, tracked.affinitySec, "affinitySec should be the same")
	assert.Equal(readTracked.namespaceName, tracked.namespaceName, "namespaceName should be the same")

	// saving affinity should automatically load endpoint count
	oldcount := tracked.totalEndpoints
	tracked.totalEndpoints = 0

	err = bpfUpdateServiceAffinity(tracked, 20)
	assert.NoErrorf(err, "failed to update service affinity info %v", err)

	assert.Equal(oldcount, tracked.totalEndpoints, "affinity update should automatically load the endpoint count")
}

func TestServiceToBackendPorts(t *testing.T) {
	assert := assert.New(t)
	serviceName := "namespace/service"

	tracked := &trackedService{
		namespaceName:  serviceName,
		affinitySec:    10,
		totalEndpoints: 10,
		bpfId:          123456,
	}

	err := bpfInsertOrUpdateServiceInfo(tracked)
	assert.NoErrorf(err, "failed to insert service info with error %v", err)

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
			err := bpfInsertOrUpdateServiceToBackendPort(tracked.bpfId, proto, fromPort, toPort)
			if err != nil {
				t.Fatalf("failed to insert port bpfId:%v proto:%v from:%v to :%v err:%v", tracked.bpfId, proto, fromPort, toPort, err)
			}
		}
	}

	// compare what was saved to what we have
	savedPortMapByProto, err := bpfGetServiceToBackendPorts(tracked.bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)

	// let us get them one by one and make sure that they are there
	for proto, portMap := range portMapByProto {
		for fromPort, toPort := range portMap {
			savedToPort, err := bpfGetServiceToBackendPort(tracked.bpfId, proto, fromPort)
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
			err := bpfDeleteServiceToBackendPort(tracked.bpfId, proto, fromPort)
			if err != nil {
				t.Fatalf("failed to delete port with error %v", err)
			}
			// remove it from source map
			portMap := portMapByProto[proto]
			delete(portMap, fromPort)
		}
	}
	// now let us re-get and compare
	savedPortMapByProto, err = bpfGetServiceToBackendPorts(tracked.bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)
}

func TestBackendToServicePorts(t *testing.T) {
	assert := assert.New(t)
	serviceName := "namespace/service"

	tracked := &trackedService{
		namespaceName:  serviceName,
		affinitySec:    10,
		totalEndpoints: 10,
		bpfId:          123456,
	}

	err := bpfInsertOrUpdateServiceInfo(tracked)
	assert.NoErrorf(err, "failed to insert service info with error %v", err)

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
			err := bpfInsertOrUpdateBackendToServicePort(tracked.bpfId, proto, fromPort, toPort)
			if err != nil {
				t.Fatalf("failed to insert port bpfId:%v proto:%v from:%v to :%v err:%v", tracked.bpfId, proto, fromPort, toPort, err)
			}
		}
	}

	// compare what was saved to what we have
	savedPortMapByProto, err := bpfGetBackEndToServicePorts(tracked.bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)

	// let us get them one by one and make sure that they are there
	for proto, portMap := range portMapByProto {
		for fromPort, toPort := range portMap {
			savedToPort, err := bpfGetBackendToServicePort(tracked.bpfId, proto, fromPort)
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
			err := bpfDeleteBackendToServicePort(tracked.bpfId, proto, fromPort)
			if err != nil {
				t.Fatalf("failed to delete port with error %v", err)
			}
			// remove it from source map
			portMap := portMapByProto[proto]
			delete(portMap, fromPort)
		}
	}
	// now let us re-get and compare
	savedPortMapByProto, err = bpfGetBackEndToServicePorts(tracked.bpfId)
	if err != nil {
		t.Fatalf("failed to get service to backend ports %v", err)
	}
	comparePortMaps(t, portMapByProto, savedPortMapByProto)
}

func comparePortMaps(t *testing.T, expected, saved map[uint8]map[uint16]uint16) {
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
	serviceName := "namespace/service"

	tracked := &trackedService{
		namespaceName:  serviceName,
		affinitySec:    10,
		totalEndpoints: 10,
		bpfId:          123456,
	}

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
		err := bpfInsertOrUpdateServiceIP(tracked.bpfId, ip)
		if err != nil {
			t.Fatalf("failed to insert service ip:%v with error:%v", ip, err)
		}
	}

	// read them
	savedServiceIPs, err := bpfGetServiceIPs(tracked.bpfId)
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
				err := bpfDeleteServiceIP(tracked.bpfId, toDeleteIP)
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
	savedServiceIPs, err = bpfGetServiceIPs(tracked.bpfId)
	if err != nil {
		t.Fatalf("failed to get service IPs with error:%v", err)
	}

	compareIPList(t, filtered, savedServiceIPs)
}

func TestBackendIPs(t *testing.T) {
	//	assert := assert.New(t)
	serviceName := "namespace/service"

	tracked := &trackedService{
		namespaceName:  serviceName,
		affinitySec:    10,
		totalEndpoints: 10,
		bpfId:          123456,
	}

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
		err := bpfInsertOrUpdateBackendToService(tracked.bpfId, ip)
		if err != nil {
			t.Fatalf("failed to insert service ip:%v with error:%v", ip, err)
		}
	}

	// read them
	savedBackendIPs, err := bpfGetBackendsToService(tracked.bpfId)
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
				err := bpfDeleteBackendToService(tracked.bpfId, toDeleteIP)
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
	savedBackendIPs, err = bpfGetBackendsToService(tracked.bpfId)
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
	allAff, err := bpfGetAllAffinities()
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
