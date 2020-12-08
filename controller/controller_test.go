package controller

import (
	"net"
	"testing"
)

// clears all the state
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
}
