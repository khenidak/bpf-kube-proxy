package controller

import (
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
