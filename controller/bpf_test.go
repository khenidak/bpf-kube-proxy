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
