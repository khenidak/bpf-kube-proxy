package controller

type Controller interface {
	// AddService adds a service to tracked list of services.
	// AddService can be called multiple times for the same service.
	AddService(namespaceName string, affinitySec uint16) error

	// SyncServiceIPs sync a list of ips for a service.
	// it adds new ips that are not currently part of the service ip list
	// it removes ips that are no longer part of ot the service ip list
	SyncServiceIPs(namespaceName string, ips []string) []error

	// SyncServicePorts syns list of ports used by this service. The expected input is
	// map[TCP||UDP||SCTP] of map[from-service-port]=>pod-port
	SyncServicePorts(namespaceName string, ports map[string]map[uint16]uint16) []error

	// used only for testing
	GetServiceBpfId(namespaceName string) uint64
}
