package controller

type Controller interface {
	// TrackService adds service to the tracked list of service
	// TrackService can be called for the same service multiple times
	TrackService(namespaceName string, affinitySec int) error
	/*
		// SyncServiceIPs synchronizes the list of ips {clusterIPs, externalIPs, LB IPs}
		// that this service listens
		SyncServiceIPs(namespaceName string, ips []string) error

		// SyncServicePorts maps service port to an endpoint port
		SyncServicePorts(namespaceName string, ports map[int16]int16) error
		// SyncServiceEndpoints synchronizes the list of endpoints backing this service
		SyncServiceEndpoints(namespaceName string, endpoints []string) error
		// UntrackService removes all data related to this service
		UntrackService(namespaceName string)
		Stop()
	*/
}
