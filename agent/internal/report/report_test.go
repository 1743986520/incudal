package report

import "testing"

func TestHeartbeatPayloadIncludesHostMetrics(t *testing.T) {
	payload := HeartbeatPayload("test-version", 30)

	capabilities, ok := payload["capabilities"].([]any)
	if !ok {
		t.Fatalf("capabilities missing or invalid: %#v", payload["capabilities"])
	}
	if !containsCapability(capabilities, "host-metrics") {
		t.Fatalf("host-metrics capability missing: %#v", capabilities)
	}
	if !containsCapability(capabilities, "instance-status") {
		t.Fatalf("instance-status capability missing: %#v", capabilities)
	}
	if !containsCapability(capabilities, "traffic-counters") {
		t.Fatalf("traffic-counters capability missing: %#v", capabilities)
	}

	instances, ok := payload["instances"].(map[string]any)
	if !ok {
		t.Fatalf("instances report missing or invalid: %#v", payload["instances"])
	}
	for _, key := range []string{"available", "reportedAt", "total", "items"} {
		if _, ok := instances[key]; !ok {
			t.Fatalf("instances key %s missing: %#v", key, instances)
		}
	}

	runtimeInfo, ok := payload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("runtime missing or invalid: %#v", payload["runtime"])
	}
	for _, key := range []string{"goos", "goarch"} {
		if _, ok := runtimeInfo[key]; !ok {
			t.Fatalf("runtime key %s missing: %#v", key, runtimeInfo)
		}
	}

	resources, ok := payload["resources"].(map[string]any)
	if !ok {
		t.Fatalf("resources missing or invalid: %#v", payload["resources"])
	}
	for _, key := range []string{
		"cpuTotal",
		"cpuUsagePercent",
		"memoryTotalMb",
		"memoryUsedMb",
		"memoryUsagePercent",
		"swapTotalMb",
		"swapUsedMb",
		"swapUsagePercent",
		"diskTotalBytes",
		"diskUsedBytes",
		"diskUsagePercent",
		"processCount",
	} {
		if _, ok := resources[key]; !ok {
			t.Fatalf("resource key %s missing: %#v", key, resources)
		}
	}

	metrics, ok := payload["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("metrics missing or invalid: %#v", payload["metrics"])
	}
	for _, key := range []string{"reportedAt", "heartbeatIntervalSeconds", "uptimeSeconds", "load1", "load5", "load15"} {
		if _, ok := metrics[key]; !ok {
			t.Fatalf("metric key %s missing: %#v", key, metrics)
		}
	}
	if metrics["heartbeatIntervalSeconds"] != 30 {
		t.Fatalf("heartbeat interval mismatch: %#v", metrics["heartbeatIntervalSeconds"])
	}
}

func TestHeartbeatPayloadClampsHeartbeatInterval(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{name: "zero falls back", input: 0, expected: 30},
		{name: "too low clamps to min", input: 1, expected: 5},
		{name: "too high clamps to max", input: 7200, expected: 3600},
		{name: "valid stays unchanged", input: 60, expected: 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := HeartbeatPayload("test-version", tt.input)
			metrics, ok := payload["metrics"].(map[string]any)
			if !ok {
				t.Fatalf("metrics missing or invalid: %#v", payload["metrics"])
			}
			if metrics["heartbeatIntervalSeconds"] != tt.expected {
				t.Fatalf("heartbeat interval mismatch: got=%#v want=%d", metrics["heartbeatIntervalSeconds"], tt.expected)
			}
		})
	}
}

func TestTrafficCountersFromIncusStateUsesBillableInterfaces(t *testing.T) {
	state := incusInstanceState{
		Network: map[string]incusNetworkDevice{
			"lo": {
				Counters: incusNetworkCounters{
					BytesReceived: "999",
					BytesSent:     "999",
				},
			},
			"eth0": {
				Counters: incusNetworkCounters{
					BytesReceived: "100",
					BytesSent:     "200",
				},
			},
			"docker0": {
				Counters: incusNetworkCounters{
					BytesReceived: "300",
					BytesSent:     "400",
				},
			},
		},
	}

	counters := getTrafficCountersFromIncusState("vm-test", state)
	if counters.rx != 100 || counters.tx != 200 {
		t.Fatalf("traffic counters mismatch: got=%+v", counters)
	}
}

func TestTrafficCountersFromIncusStateFallsBackToExternalInterfaces(t *testing.T) {
	state := incusInstanceState{
		Network: map[string]incusNetworkDevice{
			"lo": {
				Counters: incusNetworkCounters{
					BytesReceived: "999",
					BytesSent:     "999",
				},
			},
			"enp5s0": {
				Counters: incusNetworkCounters{
					BytesReceived: "123",
					BytesSent:     "456",
				},
			},
		},
	}

	counters := getTrafficCountersFromIncusState("vm-test", state)
	if counters.rx != 123 || counters.tx != 456 {
		t.Fatalf("traffic counters mismatch: got=%+v", counters)
	}
}

func TestTrafficCountersFromIncusStateIncludesMixedExternalInterfaces(t *testing.T) {
	state := incusInstanceState{
		Network: map[string]incusNetworkDevice{
			"eth0": {
				Counters: incusNetworkCounters{BytesReceived: "100", BytesSent: "200"},
			},
			// A second Incus NIC may be reported using its guest OS name. This
			// interface carries IPv6 traffic on dual-stack NAT nodes.
			"enp6s0": {
				Counters: incusNetworkCounters{BytesReceived: "300", BytesSent: "400"},
			},
			"docker0": {
				Counters: incusNetworkCounters{BytesReceived: "500", BytesSent: "600"},
			},
		},
	}

	counters := getTrafficCountersFromIncusState("vm-test", state)
	if counters.rx != 400 || counters.tx != 600 {
		t.Fatalf("mixed-interface traffic counters mismatch: got=%+v", counters)
	}
}

func TestFirstRoutableAddressesRejectsIPv6ULA(t *testing.T) {
	state := map[string]incusNetworkDevice{
		"eth0": {
			Addresses: []incusNetworkAddress{
				{Family: "inet", Address: "10.10.1.93"},
				{Family: "inet6", Address: "fd42:5c4:22dd:5a99::1"},
			},
		},
		"eth1": {
			Addresses: []incusNetworkAddress{
				{Family: "inet6", Address: "2607:9d00:2000:39::1234"},
			},
		},
	}

	ipv4, ipv6 := firstRoutableAddresses(state)
	if ipv4 != "10.10.1.93" {
		t.Fatalf("IPv4 mismatch: got=%q", ipv4)
	}
	if ipv6 != "2607:9d00:2000:39::1234" {
		t.Fatalf("public IPv6 mismatch: got=%q", ipv6)
	}
}

func containsCapability(capabilities []any, expected string) bool {
	for _, capability := range capabilities {
		if capability == expected {
			return true
		}
	}
	return false
}
