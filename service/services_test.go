package service

import (
	"testing"
)

func TestDetectService(t *testing.T) {
	services := map[int]string{
		1:  "tcpmux",
		7:  "echo",
		11: "systat",
	}

	tests := []struct {
		port         int
		expectedSvc  string
		expectedResp string
	}{
		{1, "tcpmux", "Service Detected"},
		{7, "echo", "Service Detected"},
		{11, "systat", "Service Detected"},
		{49151, "Unknown", "Service Not Detected"},
	}

	for _, test := range tests {
		svcVersion := DetectService(test.port, services)
		if svcVersion.Service != test.expectedSvc {
			t.Errorf("Port %d: Expected service %s, got %s", test.port, test.expectedSvc, svcVersion.Service)
		}
		if svcVersion.Response != test.expectedResp {
			t.Errorf("Port %d: Expected response %s, got %s", test.port, test.expectedResp, svcVersion.Response)
		}
	}
}
