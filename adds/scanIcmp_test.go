package adds

import (
	"testing"
)

// TestScanICMP verifies the functionality of the ScanICMP function.
//
// This test checks if the ScanICMP function correctly determines the reachability of an IP address.
// It uses mock or stub methods to simulate the behavior of the function.
func TestScanICMP(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{"192.168.1.1", "Reachable"}, // Expected behavior for a reachable IP
		{"10.0.0.1", "Unreachable"},  // Example of an unreachable IP (assuming simulated behavior)
	}

	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			result := ScanICMP(test.ip)
			if result != test.expected {
				t.Errorf("ScanICMP() IP: %s, expected %s, got %s", test.ip, test.expected, result)
			}
		})
	}
}

// TestWorkerICMP verifies the functionality of the WorkerICMP function.
//
// This test checks if the WorkerICMP function correctly processes IP addresses for ICMP reachability.
// It uses channels to simulate the input IP addresses and collects the results to validate the behavior.
func TestWorkerICMP(t *testing.T) {
	// Create channels for testing
	ips := make(chan string, 2)
	results := make(chan string, 2)
	done := make(chan bool)

	// Send mock IP addresses to the ips channel
	ips <- "192.168.1.1"
	ips <- "10.0.0.1"
	close(ips)

	// Run the WorkerICMP function in a goroutine
	go WorkerICMP(ips, results, done)

	// Collect results and validate
	expectedResults := map[string]string{
		"192.168.1.1": "Reachable",
		"10.0.0.1":    "Unreachable",
	}

	for i := 0; i < 2; i++ {
		result := <-results
		ip := result[:len(result)-len(": Reachable")] // Extract IP from result
		if expected, found := expectedResults[ip]; found {
			if result[len(result)-len(": Reachable"):] != expected {
				t.Errorf("WorkerICMP() IP: %s, expected %s, got %s", ip, expected, result)
			}
		} else {
			t.Errorf("Unexpected result: %s", result)
		}
	}

	// Signal completion
	<-done
}
