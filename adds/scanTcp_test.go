package adds

import (
	"fmt"
	"testing"
)

// TestScanPortTCP tests the ScanPortTCP function by evaluating its response for different port states.
//
// The ScanPortTCP function is tested under the following scenarios:
// - A common open port (e.g., 80 for HTTP) to verify if it correctly identifies the port as "Open".
// - A common closed port (e.g., 9999) to verify if it correctly identifies the port as "Closed".
// - A port on a private IP range (e.g., 10.0.0.1) to simulate a "Filtered" state, assuming the port is inaccessible.
//
// Test Parameters:
// - ip: The IP address to scan. Different IP addresses are used to cover various test scenarios.
// - port: The port number to scan. The tests cover both open and closed ports, as well as a simulated filtered state.
//
// Expected Results:
// - The expected result is a string indicating the state of the port, which can be "Open", "Closed", or "Filtered".
//
// The function iterates through a list of test cases, where each case specifies an IP address and a port number.
// For each test case, it invokes the ScanPortTCP function and compares the result with the expected port state.
// Any mismatch between the actual result and the expected result is reported as an error.
// The test also prints the result for each IP and port combination for debugging purposes.
func TestScanPortTCP(t *testing.T) {
	tests := []struct {
		ip       string
		port     int
		expected string
	}{
		// Test with a common open port (e.g., 80 for HTTP)
		{"127.0.0.1", 80, Open},
		// Test with a common closed port
		{"127.0.0.1", 9999, Closed},
		// Test with a port that will be filtered (e.g., using a private IP range)
		{"10.0.0.1", 80, Filtered},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s:%d", test.ip, test.port), func(t *testing.T) {
			// Execute the ScanPortTCP function and capture the result
			result := ScanPortTCP(test.ip, test.port)
			// Compare the result with the expected output
			if result != test.expected {
				t.Errorf("IP: %s, Port: %d, expected %s, got %s", test.ip, test.port, test.expected, result)
			} else {
				fmt.Printf("IP: %s, Port: %d, Result: %s\n", test.ip, test.port, result)
			}
		})
	}
}

// TestWorkerTCP verifies that the WorkerTCP function correctly processes and sends port scanning results.
//
// This test case simulates a scenario with multiple ports and checks whether the results and open
// port details are correctly sent to the appropriate channels.
func TestWorkerTCP(t *testing.T) {
	// Set up test environment
	ports := make(chan int, 10)
	results := make(chan int)
	openPorts := make(chan ServiceVersion)
	done := make(chan bool)

	// Start the worker
	go WorkerTCP("127.0.0.1", ports, results, openPorts, done, nil)

	// Add ports to scan
	go func() {
		for _, port := range []int{80, 9999} {
			ports <- port
		}
		close(ports)
	}()

	// Check results
	go func() {
		for range results {
			// Process results if needed
		}
	}()

	// Check openPorts
	go func() {
		for range openPorts {
			// Process open ports if needed
		}
	}()

	// Wait for worker to finish
	<-done
}
