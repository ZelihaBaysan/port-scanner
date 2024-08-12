package adds

import (
	"fmt"
	"testing"
)

// TestScanPortUDP tests the ScanPortUDP function by evaluating its response for different UDP port states.
//
// The ScanPortUDP function is tested under the following scenarios:
// - A common open UDP port (e.g., 53 for DNS) to verify if it correctly identifies the port as "Open".
// - A common closed UDP port (e.g., 9999) to verify if it correctly identifies the port as "Closed".
// - A port on a private IP range (e.g., 10.0.0.1) to simulate a "Filtered" state, assuming the port is inaccessible.
//
// Note: UDP testing can be less predictable than TCP, and results may vary depending on network configuration and firewall settings.
//
// Test Parameters:
// - ip: The IP address to scan. Different IP addresses are used to cover various test scenarios.
// - port: The port number to scan. The tests cover both open and closed ports, as well as a simulated filtered state.
//
// Expected Results:
// - The expected result is a string indicating the state of the port, which can be "Open", "Closed", or "Filtered".
//
// The function iterates through a list of test cases, where each case specifies an IP address and a port number.
// For each test case, it invokes the ScanPortUDP function and compares the result with the expected port state.
// Any mismatch between the actual result and the expected result is reported as an error.
// The test also prints the result for each IP and port combination for debugging purposes.
func TestScanPortUDP(t *testing.T) {
	tests := []struct {
		ip       string
		port     int
		expected string
	}{
		// Test with a common open UDP port (e.g., 53 for DNS)
		{"127.0.0.1", 53, Open},
		// Test with a common closed UDP port
		{"127.0.0.1", 9999, Closed},
		// Test with a port that will be filtered (e.g., using a private IP range)
		{"192.168.1.1", 53, Filtered}, // Changed to a typical private IP
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s:%d", test.ip, test.port), func(t *testing.T) {
			// Execute the ScanPortUDP function and capture the result
			result := ScanPortUDP(test.ip, test.port)
			// Compare the result with the expected output
			if result != test.expected {
				t.Errorf("IP: %s, Port: %d, expected %s, got %s", test.ip, test.port, test.expected, result)
			} else {
				fmt.Printf("IP: %s, Port: %d, Result: %s\n", test.ip, test.port, result)
			}
		})
	}
}

// TestWorkerUDP verifies that the WorkerUDP function correctly processes and sends port scanning results.
//
// This test case simulates a scenario with multiple ports and checks whether the results and open
// port details are correctly sent to the appropriate channels.
func TestWorkerUDP(t *testing.T) {
	ip := "127.0.0.1"
	ports := make(chan int, 3)
	results := make(chan int, 3)
	openPorts := make(chan ServiceVersion, 3)
	done := make(chan bool)
	services := map[int]string{
		53: "DNS",
	}

	go WorkerUDP(ip, ports, results, openPorts, done, services)

	// Send ports to scan
	ports <- 53
	ports <- 9999
	close(ports)

	// Wait for worker to finish
	<-done

	// Check results channel
	expectedResults := []int{53, 9999}
	for i := 0; i < len(expectedResults); i++ {
		result := <-results
		if result != expectedResults[i] {
			t.Errorf("Expected port %d, but got %d", expectedResults[i], result)
		}
	}

	// Check openPorts channel
	expectedOpenPorts := []ServiceVersion{
		{Port: 53, Protocol: "Unknown", Service: "DNS", Response: "Service Detected"},
	}
	for i := 0; i < len(expectedOpenPorts); i++ {
		openPort := <-openPorts
		if openPort != expectedOpenPorts[i] {
			t.Errorf("Expected open port %+v, but got %+v", expectedOpenPorts[i], openPort)
		}
	}
}
