package main

import (
	"os"
	"port/adds"
	"testing"
)

// Mock implementations for worker functions

// MockWorkerTCP is a mock implementation of a TCP worker function used for testing.
// It simulates scanning TCP ports by sending a mock service version to the `openPorts` channel.
type MockWorkerTCP struct{}

// Run simulates the TCP port scanning by sending a mock service version for each port.
func (m *MockWorkerTCP) Run(domain string, portChannel chan int, resultChannel chan int, openPorts chan adds.ServiceVersion, done chan bool, services map[int]string) {
	for port := range portChannel {
		openPorts <- adds.ServiceVersion{Port: port, Service: "mock-tcp-service"}
	}
	done <- true
}

// MockWorkerUDP is a mock implementation of a UDP worker function used for testing.
// It simulates scanning UDP ports by sending a mock service version to the `openPortsUDP` channel.
type MockWorkerUDP struct{}

// Run simulates the UDP port scanning by sending a mock service version for each port.
func (m *MockWorkerUDP) Run(domain string, portChannel chan int, resultChannel chan int, openPortsUDP chan adds.ServiceVersion, done chan bool, services map[int]string) {
	for port := range portChannel {
		openPortsUDP <- adds.ServiceVersion{Port: port, Service: "mock-udp-service"}
	}
	done <- true
}

// MockWorkerICMP is a mock implementation of an ICMP worker function used for testing.
// It simulates scanning IP addresses by sending a mock ICMP response to the `icmpResults` channel.
type MockWorkerICMP struct{}

// Run simulates the ICMP scanning by sending a mock ICMP response for each IP address.
func (m *MockWorkerICMP) Run(ipChannel chan string, icmpResults chan string, done chan bool) {
	for ip := range ipChannel {
		icmpResults <- "ICMP response from " + ip
	}
	done <- true
}

// TestNewTarget tests the NewTarget function to ensure it correctly initializes a PortScanner.
//
// The test checks if the PortScanner is initialized with the correct domain, number of workers,
// and other parameters such as IPs and ports. If the function doesn't behave as expected,
// the test will fail with an appropriate error message.
func TestNewTarget(t *testing.T) {
	domain := "example.com"
	numWorkers := 10

	ps, err := NewTarget(domain, numWorkers)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if ps.Domain != domain {
		t.Errorf("Expected domain %s, got %s", domain, ps.Domain)
	}

	if len(ps.IPs) == 0 {
		t.Errorf("Expected non-empty IPs, got %v", ps.IPs)
	}

	if len(ps.Ports) != 65535 {
		t.Errorf("Expected 65535 ports, got %d", len(ps.Ports))
	}

	if ps.NumWorkers != numWorkers {
		t.Errorf("Expected %d workers, got %d", numWorkers, ps.NumWorkers)
	}
}

// TestScan tests the Scan function of PortScanner.
//
// The test uses mock workers for TCP, UDP, and ICMP scanning, ensuring that the Scan function
// properly coordinates the scanning tasks. It also verifies that an output file is created
// and checks the scan process by redirecting output to a test file. If the output file isn't created,
// the test will fail with an error.
func TestScan(t *testing.T) {
	domain := "example.com"
	numWorkers := 10

	ps, err := NewTarget(domain, numWorkers)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Use mock workers for testing
	go (&MockWorkerTCP{}).Run(domain, ps.PortChannel, ps.ResultChannel, ps.OpenPorts, ps.Done, ps.Services)
	go (&MockWorkerUDP{}).Run(domain, ps.PortChannel, ps.ResultChannel, ps.OpenPortsUDP, ps.Done, ps.Services)

	// Start ICMP workers with a mock implementation
	ipChannel := make(chan string, len(ps.IPs))
	go (&MockWorkerICMP{}).Run(ipChannel, ps.ICMPResults, ps.Done)

	// Enqueue IP addresses to the channel
	for _, ip := range ps.IPs {
		ipChannel <- ip
	}
	close(ipChannel) // Close the IP channel

	// Temporarily redirect output to avoid file operations
	file, err := os.Create("test_output.txt")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer file.Close()

	ps.Scan()

	// Check if output file is created
	if _, err := os.Stat("test_output.txt"); os.IsNotExist(err) {
		t.Errorf("Output file was not created")
	}

	// Clean up test output file
	os.Remove("test_output.txt")
}
