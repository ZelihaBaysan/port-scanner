package main

import (
	"fmt"
	"net"
	"os"
	"port/adds"
)

// PortScanner defines a structure for scanning ports on a given domain.
//
// This structure encapsulates all the necessary fields and channels needed
// to perform a comprehensive scan on a domain's IP addresses across TCP, UDP, and ICMP protocols.
//
// Fields:
// - Domain: The domain name to be scanned.
// - IPs: A slice of IP addresses associated with the domain, resolved using DNS lookup.
// - Ports: A slice of all port numbers to be scanned, ranging from 1 to 65535.
// - NumWorkers: The number of worker goroutines that will perform the scanning concurrently.
// - PortChannel: A buffered channel for sending port numbers to be scanned by the workers.
// - ResultChannel: A buffered channel for receiving scan results from the workers.
// - OpenPorts: A buffered channel for collecting information about open TCP ports and their corresponding service versions.
// - OpenPortsUDP: A buffered channel for collecting information about open UDP ports and their corresponding service versions.
// - ICMPResults: A buffered channel for collecting results from ICMP (ping) scans, indicating IP reachability.
// - Done: A channel used by worker goroutines to signal when they have completed their tasks.
// - Services: A map that associates port numbers with human-readable service names (e.g., HTTP for port 80).
type PortScanner struct {
	Domain        string
	IPs           []string
	Ports         []int
	NumWorkers    int
	PortChannel   chan int
	ResultChannel chan int
	OpenPorts     chan adds.ServiceVersion
	OpenPortsUDP  chan adds.ServiceVersion
	ICMPResults   chan string
	Done          chan bool
	Services      map[int]string
}

// NewTarget initializes a new PortScanner instance for a specified domain.
//
// This function is responsible for resolving the given domain to its associated
// IP addresses using a DNS lookup. It also initializes all necessary fields and channels
// for scanning, including the list of ports to be scanned and the number of worker goroutines.
//
// Parameters:
// - domain: The domain name to be scanned.
// - numWorkers: The number of concurrent worker goroutines to use for scanning.
//
// Returns:
// - A pointer to a PortScanner instance configured for the specified domain.
// - An error if the domain could not be resolved to any IP addresses.
//
// Example:
//
//	scanner, err := NewTarget("example.com", 100)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewTarget(domain string, numWorkers int) (*PortScanner, error) {
	// Perform DNS lookup to resolve the domain into a list of IP addresses
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}

	// Initialize a slice to hold all port numbers from 1 to 65535
	ports := make([]int, 0, 65535)
	for port := 1; port <= 65535; port++ {
		ports = append(ports, port)
	}

	// Create and return a new PortScanner instance with initialized channels and fields
	return &PortScanner{
		Domain:        domain,
		IPs:           ips,
		Ports:         ports,
		NumWorkers:    numWorkers,
		PortChannel:   make(chan int, len(ports)),
		ResultChannel: make(chan int, len(ports)),
		OpenPorts:     make(chan adds.ServiceVersion, len(ports)),
		OpenPortsUDP:  make(chan adds.ServiceVersion, len(ports)),
		ICMPResults:   make(chan string, len(ips)),
		Done:          make(chan bool, numWorkers*2+len(ips)),
		Services:      make(map[int]string),
	}, nil
}

// Scan initiates the port scanning process on the IP addresses associated with the domain.
//
// This method launches worker goroutines for scanning TCP, UDP, and ICMP. It distributes
// ports and IP addresses among the workers, waits for them to complete their tasks, and then
// collects the results. Finally, it writes the results to an output file.
//
// The method involves several key steps:
// 1. Launching TCP, UDP, and ICMP worker goroutines.
// 2. Enqueueing all ports into the PortChannel for the workers to process.
// 3. Sending IP addresses to the ICMP workers via the IP channel.
// 4. Waiting for all scanning tasks to be completed.
// 5. Writing the results of open TCP/UDP ports and ICMP reachability to an output file.
func (t *PortScanner) Scan() {
	// Create a channel for distributing IP addresses to ICMP workers
	ipChannel := make(chan string, len(t.IPs))

	// Start the specified number of worker goroutines for TCP and UDP scanning
	for i := 0; i < t.NumWorkers; i++ {
		go adds.WorkerTCP("", t.PortChannel, t.ResultChannel, t.OpenPorts, t.Done, t.Services)
		go adds.WorkerUDP("", t.PortChannel, t.ResultChannel, t.OpenPortsUDP, t.Done, t.Services)
	}

	// Start a worker goroutine for each IP address for ICMP scanning
	for i := 0; i < len(t.IPs); i++ {
		go adds.WorkerICMP(ipChannel, t.ICMPResults, t.Done)
	}

	// Enqueue all ports to the PortChannel for the TCP and UDP workers
	for _, port := range t.Ports {
		fmt.Printf("Enqueueing port %d\n", port)
		t.PortChannel <- port
	}
	close(t.PortChannel) // Close the PortChannel after enqueueing all ports

	// Send all resolved IP addresses to the IP channel for the ICMP workers
	for _, ip := range t.IPs {
		ipChannel <- ip
	}
	close(ipChannel) // Close the IP channel after sending all IP addresses

	// Wait for the TCP and UDP results
	for range t.Ports {
		<-t.ResultChannel
	}

	// Wait for all worker goroutines to finish their tasks
	doneCount := 0
	for doneCount < t.NumWorkers*2+len(t.IPs) {
		<-t.Done
		doneCount++
	}

	// Close the result channels after all workers are done
	close(t.OpenPorts)
	close(t.OpenPortsUDP)
	close(t.ICMPResults)

	// Write the collected scan results to an output file
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Printf("Error creating file: %s\n", err)
		return
	}
	defer file.Close()

	// Write open TCP ports and their services to the output file
	_, err = file.WriteString("Open TCP Ports with Services:\n")
	if err != nil {
		fmt.Printf("Error writing to file: %s\n", err)
		return
	}
	for service := range t.OpenPorts {
		_, err = file.WriteString(fmt.Sprintf("Port %d (TCP) is Open, Service: %s\n", service.Port, service.Service))
		if err != nil {
			fmt.Printf("Error writing to file: %s\n", err)
			return
		}
	}

	// Write open UDP ports and their services to the output file
	_, err = file.WriteString("Open UDP Ports with Services:\n")
	if err != nil {
		fmt.Printf("Error writing to file: %s\n", err)
		return
	}
	for service := range t.OpenPortsUDP {
		_, err = file.WriteString(fmt.Sprintf("Port %d (UDP) is Open, Service: %s\n", service.Port, service.Service))
		if err != nil {
			fmt.Printf("Error writing to file: %s\n", err)
			return
		}
	}

	// Write ICMP reachability results to the output file
	_, err = file.WriteString("ICMP Reachability Results:\n")
	if err != nil {
		fmt.Printf("Error writing to file: %s\n", err)
		return
	}
	for result := range t.ICMPResults {
		_, err = file.WriteString(fmt.Sprintf("%s\n", result))
		if err != nil {
			fmt.Printf("Error writing to file: %s\n", err)
			return
		}
	}
}

// main is the entry point of the application.
//
// This function prompts the user to enter a domain name. It then creates a
// PortScanner instance configured for that domain and starts the port scanning process.
//
// The domain entered by the user is resolved to IP addresses, and the Scan method
// is called to perform the actual scanning. Results are written to an output file
// after the scan is completed.
func main() {
	var domain string
	fmt.Print("Enter domain: ")
	fmt.Scanln(&domain)

	// Create a new PortScanner instance with 100 worker goroutines
	target, err := NewTarget(domain, 100)
	if err != nil {
		fmt.Printf("Error resolving domain: %s\n", err)
		return
	}

	// Start the scanning process
	target.Scan()
}
