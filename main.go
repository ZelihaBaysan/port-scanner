package main

import (
	"det/service"
	"fmt"
	"net"
	"os"
	"time"
)

// ScanPortTCP scans a TCP port on a given IP address to determine its state.
//
// Parameters:
// - ip: The IP address to scan.
// - port: The TCP port to scan.
//
// Returns:
// - A string indicating the state of the port: "Open" or "Closed".
//
// Example:
//
//	state := ScanPortTCP("192.168.1.1", 80)
func ScanPortTCP(ip string, port int) string {
	address := fmt.Sprintf("%s:%d", ip, port)
	timeout := 10 * time.Second
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "Closed"
	}
	conn.Close()
	return "Open"
}

// ScanPortUDP scans a UDP port on a given IP address to determine its state.
//
// Parameters:
// - port: The UDP port to scan.
// - domain: The domain or IP address to scan.
//
// Returns:
// - An error if the scan fails, otherwise nil.
//
// Example:
//
//	err := scanUDP(53, "example.com")
func ScanUDP(port int, domain string) error {
	address := fmt.Sprintf("%s:%d", domain, port)
	conn, err := net.DialTimeout("udp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send a custom message
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		return err
	}

	// Set a deadline for reading a response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return err
	}

	return nil
}

// ScanICMP scans an IP address using ICMP to determine its reachability.
//
// Parameters:
// - ip: The IP address to scan.
//
// Returns:
// - A string indicating whether the IP is "Reachable" or "Unreachable".
//
// Example:
//
//	state := ScanICMP("192.168.1.1")
func ScanICMP(ip string) string {
	timeout := 5 * time.Second
	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err != nil {
		return "Unreachable"
	}
	conn.Close()
	return "Reachable"
}

// WorkerTCP scans TCP ports and sends results to channels.
//
// Parameters:
// - ip: The IP address to scan.
// - ports: A channel for ports to scan.
// - results: A channel to send the scan results to.
// - openPorts: A channel to send open port information to.
// - done: A channel to signal the completion of the work.
// - services: A map of known services.
//
// Example:
//
//	go WorkerTCP("192.168.1.1", ports, results, openPorts, done, services)
func WorkerTCP(ip string, ports, results chan int, openPorts chan service.ServiceVersion, done chan bool, services map[int]string) {
	for port := range ports {
		state := ScanPortTCP(ip, port)
		service := service.DetectService(port, services)
		results <- port
		if state == "Open" {
			openPorts <- service
		}
		fmt.Printf("Port %d: %s, Service: %s, Response: %s\n", port, state, service.Service, service.Response)
	}
	done <- true
}

// WorkerUDP scans UDP ports and sends results to channels.
//
// Parameters:
// - domain: The domain or IP address to scan.
// - ports: A channel for ports to scan.
// - results: A channel to send the scan results to.
// - openPorts: A channel to send open port information to.
// - done: A channel to signal the completion of the work.
// - services: A map of known services.
//
// Example:
//
//	go WorkerUDP("example.com", ports, results, openPorts, done, services)
func WorkerUDP(domain string, ports, results chan int, openPorts chan service.ServiceVersion, done chan bool, services map[int]string) {
	for port := range ports {
		err := ScanUDP(port, domain)
		state := "Closed"
		if err == nil {
			state = "Open"
			service := service.DetectService(port, services)
			openPorts <- service
		}
		results <- port
		fmt.Printf("Port %d (UDP): %s\n", port, state)
	}
	done <- true
}

// WorkerICMP scans IP addresses for ICMP reachability.
//
// Parameters:
// - ips: A channel for IP addresses to scan.
// - results: A channel to send the scan results to.
// - done: A channel to signal the completion of the work.
//
// Example:
//
//	go WorkerICMP(ips, results, done)
func WorkerICMP(ips <-chan string, results chan<- string, done chan<- bool) {
	for ip := range ips {
		state := ScanICMP(ip)
		results <- fmt.Sprintf("IP: %s, Response: %s", ip, state)
		fmt.Printf("IP: %s, Response: %s\n", ip, state)
	}
	done <- true
}

// PortScanner struct holds details for port scanning.
//
// Fields:
// - Domain: The domain to scan.
// - IPs: A list of resolved IP addresses for the domain.
// - Ports: A list of ports to scan.
// - NumWorkers: The number of worker goroutines to use for scanning.
// - PortChannel: A channel for distributing ports to workers.
// - ResultChannel: A channel for receiving scan results.
// - OpenPorts: A channel for open TCP port information.
// - OpenPortsUDP: A channel for open UDP port information.
// - ICMPResults: A channel for ICMP reachability results.
// - Done: A channel to signal the completion of all workers.
// - Services: A map of known services.
//
// Example:
//
//	scanner := &PortScanner{
//	    Domain:      "example.com",
//	    IPs:         []string{"192.168.1.1"},
//	    Ports:       []int{80, 443},
//	    NumWorkers:  10,
//	    PortChannel: make(chan int),
//	    // ...
//	}
type PortScanner struct {
	Domain        string
	IPs           []string
	Ports         []int
	NumWorkers    int
	PortChannel   chan int
	ResultChannel chan int
	OpenPorts     chan service.ServiceVersion
	OpenPortsUDP  chan service.ServiceVersion
	ICMPResults   chan string
	Done          chan bool
	Services      map[int]string
}

// NewTarget creates a new PortScanner instance with initialized channels and fields.
//
// Parameters:
// - domain: The domain to scan.
// - numWorkers: The number of worker goroutines to use for scanning.
//
// Returns:
// - A pointer to a newly created PortScanner instance.
// - An error if the domain cannot be resolved to an IP address.
//
// Example:
//
//	scanner, err := NewTarget("example.com", 100)
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
		OpenPorts:     make(chan service.ServiceVersion, len(ports)),
		OpenPortsUDP:  make(chan service.ServiceVersion, len(ports)),
		ICMPResults:   make(chan string, len(ips)),
		Done:          make(chan bool, numWorkers*2+len(ips)),
		Services:      service.Services,
	}, nil
}

// Scan performs the port scanning.
//
// Example:
//
//	scanner.Scan()
func (t *PortScanner) Scan() {
	// Create a channel for distributing IP addresses to ICMP workers
	ipChannel := make(chan string, len(t.IPs))

	// Start the specified number of worker goroutines for TCP and UDP scanning
	for i := 0; i < t.NumWorkers; i++ {
		go WorkerTCP("", t.PortChannel, t.ResultChannel, t.OpenPorts, t.Done, t.Services)
		go WorkerUDP("", t.PortChannel, t.ResultChannel, t.OpenPortsUDP, t.Done, t.Services)
	}

	// Start a worker goroutine for each IP address for ICMP scanning
	for i := 0; i < len(t.IPs); i++ {
		go WorkerICMP(ipChannel, t.ICMPResults, t.Done)
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
}

// writeResultsToFile writes the scan results to an output file.
//
// Parameters:
// - t: A pointer to the PortScanner instance containing the results.
// - fileName: The name of the output file to write the results to.
//
// Returns:
// - An error if writing to the file fails, otherwise nil.
//
// Example:
//
//	err := writeResultsToFile(target, "output.txt")
func writeResultsToFile(t *PortScanner, fileName string) error {
	// Write the collected scan results to an output file
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("error creating file: %s", err)
	}
	defer file.Close()

	// Write open TCP ports and their services to the output file
	_, err = file.WriteString("Open TCP Ports with Services:\n")
	if err != nil {
		return fmt.Errorf("error writing to file: %s", err)
	}
	for service := range t.OpenPorts {
		_, err = file.WriteString(fmt.Sprintf("Port %d (TCP) is Open, Service: %s\n", service.Port, service.Service))
		if err != nil {
			return fmt.Errorf("error writing to file: %s", err)
		}
	}

	// Write open UDP ports and their services to the output file
	_, err = file.WriteString("Open UDP Ports with Services:\n")
	if err != nil {
		return fmt.Errorf("error writing to file: %s", err)
	}
	for service := range t.OpenPortsUDP {
		_, err = file.WriteString(fmt.Sprintf("Port %d (UDP) is Open, Service: %s\n", service.Port, service.Service))
		if err != nil {
			return fmt.Errorf("error writing to file: %s", err)
		}
	}

	// Write ICMP reachability results to the output file
	_, err = file.WriteString("ICMP Reachability Results:\n")
	if err != nil {
		return fmt.Errorf("error writing to file: %s", err)
	}
	for result := range t.ICMPResults {
		_, err = file.WriteString(fmt.Sprintf("%s\n", result))
		if err != nil {
			return fmt.Errorf("error writing to file: %s", err)
		}
	}

	return nil
}

// main function is the entry point of the program.
// It prompts the user for a domain, performs port scanning,
// and writes the results to an output file.
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

	// Write the results to a file
	err = writeResultsToFile(target, "output.txt")
	if err != nil {
		fmt.Printf("Error writing results to file: %s\n", err)
	}
}
