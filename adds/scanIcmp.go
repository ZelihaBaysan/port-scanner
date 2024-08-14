package adds

import (
	"fmt"
	"net"
	"time"
)

// ScanICMP scans an IP address using ICMP to determine its reachability.
//
// Parameters:
// - ip: The IP address to scan.
//
// Returns:
// - string: The reachability status of the IP address, which can be "Reachable" or "Unreachable".
//
// The function sends an ICMP echo request and waits for a response. If a response is received within the timeout period,
// the IP address is considered "Reachable". If no response is received, the IP address is considered "Unreachable".
func ScanICMP(ip string) string {
	timeout := 5 * time.Second
	conn, err := net.DialTimeout("ip4:icmp", ip, timeout)
	if err != nil {
		return "Unreachable"
	}
	conn.Close()
	return "Reachable"
}

// WorkerICMP scans IP addresses for ICMP reachability.
//
// Parameters:
// - ips: A channel that provides IP addresses to scan.
// - results: A channel to send the reachability status of IP addresses.
// - done: A channel to signal when the worker has finished processing all IP addresses.
//
// The function retrieves IP addresses from the `ips` channel, scans each IP address using `ScanICMP`, and sends the results
// to the `results` channel. After processing all IP addresses, it signals completion by sending a value to the `done` channel.
func WorkerICMP(ips <-chan string, results chan<- string, done chan<- bool) {
	for ip := range ips {
		state := ScanICMP(ip)
		results <- fmt.Sprintf("IP: %s, Response: %s", ip, state)
		fmt.Printf("IP: %s, Response: %s\n", ip, state)
	}
	done <- true
}
