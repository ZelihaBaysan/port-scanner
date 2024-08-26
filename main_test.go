package main

import (
	"det/service"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestScanPortTCP(t *testing.T) {
	state := ScanPortTCP("localhost", 80)
	if state != "Open" {
		t.Errorf("Expected Open, got %s", state)
	}

	state = ScanPortTCP("localhost", 9999)
	if state != "Closed" {
		t.Errorf("Expected Closed, got %s", state)
	}
}

func TestScanUDP(t *testing.T) {
	err := scanUDP(53, "localhost")
	if err != nil {
		t.Errorf("Expected nil, got error %v", err)
	}

	err = scanUDP(9999, "localhost")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestScanICMP(t *testing.T) {
	state := ScanICMP("127.0.0.1")
	if state != "Reachable" {
		t.Errorf("Expected Reachable, got %s", state)
	}

	state = ScanICMP("192.0.2.1")
	if state != "Unreachable" {
		t.Errorf("Expected Unreachable, got %s", state)
	}
}

func TestWorkerTCP(t *testing.T) {
	ports := make(chan int, 1)
	results := make(chan int, 1)
	openPorts := make(chan service.ServiceVersion, 1)
	done := make(chan bool, 1)
	services := map[int]string{
		80: "HTTP",
	}

	go WorkerTCP("localhost", ports, results, openPorts, done, services)

	ports <- 80
	close(ports)

	select {
	case <-results:
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for results")
	}

	select {
	case openPort := <-openPorts:
		if openPort.Service != "HTTP" {
			t.Errorf("Expected HTTP, got %s", openPort.Service)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for open ports")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for done signal")
	}
}

func TestWorkerUDP(t *testing.T) {
	ports := make(chan int, 1)
	results := make(chan int, 1)
	openPorts := make(chan service.ServiceVersion, 1)
	done := make(chan bool, 1)
	services := map[int]string{
		53: "DNS",
	}

	go WorkerUDP("localhost", ports, results, openPorts, done, services)

	ports <- 53
	close(ports)

	select {
	case <-results:
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for results")
	}

	select {
	case openPort := <-openPorts:
		if openPort.Service != "DNS" {
			t.Errorf("Expected DNS, got %s", openPort.Service)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for open ports")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for done signal")
	}
}

func TestWorkerICMP(t *testing.T) {
	ips := make(chan string, 1)
	results := make(chan string, 1)
	done := make(chan bool, 1)

	go WorkerICMP(ips, results, done)

	ips <- "127.0.0.1"
	close(ips)

	select {
	case result := <-results:
		expected := "IP: 127.0.0.1, Response: Reachable"
		if result != expected {
			t.Errorf("Expected %s, got %s", expected, result)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for results")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for done signal")
	}
}

func TestPortScanner_Scan(t *testing.T) {
	domain := "localhost"
	target, err := NewTarget(domain, 10)
	if err != nil {
		t.Fatalf("Error creating new target: %v", err)
	}

	target.Ports = []int{80, 9999}
	target.Scan()

	file, err := os.Open("output.txt")
	if err != nil {
		t.Fatalf("Error opening output file: %v", err)
	}
	defer file.Close()

	var foundTCP bool
	var service string
	_, err = fmt.Fscanf(file, "Open TCP Ports with Services:\nPort 80 (TCP) is Open, Service: %s\n", &service)
	if err == nil && service == "HTTP" {
		foundTCP = true
	}

	if !foundTCP {
		t.Error("Expected TCP port 80 to be open with HTTP service")
	}
}
