package Tests

import (
	"VpnBlack/internal"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNetworkHandler(t *testing.T) {
	// Create a test tunnel
	tunnel := internal.NewEchoTunnel(100)

	// Create NetworkHandler
	handler, err := internal.NewNetworkHandler(":8080", ":8081", tunnel, 20)
	if err != nil {
		t.Fatalf("Failed to create NetworkHandler: %v", err)
	}

	// Start the handler
	handler.Start()
	defer func() {
		handler.Stop()
		time.Sleep(100 * time.Millisecond) // Give time for cleanup
	}()

	// Give time for servers to start
	time.Sleep(100 * time.Millisecond)

	//Test TCP connection
	t.Run("TCP Connection", func(t *testing.T) {
		conn, err := net.Dial("tcp", "localhost:8080")
		if err != nil {
			t.Fatalf("Failed to connect to TCP server: %v", err)
		}
		defer conn.Close()

		// Send data
		testData := []byte("test TCP data\n")
		_, err = conn.Write(testData)
		if err != nil {
			t.Fatalf("Failed to send data to TCP server: %v", err)
		}
		log.Printf("Sent TCP data: %s", string(testData))

		// Read response
		response := make([]byte, 1024)
		n, err := conn.Read(response)
		if err != nil {
			t.Fatalf("Failed to read response from TCP server: %v", err)
		}
		log.Printf("Received TCP response: %s", string(response[:n]))

		// Verify response
		if string(response[:n]) != string(testData) {
			t.Errorf("Expected response %q, got %q", string(testData), string(response[:n]))
		}
	})

	// Test UDP packet
	t.Run("UDP Packet", func(t *testing.T) {
		conn, err := net.Dial("udp", "localhost:8081")
		if err != nil {
			t.Fatalf("Failed to connect to UDP server: %v", err)
		}
		defer conn.Close()

		// Send data
		testData := []byte("test UDP data")
		_, err = conn.Write(testData)
		if err != nil {
			t.Fatalf("Failed to send data to UDP server: %v", err)
		}
		log.Printf("Sent UDP data: %s", string(testData))

		// Read response
		response := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second)) // Increase timeout
		n, err := conn.Read(response)
		if err != nil {
			t.Fatalf("Failed to read response from UDP server: %v", err)
		}
		log.Printf("Received UDP response: %s", string(response[:n]))

		// Verify response
		if string(response[:n]) != string(testData) {
			t.Errorf("Expected response %q, got %q", string(testData), string(response[:n]))
		}
	})

	t.Run("Concurrent TCP Connections", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				conn, err := net.Dial("tcp", "localhost:8080")
				if err != nil {
					t.Errorf("Goroutine %d: Failed to connect to TCP server: %v", i, err)
					return
				}
				defer conn.Close()

				// Set timeouts
				conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

				testData := []byte("test TCP data\n")
				_, err = conn.Write(testData)
				if err != nil {
					t.Errorf("Goroutine %d: Failed to send data to TCP server: %v", i, err)
					return
				}
				log.Printf("Sent TCP data: %s", string(testData))

				response := make([]byte, 1024)
				n, err := conn.Read(response)
				log.Printf("Received TCP response: %s", string(response[:n]))
				if err != nil {
					t.Errorf("Goroutine %d: Failed to read response from TCP server: %v", i, err)
					return
				}

				if string(response[:n]) != string(testData) {
					t.Errorf("Goroutine %d: Expected response %q, got %q", i, string(testData), string(response[:n]))
				}
			}(i)
		}
		wg.Wait()
	})
}
