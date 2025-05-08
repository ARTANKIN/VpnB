package internal

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// Tunnel represents an interface for sending and receiving data through a tunnel
type Tunnel interface {
	Send(data []byte)         // Send data to the tunnel
	Receive() ([]byte, error) // Receive data from the tunnel
}

// NetworkHandler handles incoming TCP and UDP connections
type NetworkHandler struct {
	tcpListener net.Listener
	udpConn     *net.UDPConn
	tunnel      Tunnel
	wg          sync.WaitGroup
	workerPool  chan struct{} // Empty structs to limit the number of workers
	stopChan    chan struct{} // Channel to signal goroutines to stop
}

// NewNetworkHandler creates a new NetworkHandler
func NewNetworkHandler(tcpAddr, udpAddr string, tunnel Tunnel, maxWorkers int) (*NetworkHandler, error) {
	// Create TCP listener
	tcpListener, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listener: %v", err)
	}

	// Create UDP connection
	udpAddrParsed, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddrParsed)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}

	return &NetworkHandler{
		tcpListener: tcpListener,
		udpConn:     udpConn,
		tunnel:      tunnel,
		workerPool:  make(chan struct{}, maxWorkers), // Limit the number of workers
		stopChan:    make(chan struct{}),
	}, nil
}

// Start starts handling incoming connections
func (nh *NetworkHandler) Start() {
	nh.wg.Add(2)
	go nh.handleTCPConnections()
	go nh.handleUDPPackets()
}

// Stop stops handling incoming connections
func (nh *NetworkHandler) Stop() {
	close(nh.stopChan) // Signal goroutines to stop
	nh.tcpListener.Close()
	nh.udpConn.Close()
	nh.wg.Wait()
}

// handleTCPConnections handles incoming TCP connections
func (nh *NetworkHandler) handleTCPConnections() {
	defer nh.wg.Done()

	for {
		conn, err := nh.tcpListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("TCP listener closed, exiting goroutine")
				return
			}
			log.Printf("Failed to accept TCP connection: %v", err)
			continue
		}

		// Limit the number of concurrent workers
		nh.workerPool <- struct{}{}
		nh.wg.Add(1)
		go func() {
			defer func() {
				<-nh.workerPool // Release the slot in the pool
				nh.wg.Done()
			}()
			nh.handleTCPConnection(conn)
		}()
	}
}

// handleTCPConnection handles a single TCP connection
func (nh *NetworkHandler) handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	// Увеличиваем таймауты
	//conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	//conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	for {
		data, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Println("Client closed the connection")
				return
			}
			log.Printf("Failed to read data from TCP connection: %v", err)
			return
		}

		// Отправляем данные в туннель
		nh.tunnel.Send(data)

		// Получаем ответ от туннеля
		response, err := nh.tunnel.Receive()
		if err != nil {
			log.Printf("Failed to receive data from tunnel: %v", err)
			return
		}

		// Отправляем ответ клиенту
		_, err = conn.Write(response)
		if err != nil {
			log.Printf("Failed to send response to client: %v", err)
			return
		}
	}
}

// handleUDPPackets handles incoming UDP packets
func (nh *NetworkHandler) handleUDPPackets() {
	defer nh.wg.Done()

	buffer := make([]byte, 4096)
	for {
		n, addr, err := nh.udpConn.ReadFromUDP(buffer)
		if err != nil {
			// Check if the connection was closed
			if errors.Is(err, net.ErrClosed) {
				log.Println("UDP connection closed, exiting goroutine")
				return
			}
			log.Printf("Failed to read data from UDP connection: %v", err)
			continue
		}

		data := buffer[:n]
		log.Printf("Received UDP packet from %s: %s", addr, string(data))

		// Limit the number of concurrent workers
		nh.workerPool <- struct{}{}
		nh.wg.Add(1)
		go nh.handleUDPPacket(data, addr)
	}
}

// handleUDPPacket handles a single UDP packet
func (nh *NetworkHandler) handleUDPPacket(data []byte, addr *net.UDPAddr) {
	defer func() {
		<-nh.workerPool // Release the slot in the pool
		nh.wg.Done()
	}()

	// Send data to the tunnel
	nh.tunnel.Send(data)

	// Receive data from the tunnel
	response, err := nh.tunnel.Receive()
	if err != nil {
		log.Printf("Failed to receive data from tunnel: %v", err)
		return
	}

	// Send response back to the client
	_, err = nh.udpConn.WriteToUDP(response, addr)
	if err != nil {
		log.Printf("Failed to send response to client: %v", err)
	}
}
