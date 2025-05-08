package internal

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"
)

// LoadBalancer реализует интерфейс Tunnel и распределяет нагрузку между серверами
type LoadBalancer struct {
	servers     []*Server
	serverMutex sync.Mutex
}

// Server представляет собой сервер, на который можно перенаправлять соединения
type Server struct {
	addr      string
	conn      net.Conn
	available bool
}

// NewLoadBalancer создает новый LoadBalancer
func NewLoadBalancer(serverAddrs []string) (*LoadBalancer, error) {
	lb := &LoadBalancer{
		servers: make([]*Server, len(serverAddrs)),
	}

	for i, addr := range serverAddrs {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to server %s: %v", addr, err)
		}

		lb.servers[i] = &Server{
			addr:      addr,
			conn:      conn,
			available: true,
		}
	}

	return lb, nil
}

// Send отправляет данные на доступный сервер
func (lb *LoadBalancer) Send(data []byte) {
	server := lb.getAvailableServer()
	if server == nil {
		log.Println("No available servers")
		return
	}

	_, err := server.conn.Write(data)
	if err != nil {
		log.Printf("Failed to send data to server %s: %v", server.addr, err)
		server.available = false
	}
}

// Receive получает данные от сервера
func (lb *LoadBalancer) Receive() ([]byte, error) {
	server := lb.getAvailableServer()
	if server == nil {
		return nil, fmt.Errorf("no available servers")
	}

	reader := bufio.NewReader(server.conn)
	data, err := reader.ReadBytes('\n')
	if err != nil {
		log.Printf("Failed to receive data from server %s: %v", server.addr, err)
		server.available = false
		return nil, err
	}

	return data, nil
}

// getAvailableServer возвращает доступный сервер
func (lb *LoadBalancer) getAvailableServer() *Server {
	lb.serverMutex.Lock()
	defer lb.serverMutex.Unlock()

	for _, server := range lb.servers {
		if server.available {
			return server
		}
	}

	return nil
}
