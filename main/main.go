package main

import (
	"VpnBlack/internal"
	"encoding/json"
	"fmt"
	"github.com/songgao/water"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os/exec"
	"sync"
)

type AuthPacket struct {
	Type  string `json:"type"`
	Token string `json:"token"`
	Data  []byte `json:"data,omitempty"`
}

type ClientInfo struct {
	Addr     *net.UDPAddr
	Username string
}

type WorkerPool struct {
	tasks chan func()
}

func NewWorkerPool(numWorkers int, bufferSize int) *WorkerPool {
	wp := &WorkerPool{
		tasks: make(chan func(), bufferSize),
	}
	for i := 0; i < numWorkers; i++ {
		go wp.worker()
	}
	return wp
}

func (wp *WorkerPool) worker() {
	for task := range wp.tasks {
		task()
	}
}

func (wp *WorkerPool) Submit(task func()) {
	wp.tasks <- task
}

type VPNServer struct {
	cryptoMgr         *internal.CryptoManager
	tunnelManager     *internal.TunnelManager
	tunInterface      *water.Interface
	udpConn           *net.UDPConn
	clients           sync.Map
	authorizedClients sync.Map
	config            internal.TunnelConfig
	workerPool        *WorkerPool
}

func NewVPNServer() (*VPNServer, error) {
	cryptoMgr, err := internal.NewCryptoManager(
		"32-char-key-for-AES-256-GCM-exam",
		"AES-256-GCM",
		"SHA256",
	)
	if err != nil {
		return nil, fmt.Errorf("crypto manager init error: %v", err)
	}

	config := internal.TunnelConfig{
		LocalIP:  "10.0.0.1",
		RemoteIP: "0.0.0.0",
		Port:     5555,
		Protocol: "udp",
		Cipher:   "AES-256-GCM",
		Auth:     "SHA256",
		Key:      "32-char-key-for-AES-256-GCM-exam",
	}

	tunnelManager := internal.NewTunnelManager(cryptoMgr)
	err = tunnelManager.Initialize(config)
	if err != nil {
		return nil, fmt.Errorf("tunnel manager init error: %v", err)
	}

	// Создаем пул воркеров с 10 рабочими и буфером на 1000 задач
	workerPool := NewWorkerPool(10, 1000)

	return &VPNServer{
		cryptoMgr:         cryptoMgr,
		tunnelManager:     tunnelManager,
		config:            config,
		clients:           sync.Map{},
		authorizedClients: sync.Map{},
		workerPool:        workerPool,
	}, nil
}

func (s *VPNServer) initTunInterface() error {
	tunConfig := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "utun6",
		},
	}
	iface, err := water.New(tunConfig)
	if err != nil {
		return fmt.Errorf("tun interface creation error: %v", err)
	}
	s.tunInterface = iface

	cmds := [][]string{
		{"ifconfig", iface.Name(), "10.0.0.1", "10.0.0.2", "up"},
		{"route", "-n", "add", "-net", "10.0.0.0/24", "-interface", iface.Name()},
		{"sysctl", "-w", "net.inet.ip.forwarding=1"},
		{"pfctl", "-e"},
		{"echo", "'nat on en0 from 10.0.0.0/24 to any -> (en0)' | pfctl -f -"},
	}

	for _, cmdArgs := range cmds {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: command %v error: %v", cmdArgs, err)
		}
	}

	log.Printf("TUN interface created: %s", iface.Name())
	return nil
}

func (s *VPNServer) initUDPServer() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		return fmt.Errorf("resolve udp addr error: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("udp listen error: %v", err)
	}
	s.udpConn = conn
	log.Printf("UDP Server started on port %d", s.config.Port)
	return nil
}

func (s *VPNServer) handleIncomingPackets() {
	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		// Копируем данные, чтобы избежать перезаписи буфера
		dataCopy := make([]byte, n)
		copy(dataCopy, buffer[:n])

		// Проверяем, является ли это пакетом авторизации
		var authPacket AuthPacket
		if err := json.Unmarshal(dataCopy, &authPacket); err == nil && authPacket.Type == "auth" {
			log.Printf("Processing auth packet from %s", clientAddr)
			claims, err := internal.ValidateJWTToken(authPacket.Token)
			if err != nil {
				log.Printf("Invalid token from %s: %v", clientAddr, err)
				response := AuthPacket{
					Type:  "auth_response",
					Token: "failed",
				}
				responseData, _ := json.Marshal(response)
				_, err := s.udpConn.WriteToUDP(responseData, clientAddr)
				if err != nil {
					log.Printf("Failed to send auth failure response to %s: %v", clientAddr, err)
				}
				continue
			}

			// Сохраняем информацию о клиенте
			clientInfo := &ClientInfo{
				Addr:     clientAddr,
				Username: claims.Username,
			}
			s.authorizedClients.Store(clientAddr.String(), claims.Username)
			s.clients.Store(clientAddr.String(), clientInfo)

			response := AuthPacket{
				Type:  "auth_response",
				Token: "success",
			}
			responseData, _ := json.Marshal(response)
			_, err = s.udpConn.WriteToUDP(responseData, clientAddr)
			if err != nil {
				log.Printf("Failed to send auth success response to %s: %v", clientAddr, err)
			} else {
				log.Printf("Client authenticated: %s (%s)", clientAddr, claims.Username)
			}
			continue
		}

		// Проверяем авторизацию клиента
		username, authorized := s.authorizedClients.Load(clientAddr.String())
		if !authorized {
			log.Printf("Unauthorized client: %s", clientAddr)
			continue
		}

		// Отправляем задачу в пул воркеров
		s.workerPool.Submit(func() {
			s.processClientPacket(clientAddr, dataCopy, username.(string))
		})
	}
}

func (s *VPNServer) processClientPacket(clientAddr *net.UDPAddr, data []byte, username string) {
	decrypted, err := s.cryptoMgr.Decrypt(data)
	if err != nil {
		log.Printf("Decryption error from %s: %v", clientAddr, err)
		return
	}

	if len(decrypted) < 20 {
		log.Printf("Packet too small from %s", clientAddr)
		return
	}

	version := decrypted[0] >> 4
	if version != 4 {
		log.Printf("Not an IPv4 packet from %s (version: %d)", clientAddr, version)
		return
	}

	_, err = s.tunInterface.Write(decrypted)
	if err != nil {
		log.Printf("Write to TUN error: %v", err)
	}
}

func (s *VPNServer) routeTunnelTraffic() {
	buffer := make([]byte, 4096)
	for {
		n, err := s.tunInterface.Read(buffer)
		if err != nil {
			log.Printf("Read from TUN error: %v", err)
			continue
		}

		if !isValidPacket(buffer[:n]) {
			continue
		}

		encrypted, err := s.cryptoMgr.Encrypt(buffer[:n])
		if err != nil {
			log.Printf("Encryption error: %v", err)
			continue
		}

		// Отправляем данные всем клиентам (можно оптимизировать маршрутизацию по IP)
		s.clients.Range(func(key, value interface{}) bool {
			clientInfo := value.(*ClientInfo)
			_, err = s.udpConn.WriteToUDP(encrypted, clientInfo.Addr)
			if err != nil {
				log.Printf("Write to %s error: %v", clientInfo.Addr, err)
			} else {
				log.Printf("Sent %d bytes to %s", len(encrypted), clientInfo.Addr)
			}
			return true
		})
	}
}

func isValidPacket(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	return (packet[0] >> 4) == 4
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	go internal.StartAPIServer()

	server, err := NewVPNServer()
	if err != nil {
		log.Fatalf("Server initialization error: %v", err)
	}

	err = server.initTunInterface()
	if err != nil {
		log.Fatalf("TUN interface error: %v", err)
	}
	defer server.tunInterface.Close()

	err = server.initUDPServer()
	if err != nil {
		log.Fatalf("UDP server error: %v", err)
	}
	defer server.udpConn.Close()

	go server.handleIncomingPackets()
	server.routeTunnelTraffic()
}
