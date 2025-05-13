package main

import (
	"VpnBlack/internal"
	"encoding/binary"
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

type VPNServer struct {
	cryptoMgr         *internal.CryptoManager
	tunnelManager     *internal.TunnelManager
	tunInterface      *water.Interface
	udpConn           *net.UDPConn
	clients           sync.Map
	authorizedClients sync.Map
	config            internal.TunnelConfig
}

func parseIPv4Packet(packet []byte) {
	if len(packet) < 20 {
		log.Println("Packet too short")
		return
	}

	version := packet[0] >> 4
	headerLength := (packet[0] & 0x0F) * 4
	typeOfService := packet[1]
	totalLength := binary.BigEndian.Uint16(packet[2:4])
	identification := binary.BigEndian.Uint16(packet[4:6])
	flags := packet[6] >> 5
	fragmentOffset := binary.BigEndian.Uint16(packet[6:8]) & 0x1FFF
	ttl := packet[8]
	protocol := packet[9]
	headerChecksum := binary.BigEndian.Uint16(packet[10:12])
	sourceIP := net.IP(packet[12:16])
	destIP := net.IP(packet[16:20])

	log.Printf("IPv4 Packet Details:")
	log.Printf("Version: %d", version)
	log.Printf("Header Length: %d bytes", headerLength)
	log.Printf("Type of Service: 0x%02x", typeOfService)
	log.Printf("Total Length: %d", totalLength)
	log.Printf("Identification: %d", identification)
	log.Printf("Flags: 0x%02x", flags)
	log.Printf("Fragment Offset: %d", fragmentOffset)
	log.Printf("TTL: %d", ttl)
	log.Printf("Protocol: %d", protocol)
	log.Printf("Header Checksum: 0x%04x", headerChecksum)
	log.Printf("Source IP: %s", sourceIP)
	log.Printf("Destination IP: %s", destIP)

	switch protocol {
	case 1: // ICMP
		parseICMPPacket(packet[headerLength:])
	case 6: // TCP
		parseTCPPacket(packet[headerLength:])
	case 17: // UDP
		parseUDPPacket(packet[headerLength:])
	default:
		log.Printf("Unknown protocol: %d", protocol)
	}
}

func parseICMPPacket(payload []byte) {
	if len(payload) < 8 {
		log.Println("ICMP packet too short")
		return
	}

	icmpType := payload[0]
	icmpCode := payload[1]
	icmpChecksum := binary.BigEndian.Uint16(payload[2:4])

	log.Printf("ICMP Packet:")
	log.Printf("Type: %d", icmpType)
	log.Printf("Code: %d", icmpCode)
	log.Printf("Checksum: 0x%04x", icmpChecksum)
}

func parseTCPPacket(payload []byte) {
	if len(payload) < 20 {
		log.Println("TCP packet too short")
		return
	}

	sourcePort := binary.BigEndian.Uint16(payload[0:2])
	destPort := binary.BigEndian.Uint16(payload[2:4])
	sequenceNumber := binary.BigEndian.Uint32(payload[4:8])
	acknowledgmentNumber := binary.BigEndian.Uint32(payload[8:12])
	dataOffset := payload[12] >> 4
	flags := payload[13]

	log.Printf("TCP Packet:")
	log.Printf("Source Port: %d", sourcePort)
	log.Printf("Destination Port: %d", destPort)
	log.Printf("Sequence Number: %d", sequenceNumber)
	log.Printf("Acknowledgment Number: %d", acknowledgmentNumber)
	log.Printf("Data Offset: %d bytes", dataOffset*4)
	log.Printf("Flags: 0x%02x", flags)
}

func parseUDPPacket(payload []byte) {
	if len(payload) < 8 {
		log.Println("UDP packet too short")
		return
	}

	sourcePort := binary.BigEndian.Uint16(payload[0:2])
	destPort := binary.BigEndian.Uint16(payload[2:4])
	length := binary.BigEndian.Uint16(payload[4:6])
	checksum := binary.BigEndian.Uint16(payload[6:8])

	log.Printf("UDP Packet:")
	log.Printf("Source Port: %d", sourcePort)
	log.Printf("Destination Port: %d", destPort)
	log.Printf("Length: %d", length)
	log.Printf("Checksum: 0x%04x", checksum)
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

	return &VPNServer{
		cryptoMgr:         cryptoMgr,
		tunnelManager:     tunnelManager,
		config:            config,
		clients:           sync.Map{},
		authorizedClients: sync.Map{},
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

func (s *VPNServer) extractTokenFromPacket(data []byte) (string, []byte, error) {
	var authPacket AuthPacket
	err := json.Unmarshal(data, &authPacket)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse auth packet: %v", err)
	}
	return authPacket.Token, authPacket.Data, nil
}
func (s *VPNServer) handleIncomingPackets() {
	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}
		//log.Printf("Received data from %s, length: %d, raw: %s", clientAddr.String(), n, string(buffer[:n]))

		// Attempt to parse as JSON auth packet
		var authPacket AuthPacket
		if err := json.Unmarshal(buffer[:n], &authPacket); err == nil && authPacket.Type == "auth" {
			log.Printf("Processing auth packet from %s, token: %s", clientAddr, authPacket.Token)
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

			s.authorizedClients.Store(clientAddr.String(), claims.Username)
			s.clients.Store(clientAddr.String(), clientAddr)

			response := AuthPacket{
				Type:  "auth_response",
				Token: "success",
			}
			responseData, _ := json.Marshal(response)
			_, err = s.udpConn.WriteToUDP(responseData, clientAddr)
			if err != nil {
				log.Printf("Failed to send auth success response to %s: %v", clientAddr, err)
			} else {
				log.Printf("Sent auth success response to %s", clientAddr)
			}

			log.Printf("Client authenticated: %s (%s)", clientAddr, claims.Username)
			continue
		}

		// Check if client is authorized
		username, authorized := s.authorizedClients.Load(clientAddr.String())
		if !authorized {
			log.Printf("Unauthorized client: %s", clientAddr)
			continue
		}

		go s.processClientPacket(clientAddr, buffer[:n], username.(string))
	}
}

func (s *VPNServer) processClientPacket(clientAddr *net.UDPAddr, data []byte, username string) {
	decrypted, err := s.cryptoMgr.Decrypt(data)
	if err != nil {
		log.Printf("Decryption error from %s: %v", clientAddr, err)
		return
	}

	// Проверка на минимальный размер IPv4 пакета
	if len(decrypted) < 20 {
		log.Printf("Packet too small from %s", clientAddr)
		return
	}

	// Проверка версии IP
	version := decrypted[0] >> 4
	if version != 4 {
		log.Printf("Not an IPv4 packet from %s (version: %d)", clientAddr, version)
		return
	}

	_, err = s.tunInterface.Write(decrypted)
	if err != nil {
		log.Printf("Write to TUN error: %v", err)
		return
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

		s.clients.Range(func(key, value interface{}) bool {
			clientAddr := value.(*net.UDPAddr)
			_, err = s.udpConn.WriteToUDP(encrypted, clientAddr)
			if err != nil {
				log.Printf("Write to %s error: %v", clientAddr, err)
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
