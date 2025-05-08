package main

import (
	"VpnBlack/internal"
	"fmt"
	"log"
	"net"
	"github.com/songgao/water"
)

//
//import (
//	"VpnBlack/internal"
//	"fmt"
//	"log"
//	"net"
//	"time"
//)
//
//func main() {
//	// Инициализация CryptoManager
//	cryptoMgr, err := internal.NewCryptoManager(
//		"32-char-key-for-AES-256-GCM-exam",
//		"AES-256-GCM",
//		"SHA256",
//	)
//	if err != nil {
//		log.Fatal("CryptoManager error:", err)
//	}
//
//	// Конфигурация туннеля
//	config := internal.TunnelConfig{
//		RemoteIP: "0.0.0.0",
//		Port:     5555,
//		Protocol: "udp",
//		Cipher:   "AES-256-GCM",
//		Auth:     "SHA256",
//		Key:      "32-char-key-for-AES-256-GCM-example",
//	}
//
//	// Инициализация менеджеров
//	tunnelManager := internal.NewTunnelManager(cryptoMgr)
//	tunnelManager.Initialize(config)
//
//	// Запуск UDP сервера
//	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", config.Port))
//	conn, err := net.ListenUDP("udp", addr)
//	if err != nil {
//		log.Fatal("Listen error:", err)
//	}
//	defer conn.Close()
//
//	fmt.Println("Server started on port", config.Port)
//
//	buffer := make([]byte, 4096)
//	for {
//		n, clientAddr, err := conn.ReadFromUDP(buffer)
//		if err != nil {
//			log.Println("Read error:", err)
//			continue
//		}
//
//		go handleClient(conn, clientAddr, buffer[:n], tunnelManager)
//	}
//}
//
//func handleClient(conn *net.UDPConn, addr *net.UDPAddr, data []byte, tm *internal.TunnelManager) {
//	// Дешифровка данных
//	decrypted, err := tm.CryptoMgr.Decrypt(data)
//	if err != nil {
//		log.Println("Decryption error:", err)
//		return
//	}
//
//	log.Printf("Received from %s: %s\n", addr.String(), string(decrypted))
//
//	// Формирование ответа
//	response := fmt.Sprintf("ACK: %s | %s", time.Now().Format(time.RFC3339), string(decrypted))
//
//	// Шифровка ответа
//	encrypted, err := tm.CryptoMgr.Encrypt([]byte(response))
//	if err != nil {
//		log.Println("Encryption error:", err)
//		return
//	}
//
//	// Отправка ответа
//	_, err = conn.WriteToUDP(encrypted, addr)
//	if err != nil {
//		log.Println("Write error:", err)
//		return
//	}
//
//	log.Printf("Sent to %s: %s\n", addr.String(), response)
//}

package main

import (
	"fmt"
	"log"
	"net"
	"github.com/songgao/water"
	"internal" // Ваш пакет
)

func main() {
	// Инициализация CryptoManager
	cryptoMgr, err := internal.NewCryptoManager(
		"32-char-key-for-AES-256-GCM-exam",
		"AES-256-GCM",
		"SHA256",
	)
	if err != nil {
		log.Fatal("CryptoManager error:", err)
	}

	// Конфигурация туннеля
	config := internal.TunnelConfig{
		RemoteIP: "0.0.0.0",
		Port:     5555,
		Protocol: "udp",
		Cipher:   "AES-256-GCM",
		Auth:     "SHA256",
		Key:      "32-char-key-for-AES-256-GCM-exam",
	}

	// Инициализация TunnelManager
	tunnelManager := internal.NewTunnelManager(cryptoMgr)
	tunnelManager.Initialize(config)

	// Создание TUN-интерфейса
	tunConfig := water.Config{
		DeviceType: water.TUN,
	}
	tunIface, err := water.New(tunConfig)
	if err != nil {
		log.Fatal("TUN interface error:", err)
	}
	defer tunIface.Close()

	// Настройка IP для TUN-интерфейса (требуется системная команда)
	// Например: exec.Command("ifconfig", tunIface.Name(), "10.0.0.1/24", "up").Run()
	log.Printf("TUN interface created: %s", tunIface.Name())

	// Включение IP-форвардинга (требуется на сервере)
	// Например: exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// Запуск UDP-сервера
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", config.Port))
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal("Listen error:", err)
	}
	defer conn.Close()

	fmt.Println("Server started on port", config.Port)

	// Запуск маршрутизации ответов из TUN
	go routeTraffic(tunIface, conn)

	// Обработка входящих данных от клиентов
	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Read error:", err)
			continue
		}
		go handleClient(conn, clientAddr, buffer[:n], cryptoMgr, tunIface)
	}
}

func handleClient(conn *net.UDPConn, addr *net.UDPAddr, data []byte, cryptoMgr *internal.CryptoManager, tunIface *water.Interface) {
	// Дешифровка данных
	decrypted, err := cryptoMgr.Decrypt(data)
	if err != nil {
		log.Println("Decryption error:", err)
		return
	}

	// Запись пакета в TUN-интерфейс (маршрутизация в интернет)
	_, err = tunIface.Write(decrypted)
	if err != nil {
		log.Println("Write to TUN error:", err)
	}
}

func routeTraffic(tunIface *water.Interface, conn *net.UDPConn) {
	buffer := make([]byte, 4096)
	for {
		n, err := tunIface.Read(buffer)
		if err != nil {
			log.Println("Read from TUN error:", err)
			continue
		}

		// Шифрование данных перед отправкой клиенту
		encrypted, err := cryptoMgr.Encrypt(buffer[:n])
		if err != nil {
			log.Println("Encryption error:", err)
			continue
		}

		// Отправка данных клиенту
		// Здесь нужно хранить адреса клиентов (например, в map)
		// Для простоты предполагаем одного клиента
		clientAddr, _ := net.ResolveUDPAddr("udp", "client_ip:client_port") // Замените на реальный адрес
		_, err = conn.WriteToUDP(encrypted, clientAddr)
		if err != nil {
			log.Println("Write to client error:", err)
		}
	}
}