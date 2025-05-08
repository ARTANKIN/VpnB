package internal

import (
	"fmt"
	"log"
	"strings"
)

type ProtocolHandler struct {
	tunnelManager *TunnelManager
	authManager   *AuthManager
}

func NewProtocolHandler(tm *TunnelManager, am *AuthManager) *ProtocolHandler {
	return &ProtocolHandler{
		tunnelManager: tm,
		authManager:   am,
	}
}

func (ph *ProtocolHandler) Start() error {
	dataChan := ph.tunnelManager.GetDataChan()

	go func() {
		for data := range dataChan {
			dataStr := string(data)
			parts := strings.Split(dataStr, "|")
			if len(parts) != 2 {
				log.Printf("Invalid data format: %s", dataStr)
				continue
			}

			username, password := parts[0], parts[1]

			user, err := ph.authManager.Authenticate(username, password)
			if err != nil {
				log.Printf("Auth failed: %v", err)
				continue
			}

			sessionData, err := ph.authManager.CompleteSession(user)
			if err != nil {
				log.Printf("Session error: %v", err)
				continue
			}

			// Исправленная строка - добавляем обработку второго возвращаемого значения
			encryptedData, err := ph.tunnelManager.SendData(sessionData)
			if err != nil {
				log.Printf("Send error: %v", err)
			} else {
				log.Printf("Data encrypted: %x", encryptedData)
			}
		}
	}()

	fmt.Println("ProtocolHandler started")
	return nil
}
