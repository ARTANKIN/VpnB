package Tests

//
//import (
//	"VpnBlack/internal"
//	"net"
//	"testing"
//	"time"
//)
//
//func TestAuthenticationFlow_Success(t *testing.T) {
//	// Инициализация зависимостей
//	userManager := internal.NewUserManager()
//	userManager.AddUser("testuser", "testpass123")
//
//	authManager := internal.NewAuthManager(userManager)
//	cryptoMgr, _ := internal.NewCryptoManager("supersecretkeysupersecretkeysupe", "AES-256-CBC", "SHA512")
//	tunnelManager := internal.NewTunnelManager(cryptoMgr)
//	protocolHandler := internal.NewProtocolHandler(tunnelManager, authManager)
//
//	// Настройка тестового туннеля
//	config := internal.TunnelConfig{
//		LocalIP:  "127.0.0.1",
//		RemoteIP: "127.0.0.1",
//		Port:     8080,
//		Key:      "supersecretkeysupersecretkeysupe",
//		Protocol: "tcp",
//		Cipher:   "AES-256-CBC",
//		Auth:     "SHA512",
//	}
//
//	err := tunnelManager.Initialize(config)
//	if err != nil {
//		t.Fatalf("Tunnel initialization failed: %v", err)
//	}
//
//	// Создаем тестовый TCP-сервер с обработкой аутентификации
//	ln, err := net.Listen("tcp", "127.0.0.1:8080")
//	if err != nil {
//		t.Fatalf("Failed to start test server: %v", err)
//	}
//	defer ln.Close()
//
//	serverReady := make(chan struct{})
//	go func() {
//		close(serverReady)
//		conn, err := ln.Accept()
//		if err != nil {
//			t.Logf("Failed to accept connection: %v", err)
//			return
//		}
//		defer conn.Close()
//
//		// Чтение данных
//		buf := make([]byte, 1024)
//		n, err := conn.Read(buf)
//		if err != nil {
//			t.Logf("Read error: %v", err)
//			return
//		}
//
//		// Дешифруем данные
//		decrypted, err := cryptoMgr.DecryptCBC(buf[:n])
//		if err != nil {
//			t.Logf("Decryption error: %v", err)
//			return
//		}
//
//		// Проверяем учетные данные
//		if string(decrypted) == "testuser|testpass123" {
//			// Генерируем и отправляем токен сессии
//			sessionToken := []byte("SESSION-TOKEN-testuser")
//			encryptedResponse, err := cryptoMgr.EncryptCBC(sessionToken)
//			if err != nil {
//				t.Logf("Encryption error: %v", err)
//				return
//			}
//			_, err = conn.Write(encryptedResponse)
//			if err != nil {
//				t.Logf("Write error: %v", err)
//			}
//		} else {
//			// Отправляем ошибку аутентификации
//			errorMsg := []byte("AUTH-ERROR")
//			encryptedError, err := cryptoMgr.EncryptCBC(errorMsg)
//			if err != nil {
//				t.Logf("Encryption error: %v", err)
//				return
//			}
//			_, err = conn.Write(encryptedError)
//			if err != nil {
//				t.Logf("Write error: %v", err)
//			}
//		}
//	}()
//
//	<-serverReady
//	time.Sleep(100 * time.Millisecond)
//
//	// Запуск компонентов
//	err = tunnelManager.Start()
//	if err != nil {
//		t.Fatalf("Tunnel start failed: %v", err)
//	}
//
//	err = protocolHandler.Start()
//	if err != nil {
//		t.Fatalf("Protocol handler start failed: %v", err)
//	}
//
//	// ОТПРАВКА ДАННЫХ
//	testPayload := []byte("testuser|testpass123")
//	encryptedData, err := cryptoMgr.EncryptCBC(testPayload)
//	if err != nil {
//		t.Fatalf("Encryption failed: %v", err)
//	}
//
//	err = tunnelManager.SendData(encryptedData)
//	if err != nil {
//		t.Fatalf("Data sending failed: %v", err)
//	}
//
//	// Проверка ответа
//	select {
//	case response := <-tunnelManager.GetDataChan():
//		decryptedResponse, err := cryptoMgr.DecryptCBC(response)
//		if err != nil {
//			t.Fatalf("Decryption failed: %v", err)
//		}
//
//		expected := "SESSION-TOKEN-testuser"
//		if string(decryptedResponse) != expected {
//			t.Errorf("Expected %s, got %s", expected, string(decryptedResponse))
//		}
//	case <-time.After(2 * time.Second):
//		t.Fatal("Response timeout")
//	}
//}
//
//func TestAuthenticationFlow_InvalidCredentials(t *testing.T) {
//	userManager := internal.NewUserManager()
//	userManager.AddUser("validuser", "validpass")
//
//	authManager := internal.NewAuthManager(userManager)
//	cryptoMgr, _ := internal.NewCryptoManager("32byte_test_key_1234567890abcdef", "AES-256-CBC", "SHA512")
//	tunnelManager := internal.NewTunnelManager(cryptoMgr)
//	protocolHandler := internal.NewProtocolHandler(tunnelManager, authManager)
//
//	config := internal.TunnelConfig{
//		Protocol: "tcp",
//		LocalIP:  "127.0.0.1",
//		RemoteIP: "127.0.0.1",
//		Port:     8080,
//		Key:      "32byte_test_key_1234567890abcdef",
//		Cipher:   "AES-256-CBC",
//		Auth:     "SHA512",
//	}
//
//	tunnelManager.Initialize(config)
//	tunnelManager.Start()
//	protocolHandler.Start()
//
//	// Отправка неверных данных
//	invalidData, _ := cryptoMgr.Encrypt([]byte("validuser|wrongpass"))
//	tunnelManager.SendData(invalidData)
//
//	select {
//	case response := <-tunnelManager.GetDataChan():
//		t.Errorf("Unexpected response for invalid credentials: %s", response)
//	case <-time.After(500 * time.Millisecond):
//		// Ожидаемое отсутствие ответа
//	}
//}
//
//func TestAuthenticationFlow_InvalidDataFormat(t *testing.T) {
//	userManager := internal.NewUserManager()
//	authManager := internal.NewAuthManager(userManager)
//	cryptoMgr, _ := internal.NewCryptoManager("16byte_test_key!", "AES-128-CBC", "SHA256")
//	tunnelManager := internal.NewTunnelManager(cryptoMgr)
//	protocolHandler := internal.NewProtocolHandler(tunnelManager, authManager)
//
//	config := internal.TunnelConfig{
//		Protocol: "tcp",
//		LocalIP:  "127.0.0.1",
//		RemoteIP: "127.0.0.1",
//		Port:     8080,
//		Key:      "16byte_test_key!",
//		Cipher:   "AES-128-CBC",
//		Auth:     "SHA256",
//	}
//
//	tunnelManager.Initialize(config)
//	tunnelManager.Start()
//	protocolHandler.Start()
//
//	// Отправка данных в неправильном формате
//	invalidData, _ := cryptoMgr.Encrypt([]byte("invalid_format_data"))
//	tunnelManager.SendData(invalidData)
//
//	select {
//	case response := <-tunnelManager.GetDataChan():
//		t.Errorf("Unexpected response for invalid format: %s", response)
//	case <-time.After(500 * time.Millisecond):
//		// Ожидаемое отсутствие ответа
//	}
//}
