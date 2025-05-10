package Tests

import (
	"VpnBlack/internal"
	"bytes"
	"net"
	"testing"
)

func TestEncryptDecryptCBC(t *testing.T) {
	key := "supersecretkeysupersecretkeysupe" // 32 байта для AES-256
	cm, err := internal.NewCryptoManager(key, "AES-256-CBC", "SHA256")
	if err != nil {
		t.Fatalf("Ошибка создания CryptoManager: %v", err)
	}

	data := []byte("test data")

	// Шифруем данные
	encrypted, err := cm.EncryptCBC(data)
	if err != nil {
		t.Fatalf("Ошибка шифрования: %v", err)
	}

	// Дешифруем данные
	decrypted, err := cm.DecryptCBC(encrypted)
	if err != nil {
		t.Fatalf("Ошибка дешифрования: %v", err)
	}

	// Проверяем, что данные совпадают
	if !bytes.Equal(data, decrypted) {
		t.Errorf("Ожидаемые данные: %s, полученные данные: %s", string(data), string(decrypted))
	}
}

func TestTunnelManager_SendReceiveData(t *testing.T) {
	// Создаем CryptoManager с корректными параметрами
	cryptoMgr, err := internal.NewCryptoManager(
		"supersecretkeysupersecretkeysupe",
		"AES-256-CBC",
		"SHA512",
	)
	if err != nil {
		t.Fatalf("Failed to create CryptoManager: %v", err)
	}

	// Создаем TunnelManager с CryptoManager
	tm := internal.NewTunnelManager(cryptoMgr)

	// Конфигурация туннеля
	config := internal.TunnelConfig{
		LocalIP:  "127.0.0.1",
		RemoteIP: "127.0.0.1",
		Port:     8080,
		Key:      "supersecretkeysupersecretkeysupe",
		Protocol: "tcp",
		Cipher:   "AES-256-CBC", // Указываем алгоритм шифрования
		Auth:     "SHA512",      // Указываем алгоритм аутентификации
	}

	// Инициализация туннеля
	err = tm.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Создаем тестовый TCP-сервер для эмуляции удаленного сервера
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer ln.Close()

	// Канал для синхронизации
	serverReady := make(chan struct{})

	// Запускаем горутину для обработки входящих соединений
	go func() {
		close(serverReady) // Сервер готов принимать соединения
		conn, err := ln.Accept()
		if err != nil {
			t.Logf("Failed to accept connection: %v", err)
			return
		}
		defer conn.Close()

		// Читаем данные от клиента
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Logf("Failed to read data: %v", err)
			return
		}

		// Отправляем данные обратно клиенту
		_, err = conn.Write(buf[:n])
		if err != nil {
			t.Logf("Failed to write data: %v", err)
			return
		}
	}()

	// Ожидаем, пока сервер не будет готов принимать соединения
	<-serverReady

	// Запуск туннеля
	err = tm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	testData := []byte("test data")

	// Отправка данных через туннель
	_, err = tm.SendData(testData)
	if err != nil {
		t.Fatalf("SendData failed: %v", err)
	}

	// Получение данных через туннель
	receivedData, err := tm.ReceiveData()
	if err != nil {
		t.Fatalf("ReceiveData failed: %v", err)
	}

	// Проверка, что полученные данные совпадают с отправленными
	if string(receivedData) != string(testData) {
		t.Errorf("Expected received data %s, got %s", string(testData), string(receivedData))
	}

	// Остановка туннеля
	err = tm.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}
