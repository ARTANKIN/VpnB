package internal

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// TunnelConfig содержит конфигурацию туннеля
type TunnelConfig struct {
	LocalIP  string
	RemoteIP string
	Port     int
	Key      string
	Protocol string // "tcp" или "udp"
	Cipher   string // Добавить поле для алгоритма шифрования
	Auth     string // Добавить поле для алгоритма аутентификации
}

// TunnelManager управляет туннелем
type TunnelManager struct {
	config      TunnelConfig
	active      bool
	conn        net.Conn
	udpConn     *net.UDPConn
	reconnectMu sync.Mutex
	stopChan    chan struct{}
	dataChan    chan []byte
	CryptoMgr   *CryptoManager // Использовать указатель
}

// NewTunnelManager создает новый экземпляр TunnelManager
func NewTunnelManager(cryptoMgr *CryptoManager) *TunnelManager {
	return &TunnelManager{
		active:    false,
		stopChan:  make(chan struct{}),
		dataChan:  make(chan []byte, 100),
		CryptoMgr: cryptoMgr, // Передаем созданный cryptoMgr
	}
}

// Initialize инициализирует туннель с заданной конфигурацией
func (tm *TunnelManager) Initialize(config TunnelConfig) error {
	tm.config = config

	// Инициализируем CryptoManager с параметрами из конфигурации
	cryptoMgr, err := NewCryptoManager(config.Key, config.Cipher, config.Auth)
	if err != nil {
		return fmt.Errorf("ошибка инициализации CryptoManager: %v", err)
	}
	tm.CryptoMgr = cryptoMgr

	fmt.Printf("Туннель инициализирован с протоколом %s\n", tm.config.Protocol)
	return nil
}

// Start запускает туннель
func (tm *TunnelManager) Start() error {
	tm.reconnectMu.Lock()
	defer tm.reconnectMu.Unlock()

	if tm.active {
		return fmt.Errorf("tunnel is already active")
	}

	// Устанавливаем соединение в зависимости от протокола
	var err error
	switch tm.config.Protocol {
	case "tcp":
		tm.conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", tm.config.RemoteIP, tm.config.Port))
		if err != nil {
			return fmt.Errorf("не удалось установить TCP соединение: %v", err)
		}
	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", tm.config.RemoteIP, tm.config.Port))
		if err != nil {
			return fmt.Errorf("не удалось разрешить UDP адрес: %v", err)
		}
		tm.udpConn, err = net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return fmt.Errorf("не удалось установить UDP соединение: %v", err)
		}
	default:
		return fmt.Errorf("неподдерживаемый протокол: %s", tm.config.Protocol)
	}

	tm.active = true
	fmt.Println("Туннель запущен")

	// Запускаем мониторинг соединения
	go tm.monitorConnection()

	// Запускаем обработку входящих данных
	go tm.handleIncomingData()

	return nil
}

// Stop останавливает туннель
func (tm *TunnelManager) Stop() error {
	tm.reconnectMu.Lock()
	defer tm.reconnectMu.Unlock()

	if !tm.active {
		return fmt.Errorf("tunnel is not active")
	}

	// Закрываем соединение
	if tm.conn != nil {
		tm.conn.Close()
	}
	if tm.udpConn != nil {
		tm.udpConn.Close()
	}

	// Останавливаем мониторинг соединения
	close(tm.stopChan)
	tm.active = false
	fmt.Println("Туннель остановлен")
	return nil
}

// Restart перезапускает туннель
func (tm *TunnelManager) Restart() error {
	fmt.Println("Перезапуск туннеля...")
	tm.Stop()
	return tm.Start()
}

// IsActive проверяет, активен ли туннель
func (tm *TunnelManager) IsActive() bool {
	return tm.active
}

// monitorConnection отслеживает состояние соединения и восстанавливает его при разрыве
func (tm *TunnelManager) monitorConnection() {
	for {
		select {
		case <-tm.stopChan:
			return
		default:
			time.Sleep(5 * time.Second) // Проверяем соединение каждые 5 секунд

			if !tm.active {
				continue
			}

			// Проверяем состояние соединения
			var isBroken bool
			switch tm.config.Protocol {
			case "tcp":
				if tm.conn == nil {
					isBroken = true
				} else {
					_, err := tm.conn.Write([]byte("ping"))
					if err != nil {
						isBroken = true
					}
				}
			case "udp":
				if tm.udpConn == nil {
					isBroken = true
				} else {
					_, err := tm.udpConn.Write([]byte("ping"))
					if err != nil {
						isBroken = true
					}
				}
			}

			// Если соединение разорвано, пытаемся восстановить
			if isBroken {
				log.Println("Соединение разорвано, попытка восстановления...")
				err := tm.Restart()
				if err != nil {
					log.Printf("Ошибка восстановления соединения: %v", err)
				} else {
					log.Println("Соединение восстановлено")
				}
			}
		}
	}
}

// SendData передает данные через туннель и возвращает зашифрованные данные
func (tm *TunnelManager) SendData(data []byte) ([]byte, error) {
	if !tm.active {
		return nil, fmt.Errorf("tunnel is not active")
	}

	// Шифруем данные
	encryptedData, err := tm.CryptoMgr.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}

	// Отправляем данные в зависимости от протокола
	switch tm.config.Protocol {
	case "tcp":
		_, err = tm.conn.Write(encryptedData)
	case "udp":
		_, err = tm.udpConn.Write(encryptedData)
	default:
		return nil, fmt.Errorf("неподдерживаемый протокол: %s", tm.config.Protocol)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to send data through tunnel: %v", err)
	}

	return encryptedData, nil
}

// ReceiveData получает данные через туннель
func (tm *TunnelManager) ReceiveData() ([]byte, error) {
	if !tm.active {
		return nil, fmt.Errorf("tunnel is not active")
	}

	var buffer []byte
	var err error

	switch tm.config.Protocol {
	case "tcp":
		buffer = make([]byte, 4096)
		n, err := tm.conn.Read(buffer)
		if err != nil {
			return nil, fmt.Errorf("failed to receive TCP data: %v", err)
		}
		buffer = buffer[:n]
	case "udp":
		buffer = make([]byte, 4096)
		n, _, err := tm.udpConn.ReadFromUDP(buffer)
		if err != nil {
			return nil, fmt.Errorf("failed to receive UDP data: %v", err)
		}
		buffer = buffer[:n]
	default:
		return nil, fmt.Errorf("неподдерживаемый протокол: %s", tm.config.Protocol)
	}

	// Дешифруем данные
	decryptedData, err := tm.CryptoMgr.Decrypt(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return decryptedData, nil
}

// handleIncomingData обрабатывает входящие данные
func (tm *TunnelManager) handleIncomingData() {
	for {
		data, err := tm.ReceiveData()
		if err != nil {
			log.Printf("Ошибка получения данных: %v", err)
			continue
		}
		select {
		case tm.dataChan <- data:
		default:
			log.Println("Буфер данных переполнен")
		}
	}
}

// GetDataChan возвращает канал для получения данных
func (tm *TunnelManager) GetDataChan() <-chan []byte {
	return tm.dataChan
}
