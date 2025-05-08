package internal

import (
	"errors"
	"sync"
)

// EchoTunnel - тестовый туннель, который возвращает полученные данные обратно
type EchoTunnel struct {
	mu      sync.Mutex
	cond    *sync.Cond
	queue   [][]byte
	maxSize int
	closed  bool
}

// NewEchoTunnel создает новый EchoTunnel с ограничением на размер очереди
func NewEchoTunnel(maxSize int) *EchoTunnel {
	et := &EchoTunnel{
		maxSize: maxSize,
	}
	et.cond = sync.NewCond(&et.mu)
	return et
}

// Send отправляет данные в туннель
func (et *EchoTunnel) Send(data []byte) {
	et.mu.Lock()
	defer et.mu.Unlock()

	// Ожидаем, пока в очереди не появится место
	for len(et.queue) >= et.maxSize && !et.closed {
		et.cond.Wait()
	}

	// Проверяем, закрыт ли туннель
	if et.closed {
		return
	}

	// Добавляем данные в очередь
	et.queue = append(et.queue, data)

	// Уведомляем одну ожидающую горутину
	et.cond.Signal()
}

// Receive получает данные из туннеля с таймаутом
func (et *EchoTunnel) Receive() ([]byte, error) {
	et.mu.Lock()
	defer et.mu.Unlock()

	// Ожидаем, пока в очереди не появятся данные
	for len(et.queue) == 0 && !et.closed {
		et.cond.Wait()
	}

	// Проверяем, закрыт ли туннель
	if et.closed {
		return nil, errors.New("tunnel is closed")
	}

	// Извлекаем данные из очереди
	data := et.queue[0]
	et.queue = et.queue[1:]

	// Уведомляем одну ожидающую горутину (если очередь была полной)
	et.cond.Signal()
	return data, nil
}

// Close закрывает туннель и уведомляет все ожидающие горутины
func (et *EchoTunnel) Close() {
	et.mu.Lock()
	defer et.mu.Unlock()
	et.closed = true
	et.cond.Broadcast() // Уведомляем все ожидающие горутины
}
