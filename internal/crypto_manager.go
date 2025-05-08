package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// CryptoManager управляет шифрованием и дешифрованием данных
type CryptoManager struct {
	Key    []byte // Ключ для шифрования/дешифрования
	Cipher string // Алгоритм шифрования
	Auth   string // Алгоритм аутентификации
}

// pkcs7Pad дополняет данные до размера, кратного размеру блока
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad удаляет дополнение из данных
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("данные пусты")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("неверное дополнение")
	}
	return data[:length-padding], nil
}

// NewCryptoManager создает новый экземпляр CryptoManager
func NewCryptoManager(key, cipher, auth string) (*CryptoManager, error) {
	keyLen := len(key)
	switch cipher {
	case "AES-128-CBC", "AES-128-GCM":
		if keyLen != 16 {
			return nil, fmt.Errorf("ключ должен быть длиной 16 байт для %s", cipher)
		}
	case "AES-192-CBC", "AES-192-GCM":
		if keyLen != 24 {
			return nil, fmt.Errorf("ключ должен быть длиной 24 байта для %s", cipher)
		}
	case "AES-256-CBC", "AES-256-GCM":
		if keyLen != 32 {
			return nil, fmt.Errorf("ключ должен быть длиной 32 байта для %s", cipher, keyLen)
		}
	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм шифрования: %s", cipher)
	}

	return &CryptoManager{Key: []byte(key), Cipher: cipher, Auth: auth}, nil
}

// Encrypt шифрует данные
func (cm *CryptoManager) Encrypt(data []byte) ([]byte, error) {
	switch cm.Cipher {
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return cm.EncryptCBC(data)
	case "AES-128-GCM", "AES-192-GCM", "AES-256-GCM":
		return cm.encryptGCM(data)
	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм шифрования: %s", cm.Cipher)
	}
}

func (cm *CryptoManager) Decrypt(ciphertext []byte) ([]byte, error) {
	switch cm.Cipher {
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return cm.DecryptCBC(ciphertext)
	case "AES-128-GCM", "AES-192-GCM", "AES-256-GCM":
		return cm.decryptGCM(ciphertext)
	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм шифрования: %s", cm.Cipher)
	}
}

func (cm *CryptoManager) EncryptCBC(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(cm.Key)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания шифра: %v", err)
	}

	// Дополняем данные до размера блока
	data = pkcs7Pad(data, aes.BlockSize)

	// Создаем буфер для хранения зашифрованных данных
	ciphertext := make([]byte, aes.BlockSize+len(data))

	// Генерируем случайный IV (Initialization Vector)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("ошибка генерации IV: %v", err)
	}

	// Шифруем данные
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func (cm *CryptoManager) DecryptCBC(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(cm.Key)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания шифра: %v", err)
	}

	// Проверяем, что длина данных достаточна для IV
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("длина зашифрованных данных меньше размера блока")
	}

	// Извлекаем IV из начала данных
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Дешифруем данные
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Удаляем дополнение
	plaintext, err := pkcs7Unpad(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ошибка удаления дополнения: %v", err)
	}

	return plaintext, nil
}

// encryptGCM шифрует данные с использованием режима GCM
func (cm *CryptoManager) encryptGCM(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(cm.Key)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания шифра: %v", err)
	}

	// Создаем GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}

	// Генерируем случайный nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ошибка генерации nonce: %v", err)
	}

	// Шифруем данные
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

// decryptGCM дешифрует данные с использованием режима GCM
func (cm *CryptoManager) decryptGCM(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(cm.Key)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания шифра: %v", err)
	}

	// Создаем GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}

	// Проверяем, что длина данных достаточна для nonce
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("длина зашифрованных данных меньше размера nonce")
	}

	// Извлекаем nonce из начала данных
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Дешифруем данные
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка дешифрования: %v", err)
	}

	return plaintext, nil
}

// EncryptBase64 шифрует данные и возвращает их в формате base64
func (cm *CryptoManager) EncryptBase64(data []byte) (string, error) {
	encrypted, err := cm.Encrypt(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptBase64 дешифрует данные из формата base64
func (cm *CryptoManager) DecryptBase64(data string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования base64: %v", err)
	}
	return cm.Decrypt(encrypted)
}

// Hash вычисляет хэш данных с использованием указанного алгоритма аутентификации
func (cm *CryptoManager) Hash(data []byte) ([]byte, error) {
	switch cm.Auth {
	case "SHA1":
		hash := sha1.Sum(data)
		return hash[:], nil
	case "SHA256":
		hash := sha256.Sum256(data)
		return hash[:], nil
	case "SHA512":
		hash := sha512.Sum512(data)
		return hash[:], nil
	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм аутентификации: %s", cm.Auth)
	}
}
