package Tests

import (
	"VpnBlack/internal"
	"testing"
)

func TestCryptoManager_EncryptDecrypt(t *testing.T) {
	key := "1234567890123456"
	cipher := "AES-128-CBC"
	auth := "SHA256"

	cm, err := internal.NewCryptoManager(key, cipher, auth)
	if err != nil {
		t.Errorf("NewCryptoManager failed: %v", err)
	}

	data := []byte("test data")

	encrypted, err := cm.Encrypt(data)
	if err != nil {
		t.Errorf("Encrypt failed: %v", err)
	}

	decrypted, err := cm.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Errorf("Decrypted data does not match original data")
	}
}

func TestCryptoManager_EncryptDecryptBase64(t *testing.T) {
	key := "1234567890123456"
	cipher := "AES-128-CBC"
	auth := "SHA256"

	cm, err := internal.NewCryptoManager(key, cipher, auth)
	if err != nil {
		t.Errorf("NewCryptoManager failed: %v", err)
	}

	data := []byte("test data")

	encryptedBase64, err := cm.EncryptBase64(data)
	if err != nil {
		t.Errorf("EncryptBase64 failed: %v", err)
	}

	decrypted, err := cm.DecryptBase64(encryptedBase64)
	if err != nil {
		t.Errorf("DecryptBase64 failed: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Errorf("Decrypted data does not match original data")
	}
}

func TestCryptoManager_Hash(t *testing.T) {
	key := "1234567890123456"
	cipher := "AES-128-CBC"
	auth := "SHA256"

	cm, err := internal.NewCryptoManager(key, cipher, auth)
	if err != nil {
		t.Errorf("NewCryptoManager failed: %v", err)
	}

	data := []byte("test data")

	hash, err := cm.Hash(data)
	if err != nil {
		t.Errorf("Hash failed: %v", err)
	}

	if len(hash) == 0 {
		t.Errorf("Hash returned empty data")
	}
}
