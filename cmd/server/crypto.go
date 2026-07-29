package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"os"
)

var emailEncryptionKey []byte

// loadEmailEncryptionKey читает 32-байтный (AES-256) ключ из EMAIL_ENCRYPTION_KEY
// (base64). Если переменная не задана, генерирует ключ в памяти — email,
// зашифрованные с эфемерным ключом, не расшифровать после рестарта процесса,
// поэтому это подходит только для dev/тестов, не для продакшена.
func loadEmailEncryptionKey() error {
	raw := os.Getenv("EMAIL_ENCRYPTION_KEY")
	if raw == "" {
		log.Println("crypto: EMAIL_ENCRYPTION_KEY не задан — генерирую эфемерный ключ AES-256 (только для dev, email не переживут рестарт)")
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		emailEncryptionKey = key
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return errors.New("crypto: EMAIL_ENCRYPTION_KEY должен быть валидным base64")
	}
	if len(key) != 32 {
		return errors.New("crypto: EMAIL_ENCRYPTION_KEY должен декодироваться в 32 байта (AES-256)")
	}
	emailEncryptionKey = key
	return nil
}

// encryptEmail шифрует email AES-256-GCM (случайный nonce на каждый вызов —
// одинаковый email даёт разный шифротекст, что и требуется: в коде нет ни
// одного запроса "WHERE email = ?", email только пишется и точечно читается
// по user_id, детерминированность/индекс по этому полю не нужны).
func encryptEmail(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	block, err := aes.NewCipher(emailEncryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptEmail — обратная операция; используется там, где email нужно
// прочитать в открытом виде (например, для повторной отправки письма).
func decryptEmail(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(emailEncryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("crypto: зашифрованный email повреждён")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
