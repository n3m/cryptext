package cryptext

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func EncryptWithPhrase(phrase string, data string) (encryptedText string, err error) {
	// The AES Cipher Engine requires a 32 byte key
	// We're using SHA256 to generate a hash from the key
	hash := sha256.Sum256([]byte(phrase))

	// Create the AES Cipher Engine Block
	CipherEngineBlock, err := aes.NewCipher(hash[:])
	if err != nil {
		return
	}

	// Create the AES Cipher Engine
	CipherEngine, err := cipher.NewGCM(CipherEngineBlock)
	if err != nil {
		return
	}

	// Create the Nonce
	nonce := make([]byte, CipherEngine.NonceSize())

	// Verify the length of the nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the data
	encryptedBytes := CipherEngine.Seal(nonce, nonce, []byte(data), nil)

	fmt.Printf("%+v", string(encryptedBytes))
	return string(encryptedBytes), nil
}

func DecryptWithPhrase(phrase string, data []byte) (encryptedText string, err error) {
	// The AES Cipher Engine requires a 32 byte key
	// We're using SHA256 to generate a hash from the key
	hash := sha256.Sum256([]byte(phrase))

	// Create the AES Cipher Engine Block
	CipherEngineBlock, err := aes.NewCipher(hash[:])
	if err != nil {
		return
	}

	// Create the AES Cipher Engine
	CipherEngine, err := cipher.NewGCM(CipherEngineBlock)
	if err != nil {
		return
	}

	// Create the Nonce from the data
	nonceSize := CipherEngine.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the data
	decryptedBytes, err := CipherEngine.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	return string(decryptedBytes), nil
}
