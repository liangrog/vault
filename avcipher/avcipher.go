// The cipher package provide functions that can be used
// to encrypt or decrypt data that complys to Ansible Vault 1.1
// specification.
package avcipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Ansible Vault 1.1 spec: key length
	CipherKeyLength = 32

	// Ansible Vault 1.1 spec: HMAC key length
	HMACKeyLength = 32

	// Ansible Vault 1.1 spec: Salt string length
	SaltLength = 32

	// Ansible Vault 1.1 spec: initialization vector length
	IVLength = 16

	// Ansible Vault 1.1 spec: iteration rounds
	Iteration = 10000
)

// Key used to cipher
type CipherKey struct {
	// Cipher Key
	Key []byte

	// Hmac key
	HMACKey []byte

	// Initialization vetor
	IV []byte
}

// Generate cipher key for given password and salt
func KeyGen(password string, salt []byte) *CipherKey {
	k := pbkdf2.Key(
		[]byte(password),
		salt,
		Iteration,
		(CipherKeyLength + HMACKeyLength + IVLength),
		sha256.New,
	)

	return &CipherKey{
		Key:     k[:CipherKeyLength],
		HMACKey: k[CipherKeyLength:(CipherKeyLength + HMACKeyLength)],
		IV:      k[(CipherKeyLength + HMACKeyLength):(CipherKeyLength + HMACKeyLength + IVLength)],
	}
}

// Generate given length of random salt bytes
func SaltGen(n int) ([]byte, error) {
	s := make([]byte, n)
	_, err := rand.Read(s)

	return s, err
}

// Encrypt or decrypt the given data and key.
// Use "encrypt" and "decrypt' for CipherType to determine the cipher direction.
func CipherData(CipherType string, data []byte, key *CipherKey) ([]byte, error) {
	var output []byte

	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, key.IV)

	switch CipherType {
	case "encrypt":
		data = AESBlockPad(data)
		output = make([]byte, len(data))
		stream.XORKeyStream(output, data)
	case "decrypt":
		decryptedData := make([]byte, len(data))
		stream.XORKeyStream(decryptedData, data)
		output, err = AESBlockUnpad(decryptedData)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Missing instruction on how to cipher")
	}

	return output, nil
}

// Pad data to fit AES block size
func AESBlockPad(data []byte) []byte {
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	return append(data, (bytes.Repeat([]byte{byte(padLen)}, padLen))...)
}

// Unpad data for AES block
func AESBlockUnpad(data []byte) ([]byte, error) {
	length := len(data)
	unpad := int(data[length-1])

	if unpad > length {
		return nil, errors.New("Unpad error")
	}

	return data[:(length - unpad)], nil
}

// Validate HMAC checksum
func IsCheckSumValid(checkSum, data, hmacKey []byte) bool {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), checkSum)
}
