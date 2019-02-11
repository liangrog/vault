// Vault package provide functions that take in plain text data or
// enncrypted data then encrypt and decrypt them using avcipher package.
package avault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/liangrog/ansible-vault/avcipher"
)

const (
	// Ansible vault version header
	HEADER = "$ANSIBLE_VAULT;1.1;AES256"

	// Format output line length
	CharPerLine = 80
)

// Format the text to given length per linne.
func Wrap(data []byte, length int) string {
	var output []byte

	for i := 0; i < len(data); i++ {
		// Append prune line wrap char
		if i > 0 && i%length == 0 {
			output = append(output, '\n')
		}
		output = append(output, data[i])
	}

	return string(output)
}

// To be encrypted data part in a vault file.
type Vault struct {
	// The encrypted data.
	Data []byte

	// Data checksum
	CheckSum []byte

	// Salt string
	Salt []byte
}

// Encypt data using given the password. The output is hash encoded.
func (v *Vault) Encrypt(data []byte, password string) ([]byte, error) {
	var err error

	// Empty password is not allowed.
	if len(password) <= 0 {
		return nil, errors.New("Empty password")
	}

	// Get salt
	v.Salt, err = avcipher.SaltGen(avcipher.SaltLength)
	if err != nil {
		return nil, err
	}

	key := avcipher.KeyGen(password, v.Salt)

	v.Data, err = avcipher.CipherData(avcipher.ENCRYPT, data, key)
	if err != nil {
		return nil, err
	}

	// Generate checksum
	mac := hmac.New(sha256.New, key.HMACKey)
	mac.Write(v.Data)
	v.CheckSum = mac.Sum(nil)

	return v.encode(), nil
}

// Encode the encrypted vault file data.
func (v *Vault) encode() []byte {
	content := []byte(
		strings.Join(
			[]string{
				hex.EncodeToString(v.Salt),
				hex.EncodeToString(v.CheckSum),
				hex.EncodeToString(v.Data),
			},
			"\n",
		))

	return []byte(strings.Join(
		[]string{
			HEADER,
			Wrap([]byte(hex.EncodeToString(content)), CharPerLine),
		}, "\n"))
}

// Decode hashed vault data.
func (v *Vault) decode(str string) error {
	lines := strings.SplitN(str, "\n", 2)

	if strings.TrimSpace(lines[0]) != HEADER {
		return errors.New("Invalid vault file format")
	}

	// Concat all lines
	content := strings.TrimSpace(lines[1])
	content = strings.Replace(content, "\r", "", -1)
	content = strings.Replace(content, "\n", "", -1)

	// Decode the first layer
	decodedStr, err := hex.DecodeString(content)
	if err != nil {
		return err
	}

	lines = strings.Split(string(decodedStr), "\n")
	if len(lines) != 3 {
		return errors.New("Invalid encoded data")
	}

	if v.Salt, err = hex.DecodeString(lines[0]); err != nil {
		return err
	}

	if v.CheckSum, err = hex.DecodeString(lines[1]); err != nil {
		return err
	}

	if v.Data, err = hex.DecodeString(lines[2]); err != nil {
		return err
	}

	return nil
}

// Decrypt vault file data by given password.
func (v *Vault) Decrypt(password string, data []byte) ([]byte, error) {
	// Empty password is not allowed
	if len(password) <= 0 {
		return nil, errors.New("Empty password")
	}

	if err := v.decode(string(data)); err != nil {
		return nil, err
	}

	key := avcipher.KeyGen(password, v.Salt)

	// Check checksum in case data is tempered
	if !avcipher.IsCheckSumValid(v.CheckSum, v.Data, key.HMACKey) {
		return nil, errors.New("Checksum doesn't match")
	}

	return avcipher.CipherData(avcipher.DECRYPT, v.Data, key)
}

// Check if file has Ansible Vault header
func (v *Vault) HasVaultHeader(data []byte) bool {
	lines := strings.SplitN(string(data), "\n", 2)

	if strings.TrimSpace(lines[0]) != HEADER {
		return false
	}

	return true
}
