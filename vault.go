package vault

import (
	"github.com/liangrog/vault/avault"
)

// It encrypt given byte data using provided password
// into ansible-vault 1.1 format.
func Encrypt(data []byte, password string) ([]byte, error) {
	return new(avault.Vault).Encrypt(data, password)
}

// It decrypt given byte data in ansible-vault 1.1
// format using provided password into plain text.
func Decrypt(password string, data []byte) ([]byte, error) {
	return new(avault.Vault).Decrypt(password, data)
}

// Check if given data has ansible vault header
func HasVaultHeader(data []byte) bool {
	return new(avault.Vault).HasVaultHeader(data)
}
