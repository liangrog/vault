package vault

import (
	"github.com/liangrog/ansible-vault/avault"
)

var v = new(avault.Vault)

// Facade encrypt function.
// It encrypt given byte data using provided password
// into ansible-vault 1.1 format.
func Encrypt(data []byte, password string) ([]byte, error) {
	return v.Encrypt(data, password)
}

// Facade decrypt function.
// It decrypt given byte data inansible-vault 1.1
// format using provided password into plain text.
func Decrypt(password string, data []byte) ([]byte, error) {
	return v.Decrypt(password, data)
}
