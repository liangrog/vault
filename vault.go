package vault

import (
	"github.com/liangrog/ansible-vault/avault"
)

var v = new(avault.Vault)

// Facade encrypt function
func Encrypt(data []byte, password string) ([]byte, error) {
	return v.Encrypt(data, password)
}

// Facade decrypt function
func Decrypt(password string, data []byte) ([]byte, error) {
	return v.Decrypt(password, data)
}
