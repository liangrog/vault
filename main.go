// This is an example of how to use the vault package.
// For those of whom want just the enncryption, please take a look into avcipher package.
package main

import (
	"fmt"

	"github.com/liangrog/ansible-vault/vault"
)

func main() {
	plainText := "ansible vault secret 1.1"
	password := "password123"

	v := new(vault.Vault)

	// To encrypt
	secret, err := v.Encrypt([]byte(plainText), password)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%s\n", secret)

	// To decrypt
	plainSecret, err := v.Decrypt(password, secret)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%s\n", plainSecret)
}
