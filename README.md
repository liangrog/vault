# ansible-vault
ansible-vault is developed as a [go module](https://github.com/golang/go/wiki/Modules) which can be used by other go tools for data encryption or decryption.

It is designed to follow the exact [spec of Ansible Vault 1.1](https://docs.ansible.com/ansible/latest/user_guide/vault.html#vault-payload-format-1-1) so the data it encrypted can be decrypted by Ansible Vault and vice versa.

## Module Docs
Please refer to [GoDoc](https://godoc.org/github.com/liangrog/ansible-vault)

## Example
```go
package main

import (
    "fmt"

    "github.com/liangrog/ansible-vault/vault"
)

func main() {
    plainText := "ansible vault secret 1.1"
    password  := "password123"

    v := new(vault.Vault)

    // To encrypt
    secret, err := v.Encrypt([]byte(plainText), password)
    if err != nil {
        fmt.Println(err)
    }

    fmt.Println(secret)


    // To decrypt
    plainSecret, err := v.Decrypt(password, secret)
    if err != nil {
        fmt.Println(err)
    }
   
    fmt.Println(plainSecret)
}
```
