# Ansible Vault Go Module
[![Version](https://img.shields.io/github/v/release/liangrog/vault)](https://github.com/liangrog/vault/releases)
[![GoDoc](https://godoc.org/github.com/liangrog/vault?status.svg)](https://godoc.org/github.com/liangrog/vault)


vault is developed as a [go module](https://github.com/golang/go/wiki/Modules) which can be used by other go tools for data encryption or decryption.

It is designed to follow the exact [spec of Ansible Vault 1.1](https://docs.ansible.com/ansible/latest/user_guide/vault.html#vault-payload-format-1-1) so the data it encrypted can be decrypted by Ansible Vault or vice versa.

## Module Docs
Please refer to [GoDoc](https://godoc.org/github.com/liangrog/vault)

## Example
```go
package main

import (
    "fmt"

    "github.com/liangrog/vault"
)

func main() {
    plainText := "ansible vault secret 1.1"
    password  := "password123"

    // To encrypt
    secret, err := vault.Encrypt([]byte(plainText), password)
    if err != nil {
        fmt.Println(err)
    }

    fmt.Printf("%s\n", secret)


    // To decrypt
    plainSecret, err := vault.Decrypt(password, secret)
    if err != nil {
        fmt.Println(err)
    }
   
    fmt.Printf("%s\n", plainSecret)
}
```

The output:
```
$ANSIBLE_VAULT;1.1;AES256
31326233666231326135313164643631323064373739663635323861366565633666646135316631
6335613566396562323836323338313130343265363035390a653931346633376335326530323266
36616333356161613566323665323962353638383863623637316535363232326164623365396533
3962366236326661340a393665306530396536343134366464303561633661393763303134396232
35633436363033646332626334363061326332343731383535363334666665653533
ansible vault secret 1.1
```
