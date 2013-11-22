package main

import (
        "code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/go.crypto/pbkdf2"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main () {
    pass := fmt.Sprint("ER8FT+HFjk0", "\x01")
    salt := fmt.Sprint("7DpniYifN6c", "\x01")
    key, _ := scrypt.Key([]byte(pass), []byte(salt), 262144, 8, 1, 32)

    pass = fmt.Sprint("ER8FT+HFjk0", "\x02")
    salt = fmt.Sprint("7DpniYifN6c", "\x02")
    key2 := pbkdf2.Key([]byte(pass), []byte(salt), 65536, 32, sha256.New)

    var result bytes.Buffer
    for i := 0; i < len(key); i++ {
        result.WriteByte(key[i] ^ key2[i])
    }
    
    fmt.Printf(hex.EncodeToString(key))
    fmt.Printf("\n")
    fmt.Printf(hex.EncodeToString(key2))
    fmt.Printf("\n")
    fmt.Printf(hex.EncodeToString(result.Bytes()))
    fmt.Printf("\n")
}
