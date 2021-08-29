package crypt

import (
    "fmt"
    "crypto/hmac"
    "crypto/sha1"
)

// hmac
func Hmac(secretKey, body string) string {
    m := hmac.New(sha1.New, []byte(secretKey))

    m.Write([]byte(body))
    data := m.Sum(nil)

    return fmt.Sprintf("%x", data)
}
