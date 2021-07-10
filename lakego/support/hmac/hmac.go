package hmac

import (
    "crypto"
    "crypto/hmac"
    "encoding/hex"
    "encoding/base64"
)

// Sha256 签名
func Sha256(message string, secret string) string {
    return Sign(crypto.SHA256, message, secret)
}

// Sha384 签名
func Sha384(message string, secret string) string {
    return Sign(crypto.SHA384, message, secret)
}

// Sha512 签名
func Sha512(message string, secret string) string {
    return Sign(crypto.SHA512, message, secret)
}

// 签名
func Sign(hash crypto.Hash, message string, secret string) string {
    key := []byte(secret)
    hasher := hmac.New(hash.New, key)
    hasher.Write([]byte(message))
    sha := hex.EncodeToString(hasher.Sum(nil))
    return base64.StdEncoding.EncodeToString([]byte(sha))
}

