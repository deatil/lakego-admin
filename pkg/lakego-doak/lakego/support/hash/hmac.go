package hash

import (
    "crypto"
    "crypto/hmac"
    "encoding/hex"
)

// HmacMd4 签名
func HmacMd4(message string, secret string) string {
    return HmacHash(crypto.MD4, message, secret)
}

// HmacMd5 签名
func HmacMd5(message string, secret string) string {
    return HmacHash(crypto.MD5, message, secret)
}

// HmacSHA1 签名
func HmacSHA1(message string, secret string) string {
    return HmacHash(crypto.SHA1, message, secret)
}

// HmacSha224 签名
func HmacSha224(message string, secret string) string {
    return HmacHash(crypto.SHA224, message, secret)
}

// HmacSha256 签名
func HmacSha256(message string, secret string) string {
    return HmacHash(crypto.SHA256, message, secret)
}

// HmacSha384 签名
func HmacSha384(message string, secret string) string {
    return HmacHash(crypto.SHA384, message, secret)
}

// HmacSha512 签名
func HmacSha512(message string, secret string) string {
    return HmacHash(crypto.SHA512, message, secret)
}

// HmacSha512 签名
func HmacRipemd160(message string, secret string) string {
    return HmacHash(crypto.RIPEMD160, message, secret)
}

// 签名
func HmacHash(hash crypto.Hash, message string, secret string) string {
    hasher := hmac.New(hash.New, []byte(secret))
    hasher.Write([]byte(message))
    return hex.EncodeToString(hasher.Sum(nil))
}

