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

// HmacMd4 哈希值
func (this Hash) HmacMd4(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacMd4(newData, secret), nil
    })
}

// HmacMd5 签名
func HmacMd5(message string, secret string) string {
    return HmacHash(crypto.MD5, message, secret)
}

// HmacMd5 哈希值
func (this Hash) HmacMd5(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacMd5(newData, secret), nil
    })
}

// HmacSHA1 签名
func HmacSHA1(message string, secret string) string {
    return HmacHash(crypto.SHA1, message, secret)
}

// HmacSHA1 哈希值
func (this Hash) HmacSHA1(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacSHA1(newData, secret), nil
    })
}

// HmacSha224 签名
func HmacSha224(message string, secret string) string {
    return HmacHash(crypto.SHA224, message, secret)
}

// HmacSha224 哈希值
func (this Hash) HmacSha224(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacSha224(newData, secret), nil
    })
}

// HmacSha256 签名
func HmacSha256(message string, secret string) string {
    return HmacHash(crypto.SHA256, message, secret)
}

// HmacSha256 哈希值
func (this Hash) HmacSha256(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacSha256(newData, secret), nil
    })
}

// HmacSha384 签名
func HmacSha384(message string, secret string) string {
    return HmacHash(crypto.SHA384, message, secret)
}

// HmacSha384 哈希值
func (this Hash) HmacSha384(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacSha384(newData, secret), nil
    })
}

// HmacSha512 签名
func HmacSha512(message string, secret string) string {
    return HmacHash(crypto.SHA512, message, secret)
}

// HmacSha512 哈希值
func (this Hash) HmacSha512(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacSha512(newData, secret), nil
    })
}

// HmacSha512 签名
func HmacRipemd160(message string, secret string) string {
    return HmacHash(crypto.RIPEMD160, message, secret)
}

// HmacRipemd160 哈希值
func (this Hash) HmacRipemd160(secret string) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return HmacRipemd160(newData, secret), nil
    })
}

// 签名
func HmacHash(hash crypto.Hash, message string, secret string) string {
    hasher := hmac.New(hash.New, []byte(secret))
    hasher.Write([]byte(message))
    return hex.EncodeToString(hasher.Sum(nil))
}

