package ecdsa

import (
    "crypto/elliptic"
)

// 构造函数
func NewEcdsa() Ecdsa {
    return Ecdsa{
        curve:    elliptic.P256(),
        signHash: "SHA512",
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Ecdsa {
    return NewEcdsa()
}

// ==========

// 私钥
func FromPrivateKey(key []byte) Ecdsa {
    return NewEcdsa().FromPrivateKey(key)
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return NewEcdsa().FromPrivateKeyWithPassword(key, password)
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) Ecdsa {
    return NewEcdsa().FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return NewEcdsa().FromPKCS8PrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) Ecdsa {
    return NewEcdsa().FromPublicKey(key)
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKey(hash string) Ecdsa {
    return NewEcdsa().WithCurve(hash).GenerateKey()
}

// ==========

// 字节
func FromBytes(data []byte) Ecdsa {
    return NewEcdsa().FromBytes(data)
}

// 字符
func FromString(data string) Ecdsa {
    return NewEcdsa().FromString(data)
}

// Base64
func FromBase64String(data string) Ecdsa {
    return NewEcdsa().FromBase64String(data)
}

// Hex
func FromHexString(data string) Ecdsa {
    return NewEcdsa().FromHexString(data)
}
