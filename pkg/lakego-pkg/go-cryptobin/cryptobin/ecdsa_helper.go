package cryptobin

import (
    "crypto/elliptic"
)

// 构造函数
func NewEcdsa() Ecdsa {
    return Ecdsa{
        curve:    elliptic.P256(),
        signHash: "SHA512",
        veryed:   false,
    }
}

// ==========

// 私钥
func EcdsaFromPrivateKey(key []byte) Ecdsa {
    return NewEcdsa().FromPrivateKey(key)
}

// 公钥
func EcdsaFromPublicKey(key []byte) Ecdsa {
    return NewEcdsa().FromPublicKey(key)
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func EcdsaGenerateKey(hash string) Ecdsa {
    return NewEcdsa().WithCurve(hash).GenerateKey()
}

// ==========

// 字节
func EcdsaFromBytes(data []byte) Ecdsa {
    return NewEcdsa().FromBytes(data)
}

// 字符
func EcdsaFromString(data string) Ecdsa {
    return NewEcdsa().FromString(data)
}

// Base64
func EcdsaFromBase64String(data string) Ecdsa {
    return NewEcdsa().FromBase64String(data)
}

// Hex
func EcdsaFromHexString(data string) Ecdsa {
    return NewEcdsa().FromHexString(data)
}
