package eddsa

import (
    "io"
    "crypto/rand"
    "crypto/ed25519"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 生成密钥
func (this EdDSA) GenerateKeyWithSeed(reader io.Reader) EdDSA {
    publicKey, privateKey, err := ed25519.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader) EdDSA {
    return defaultEdDSA.GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this EdDSA) GenerateKey() EdDSA {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
func GenerateKey() EdDSA {
    return defaultEdDSA.GenerateKey()
}

// ==========

// 私钥
func (this EdDSA) FromPrivateKey(key []byte) EdDSA {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed25519.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) EdDSA {
    return defaultEdDSA.FromPrivateKey(key)
}

// 私钥带密码
func (this EdDSA) FromPrivateKeyWithPassword(key []byte, password string) EdDSA {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed25519.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) EdDSA {
    return defaultEdDSA.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this EdDSA) FromPublicKey(key []byte) EdDSA {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(ed25519.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) EdDSA {
    return defaultEdDSA.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this EdDSA) FromPrivateKeyDer(der []byte) EdDSA {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed25519.PrivateKey)

    return this
}

// DER 公钥
func (this EdDSA) FromPublicKeyDer(der []byte) EdDSA {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(ed25519.PublicKey)

    return this
}

// ==========

// 私钥 Seed
func (this EdDSA) FromPrivateKeySeed(seed []byte) EdDSA {
    this.privateKey = ed25519.NewKeyFromSeed(seed)

    return this
}

// 私钥 Seed
func FromPrivateKeySeed(seed []byte) EdDSA {
    return defaultEdDSA.FromPrivateKeySeed(seed)
}

// ==========

// 字节
func (this EdDSA) FromBytes(data []byte) EdDSA {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) EdDSA {
    return defaultEdDSA.FromBytes(data)
}

// 字符
func (this EdDSA) FromString(data string) EdDSA {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) EdDSA {
    return defaultEdDSA.FromString(data)
}

// Base64
func (this EdDSA) FromBase64String(data string) EdDSA {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) EdDSA {
    return defaultEdDSA.FromBase64String(data)
}

// Hex
func (this EdDSA) FromHexString(data string) EdDSA {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) EdDSA {
    return defaultEdDSA.FromHexString(data)
}
