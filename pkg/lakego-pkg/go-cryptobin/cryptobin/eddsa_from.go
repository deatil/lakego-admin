package cryptobin

import (
    "crypto/ed25519"
    "crypto/rand"
)

// 私钥
func (this EdDSA) FromPrivateKey(key []byte) EdDSA {
    parsedKey, err := this.ParseEdPrivateKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(ed25519.PrivateKey)

    return this
}

// 公钥
func (this EdDSA) FromPublicKey(key []byte) EdDSA {
    parsedKey, err := this.ParseEdPublicKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.publicKey = parsedKey.(ed25519.PublicKey)

    return this
}

// 生成密钥
func (this EdDSA) GenerateKey() EdDSA {
    this.publicKey, this.privateKey, this.Error = ed25519.GenerateKey(rand.Reader)

    return this
}

// ==========

// 字节
func (this EdDSA) FromBytes(data []byte) EdDSA {
    this.data = data

    return this
}

// 字符
func (this EdDSA) FromString(data string) EdDSA {
    this.data = []byte(data)

    return this
}

// Base64
func (this EdDSA) FromBase64String(data string) EdDSA {
    newData, err := this.Base64Decode(data)

    this.data = newData
    this.Error = err

    return this
}

// Hex
func (this EdDSA) FromHexString(data string) EdDSA {
    newData, err := this.HexDecode(data)

    this.data = newData
    this.Error = err

    return this
}
