package eddsa

import (
    "crypto/rand"
    "crypto/ed25519"
    
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this EdDSA) FromPrivateKey(key []byte) EdDSA {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed25519.PrivateKey)

    return this
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

// 公钥
func (this EdDSA) FromPublicKey(key []byte) EdDSA {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(ed25519.PublicKey)

    return this
}

// 生成密钥
func (this EdDSA) GenerateKey() EdDSA {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.publicKey  = publicKey
    this.privateKey = privateKey

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
    newData, err := cryptobin_tool.NewEncoding().Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func (this EdDSA) FromHexString(data string) EdDSA {
    newData, err := cryptobin_tool.NewEncoding().HexDecode(data)

    this.data = newData
    
    return this.AppendError(err)
}
