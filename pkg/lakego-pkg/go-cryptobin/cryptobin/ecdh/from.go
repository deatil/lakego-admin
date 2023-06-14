package ecdh

import (
    "crypto/rand"
    "crypto/ecdh"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this Ecdh) FromPrivateKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) Ecdh {
    return defaultECDH.FromPrivateKey(key)
}

// 私钥带密码
func (this Ecdh) FromPrivateKeyWithPassword(key []byte, password string) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Ecdh {
    return defaultECDH.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this Ecdh) FromPublicKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) Ecdh {
    return defaultECDH.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this Ecdh) FromPrivateKeyDer(der []byte) Ecdh {
    key := cryptobin_tool.EncodeDerToPem(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// DER 公钥
func (this Ecdh) FromPublicKeyDer(der []byte) Ecdh {
    key := cryptobin_tool.EncodeDerToPem(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// ==========

// 生成密钥
func (this Ecdh) GenerateKey() Ecdh {
    privateKey, err := this.curve.GenerateKey(rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = privateKey.PublicKey()

    return this
}

// 生成密钥
func GenerateKey() Ecdh {
    return defaultECDH.GenerateKey()
}
