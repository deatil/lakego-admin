package ecdh

import (
    "io"
    "crypto/rand"
    "crypto/ecdh"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

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
func GenerateKey(curve string) Ecdh {
    return defaultECDH.SetCurve(curve).GenerateKey()
}

// 生成密钥
func (this Ecdh) GenerateKeyWithSeed(reader io.Reader) Ecdh {
    privateKey, err := this.curve.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = privateKey.PublicKey()

    return this
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader, curve string) Ecdh {
    return defaultECDH.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// ==========

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

// 私钥, 库自使用的 asn1 格式
func (this Ecdh) FromECDHPrivateKey(key []byte) Ecdh {
    parsedKey, err := this.ParseECDHPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥, 库自使用的 asn1 格式
func FromECDHPrivateKey(key []byte) Ecdh {
    return defaultECDH.FromECDHPrivateKey(key)
}

// 私钥带密码, 库自使用的 asn1 格式
func (this Ecdh) FromECDHPrivateKeyWithPassword(key []byte, password string) Ecdh {
    parsedKey, err := this.ParseECDHPrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥, 库自使用的 asn1 格式
func FromECDHPrivateKeyWithPassword(key []byte, password string) Ecdh {
    return defaultECDH.FromECDHPrivateKeyWithPassword(key, password)
}

// 公钥, 库自使用的 asn1 格式
func (this Ecdh) FromECDHPublicKey(key []byte) Ecdh {
    parsedKey, err := this.ParseECDHPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 公钥, 库自使用的 asn1 格式
func FromECDHPublicKey(key []byte) Ecdh {
    return defaultECDH.FromECDHPublicKey(key)
}

// ==========

// DER 私钥, 库自使用的 asn1 格式
func (this Ecdh) FromECDHPrivateKeyDer(der []byte) Ecdh {
    key := cryptobin_tool.EncodeDerToPem(der, "PRIVATE KEY")

    parsedKey, err := this.ParseECDHPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// DER 公钥, 库自使用的 asn1 格式
func (this Ecdh) FromECDHPublicKeyDer(der []byte) Ecdh {
    key := cryptobin_tool.EncodeDerToPem(der, "PUBLIC KEY")

    parsedKey, err := this.ParseECDHPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}
