package ecdh

import (
    "io"
    "crypto/rand"
    "crypto/ecdh"

    "github.com/deatil/go-cryptobin/tool/pem"
)

// 生成密钥
func (this ECDH) GenerateKeyWithSeed(reader io.Reader) ECDH {
    privateKey, err := this.curve.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = privateKey.PublicKey()

    return this
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader, curve string) ECDH {
    return defaultECDH.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this ECDH) GenerateKey() ECDH {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
func GenerateKey(curve string) ECDH {
    return defaultECDH.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this ECDH) FromPrivateKey(key []byte) ECDH {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) ECDH {
    return defaultECDH.FromPrivateKey(key)
}

// 私钥带密码
func (this ECDH) FromPrivateKeyWithPassword(key []byte, password string) ECDH {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) ECDH {
    return defaultECDH.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this ECDH) FromPublicKey(key []byte) ECDH {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) ECDH {
    return defaultECDH.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this ECDH) FromPrivateKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// DER 公钥
func (this ECDH) FromPublicKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// ==========

// 私钥, 库自使用的 asn1 格式
func (this ECDH) FromECDHPrivateKey(key []byte) ECDH {
    parsedKey, err := this.ParseECDHPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥, 库自使用的 asn1 格式
func FromECDHPrivateKey(key []byte) ECDH {
    return defaultECDH.FromECDHPrivateKey(key)
}

// 私钥带密码, 库自使用的 asn1 格式
func (this ECDH) FromECDHPrivateKeyWithPassword(key []byte, password string) ECDH {
    parsedKey, err := this.ParseECDHPrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥, 库自使用的 asn1 格式
func FromECDHPrivateKeyWithPassword(key []byte, password string) ECDH {
    return defaultECDH.FromECDHPrivateKeyWithPassword(key, password)
}

// 公钥, 库自使用的 asn1 格式
func (this ECDH) FromECDHPublicKey(key []byte) ECDH {
    parsedKey, err := this.ParseECDHPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 公钥, 库自使用的 asn1 格式
func FromECDHPublicKey(key []byte) ECDH {
    return defaultECDH.FromECDHPublicKey(key)
}

// ==========

// DER 私钥, 库自使用的 asn1 格式
func (this ECDH) FromECDHPrivateKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParseECDHPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// DER 公钥, 库自使用的 asn1 格式
func (this ECDH) FromECDHPublicKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParseECDHPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}
