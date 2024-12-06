package gost

import (
    "io"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/gost"
)

// 生成密钥
func (this Gost) GenerateKeyWithSeed(reader io.Reader) Gost {
    priv, err := gost.GenerateKey(reader, this.curve)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader) Gost {
    return defaultGost.GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this Gost) GenerateKey() Gost {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
func GenerateKey(curve string) Gost {
    return defaultGost.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this Gost) FromPrivateKey(key []byte) Gost {
    return this.FromPKCS8PrivateKey(key)
}

// 私钥
func FromPrivateKey(key []byte) Gost {
    return defaultGost.FromPrivateKey(key)
}

// 私钥带密码
func (this Gost) FromPrivateKeyWithPassword(key []byte, password string) Gost {
    return this.FromPKCS8PrivateKeyWithPassword(key, password)
}

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) Gost {
    return defaultGost.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this Gost) FromPublicKey(key []byte) Gost {
    return this.FromPKCS8PublicKey(key)
}

// 公钥
func FromPublicKey(key []byte) Gost {
    return defaultGost.FromPublicKey(key)
}

// ==========

// PKCS8 私钥
func (this Gost) FromPKCS8PrivateKey(key []byte) Gost {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) Gost {
    return defaultGost.FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func (this Gost) FromPKCS8PrivateKeyWithPassword(key []byte, password string) Gost {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Gost {
    return defaultGost.FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func (this Gost) FromPKCS8PublicKey(key []byte) Gost {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) Gost {
    return defaultGost.FromPKCS8PublicKey(key)
}

// ==========

// Pkcs8 DER 私钥
func (this Gost) FromPKCS8PrivateKeyDer(der []byte) Gost {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 DER 公钥
func (this Gost) FromPKCS8PublicKeyDer(der []byte) Gost {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// 私钥明文, hex 或者 base64 解码后
func (this Gost) FromPrivateKeyBytes(priBytes []byte) Gost {
    parsedKey, err := gost.NewPrivateKey(this.curve, priBytes)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// 公钥明文, hex 或者 base64 解码后
func (this Gost) FromPublicKeyBytes(pubBytes []byte) Gost {
    parsedKey, err := gost.NewPublicKey(this.curve, pubBytes)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// 字节
func (this Gost) FromBytes(data []byte) Gost {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Gost {
    return defaultGost.FromBytes(data)
}

// 字符
func (this Gost) FromString(data string) Gost {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Gost {
    return defaultGost.FromString(data)
}

// Base64
func (this Gost) FromBase64String(data string) Gost {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) Gost {
    return defaultGost.FromBase64String(data)
}

// Hex
func (this Gost) FromHexString(data string) Gost {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) Gost {
    return defaultGost.FromHexString(data)
}
