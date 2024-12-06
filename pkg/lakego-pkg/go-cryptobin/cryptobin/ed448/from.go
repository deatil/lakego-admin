package ed448

import (
    "io"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/ed448"
)

// 生成密钥
func (this ED448) GenerateKeyWithSeed(reader io.Reader) ED448 {
    publicKey, privateKey, err := ed448.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader) ED448 {
    return defaultED448.GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this ED448) GenerateKey() ED448 {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
func GenerateKey() ED448 {
    return defaultED448.GenerateKey()
}

// ==========

// 私钥
func (this ED448) FromPrivateKey(key []byte) ED448 {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed448.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) ED448 {
    return defaultED448.FromPrivateKey(key)
}

// 私钥带密码
func (this ED448) FromPrivateKeyWithPassword(key []byte, password string) ED448 {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed448.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) ED448 {
    return defaultED448.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this ED448) FromPublicKey(key []byte) ED448 {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(ed448.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) ED448 {
    return defaultED448.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this ED448) FromPrivateKeyDer(der []byte) ED448 {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed448.PrivateKey)

    return this
}

// DER 公钥
func (this ED448) FromPublicKeyDer(der []byte) ED448 {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(ed448.PublicKey)

    return this
}

// ==========

// 私钥 Seed
func (this ED448) FromPrivateKeySeed(seed []byte) ED448 {
    this.privateKey = ed448.NewKeyFromSeed(seed)

    return this
}

// 私钥 Seed
func FromPrivateKeySeed(seed []byte) ED448 {
    return defaultED448.FromPrivateKeySeed(seed)
}

// ==========

// 字节
func (this ED448) FromBytes(data []byte) ED448 {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) ED448 {
    return defaultED448.FromBytes(data)
}

// 字符
func (this ED448) FromString(data string) ED448 {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) ED448 {
    return defaultED448.FromString(data)
}

// Base64
func (this ED448) FromBase64String(data string) ED448 {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) ED448 {
    return defaultED448.FromBase64String(data)
}

// Hex
func (this ED448) FromHexString(data string) ED448 {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) ED448 {
    return defaultED448.FromHexString(data)
}
