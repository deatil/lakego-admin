package cryptobin

import (
    "crypto/ecdsa"
    "crypto/rand"
)

// 私钥
func (this Ecdsa) FromPrivateKey(key []byte) Ecdsa {
    this.privateKey, this.Error = this.ParseECPrivateKeyFromPEM(key)

    return this
}

// 公钥
func (this Ecdsa) FromPublicKey(key []byte) Ecdsa {
    this.publicKey, this.Error = this.ParseECPublicKeyFromPEM(key)

    return this
}

// 生成密钥
func (this Ecdsa) GenerateKey() Ecdsa {
    this.privateKey, this.Error = ecdsa.GenerateKey(this.curve, rand.Reader)

    return this
}

// ==========

// 字节
func (this Ecdsa) FromBytes(data []byte) Ecdsa {
    this.data = data

    return this
}

// 字符
func (this Ecdsa) FromString(data string) Ecdsa {
    this.data = []byte(data)

    return this
}

// Base64
func (this Ecdsa) FromBase64String(data string) Ecdsa {
    newData, err := this.Base64Decode(data)

    this.data = newData
    this.Error = err

    return this
}

// Hex
func (this Ecdsa) FromHexString(data string) Ecdsa {
    newData, err := this.HexDecode(data)

    this.data = newData
    this.Error = err

    return this
}
