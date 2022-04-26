package cryptobin

import (
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"
)

// 私钥
func (this SM2) FromPrivateKey(key []byte) SM2 {
    this.privateKey, this.Error = this.ParsePrivateKeyFromPEM(key)

    return this
}

// 私钥带密码
func (this SM2) FromPrivateKeyWithPassword(key []byte, password string) SM2 {
    this.privateKey, this.Error = this.ParsePrivateKeyFromPEMWithPassword(key, password)

    return this
}

// 公钥
func (this SM2) FromPublicKey(key []byte) SM2 {
    this.publicKey, this.Error = this.ParsePublicKeyFromPEM(key)

    return this
}

// 生成密钥
func (this SM2) GenerateKey() SM2 {
    this.privateKey, this.Error = sm2.GenerateKey(rand.Reader)

    return this
}

// ==========

// 字节
func (this SM2) FromBytes(data []byte) SM2 {
    this.data = data

    return this
}

// 字符
func (this SM2) FromString(data string) SM2 {
    this.data = []byte(data)

    return this
}

// Base64
func (this SM2) FromBase64String(data string) SM2 {
    newData, err := NewEncoding().Base64Decode(data)

    this.data = newData
    this.Error = err

    return this
}

// Hex
func (this SM2) FromHexString(data string) SM2 {
    newData, err := NewEncoding().HexDecode(data)

    this.data = newData
    this.Error = err

    return this
}
