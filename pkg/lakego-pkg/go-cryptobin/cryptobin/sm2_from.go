package cryptobin

import (
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"
)

// Pkcs8
func (this SM2) FromSM2PrivateKey(key []byte) SM2 {
    this.privateKey, this.Error = this.ParseSM2PrivateKeyFromPEM(key)

    return this
}

// Pkcs8WithPassword
func (this SM2) FromSM2PrivateKeyWithPassword(key []byte, password string) SM2 {
    this.privateKey, this.Error = this.ParseSM2PrivateKeyFromPEMWithPassword(key, []byte(password))

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
    newData, err := this.Base64Decode(data)

    this.data = newData
    this.Error = err

    return this
}

// Hex
func (this SM2) FromHexString(data string) SM2 {
    newData, err := this.HexDecode(data)

    this.data = newData
    this.Error = err

    return this
}
