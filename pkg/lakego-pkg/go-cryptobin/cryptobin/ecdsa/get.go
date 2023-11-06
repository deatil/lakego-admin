package ecdsa

import (
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this Ecdsa) GetPrivateKey() *ecdsa.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeyCurve
func (this Ecdsa) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// 获取 PrivateKeyD
func (this Ecdsa) GetPrivateKeyDHexString() string {
    data := this.privateKey.D

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取私钥明文
func (this Ecdsa) GetPrivateKeyString() string {
    return this.GetPrivateKeyDHexString()
}

// 获取 PublicKey
func (this Ecdsa) GetPublicKey() *ecdsa.PublicKey {
    return this.publicKey
}

// 获取 PublicKeyCurve
func (this Ecdsa) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// 获取 PublicKeyX
func (this Ecdsa) GetPublicKeyXHexString() string {
    data := this.publicKey.X

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyY
func (this Ecdsa) GetPublicKeyYHexString() string {
    data := this.publicKey.Y

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyXYHex
func (this Ecdsa) GetPublicKeyXYHexString() string {
    dataHex := this.GetPublicKeyXHexString() + this.GetPublicKeyYHexString()

    return dataHex
}

// 获取未压缩公钥
func (this Ecdsa) GetPublicKeyUncompressString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return tool.HexEncode(key)
}

// 获取压缩公钥
func (this Ecdsa) GetPublicKeyCompressString() string {
    key := elliptic.MarshalCompressed(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return tool.HexEncode(key)
}

// 获取 hash 类型
func (this Ecdsa) GetSignHash() HashFunc {
    return this.signHash
}

// 获取 keyData
func (this Ecdsa) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this Ecdsa) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this Ecdsa) GetParedData() []byte {
    return this.paredData
}

// 获取验证后情况
func (this Ecdsa) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this Ecdsa) GetErrors() []error {
    return this.Errors
}
