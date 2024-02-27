package ecdsa

import (
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this ECDSA) GetPrivateKey() *ecdsa.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeyCurve
func (this ECDSA) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// 获取 PrivateKeyD
func (this ECDSA) GetPrivateKeyDHexString() string {
    data := this.privateKey.D

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取私钥明文
func (this ECDSA) GetPrivateKeyString() string {
    return this.GetPrivateKeyDHexString()
}

// 获取 PublicKey
func (this ECDSA) GetPublicKey() *ecdsa.PublicKey {
    return this.publicKey
}

// 获取 PublicKeyCurve
func (this ECDSA) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// 获取 PublicKeyX
func (this ECDSA) GetPublicKeyXHexString() string {
    data := this.publicKey.X

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyY
func (this ECDSA) GetPublicKeyYHexString() string {
    data := this.publicKey.Y

    dataHex := tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyXYHex
func (this ECDSA) GetPublicKeyXYHexString() string {
    dataHex := this.GetPublicKeyXHexString() + this.GetPublicKeyYHexString()

    return dataHex
}

// 获取未压缩公钥
func (this ECDSA) GetPublicKeyUncompressString() string {
    key := elliptic.Marshal(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return tool.HexEncode(key)
}

// 获取压缩公钥
func (this ECDSA) GetPublicKeyCompressString() string {
    key := elliptic.MarshalCompressed(this.publicKey.Curve, this.publicKey.X, this.publicKey.Y)

    return tool.HexEncode(key)
}

// 获取 Curve
func (this ECDSA) GetCurve() elliptic.Curve {
    return this.curve
}

// 获取 hash 类型
func (this ECDSA) GetSignHash() HashFunc {
    return this.signHash
}

// 获取 keyData
func (this ECDSA) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this ECDSA) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this ECDSA) GetParsedData() []byte {
    return this.parsedData
}

// 获取验证后情况
func (this ECDSA) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this ECDSA) GetErrors() []error {
    return this.Errors
}
