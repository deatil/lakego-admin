package sm2

import (
    "crypto/elliptic"
    "github.com/tjfoc/gmsm/sm2"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this SM2) GetPrivateKey() *sm2.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeyCurve
func (this SM2) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// 获取 PrivateKeyD
func (this SM2) GetPrivateKeyDHexString() string {
    data := this.privateKey.D

    dataHex := cryptobin_tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取私钥明文
func (this SM2) GetPrivateKeyString() string {
    return this.GetPrivateKeyDHexString()
}

// 获取 PublicKey
func (this SM2) GetPublicKey() *sm2.PublicKey {
    return this.publicKey
}

// 获取 PublicKeyCurve
func (this SM2) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// 获取 PublicKeyXHex
func (this SM2) GetPublicKeyXHexString() string {
    data := this.publicKey.X

    dataHex := cryptobin_tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyYHex
func (this SM2) GetPublicKeyYHexString() string {
    data := this.publicKey.Y

    dataHex := cryptobin_tool.HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyXYHex
func (this SM2) GetPublicKeyXYHexString() string {
    dataHex := this.GetPublicKeyXHexString() + this.GetPublicKeyYHexString()

    return dataHex
}

// 获取未压缩公钥
func (this SM2) GetPublicKeyUncompressString() string {
    dataHex := "04" + this.GetPublicKeyXHexString() + this.GetPublicKeyYHexString()

    return dataHex
}

// 获取压缩公钥
func (this SM2) GetPublicKeyCompressString() string {
    data := sm2.Compress(this.publicKey)

    dataHex := cryptobin_tool.HexEncode(data)

    pre := formatPublicKeyCompressPrefix(dataHex[:2])

    return pre + dataHex[2:]
}

// 获取 keyData
func (this SM2) GetKeyData() []byte {
    return this.keyData
}

// 获取 mode
func (this SM2) GetMode() int {
    return this.mode
}

// 获取 data
func (this SM2) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this SM2) GetParedData() []byte {
    return this.paredData
}

// 获取验证后情况
func (this SM2) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this SM2) GetErrors() []error {
    return this.Errors
}
