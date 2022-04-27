package cryptobin

import (
    "math/big"
    "crypto/elliptic"

    "github.com/tjfoc/gmsm/sm2"
)

// 获取 PrivateKey
func (this SM2) GetPrivateKey() *sm2.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeyCurve
func (this SM2) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// 获取 PrivateKeyX
// privateKeyXHex := NewEncoding().HexEncode(GetPrivateKeyX().Bytes())
func (this SM2) GetPrivateKeyX() *big.Int {
    return this.privateKey.X
}

// 获取 PrivateKeyY
// privateKeyYHex := NewEncoding().HexEncode(GetPrivateKeyY().Bytes())
func (this SM2) GetPrivateKeyY() *big.Int {
    return this.privateKey.Y
}

// 获取 PrivateKeyD
// privateKeyDHex := NewEncoding().HexEncode(GetPrivateKeyD().Bytes())
func (this SM2) GetPrivateKeyD() *big.Int {
    return this.privateKey.D
}

// 获取 PublicKey
func (this SM2) GetPublicKey() *sm2.PublicKey {
    return this.publicKey
}

// 获取 PublicKeyCurve
func (this SM2) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// 获取 PublicKeyX
// publicKeyXHex := NewEncoding().HexEncode(GetPublicKeyX().Bytes())
func (this SM2) GetPublicKeyX() *big.Int {
    return this.publicKey.X
}

// 获取 PublicKeyY
// publicKeyYHex := NewEncoding().HexEncode(GetPublicKeyY().Bytes())
func (this SM2) GetPublicKeyY() *big.Int {
    return this.publicKey.Y
}

// 获取 keyData
func (this SM2) GetKeyData() []byte {
    return this.keyData
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
func (this SM2) GetVeryed() bool {
    return this.veryed
}

// 获取错误
func (this SM2) GetError() error {
    return this.Error
}
