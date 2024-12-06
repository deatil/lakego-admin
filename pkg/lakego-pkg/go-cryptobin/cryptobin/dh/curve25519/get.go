package curve25519

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/dh/curve25519"
)

// 获取 PrivateKey
func (this Curve25519) GetPrivateKey() *curve25519.PrivateKey {
    return this.privateKey
}

// 获取 X 16进制字符
func (this Curve25519) GetPrivateKeyXString() string {
    data := this.privateKey.X

    dataHex := encoding.HexEncode(data)

    return dataHex
}

// 获取 PublicKey
func (this Curve25519) GetPublicKey() *curve25519.PublicKey {
    return this.publicKey
}

// 获取 Y 16进制字符
func (this Curve25519) GetPublicKeyYString() string {
    data := this.publicKey.Y

    dataHex := encoding.HexEncode(data)

    return dataHex
}

// 获取 keyData
func (this Curve25519) GetKeyData() []byte {
    return this.keyData
}

// 获取 secretData
func (this Curve25519) GetSecretData() []byte {
    return this.secretData
}

// 获取错误
func (this Curve25519) GetErrors() []error {
    return this.Errors
}
