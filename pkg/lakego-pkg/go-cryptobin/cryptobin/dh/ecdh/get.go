package ecdh

import (
    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/dh/ecdh"
)

// 获取 PrivateKey
func (this ECDH) GetPrivateKey() *ecdh.PrivateKey {
    return this.privateKey
}

// 获取 X 16进制字符
func (this ECDH) GetPrivateKeyXHexString() string {
    data := this.privateKey.X

    dataHex := tool.HexEncode(data)

    return dataHex
}

// 获取 PublicKey
func (this ECDH) GetPublicKey() *ecdh.PublicKey {
    return this.publicKey
}

// 获取 Y 16进制字符
func (this ECDH) GetPublicKeyYString() string {
    data := this.publicKey.Y

    dataHex := tool.HexEncode(data)

    return dataHex
}

// 获取散列方式
func (this ECDH) GetCurve() ecdh.Curve {
    return this.curve
}

// 获取 keyData
func (this ECDH) GetKeyData() []byte {
    return this.keyData
}

// 获取 secretData
func (this ECDH) GetSecretData() []byte {
    return this.secretData
}

// 获取错误
func (this ECDH) GetErrors() []error {
    return this.Errors
}
