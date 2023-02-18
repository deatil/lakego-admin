package curve25519

import (
    "github.com/deatil/go-cryptobin/dh/curve25519"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this Curve25519) GetPrivateKey() *curve25519.PrivateKey {
    return this.privateKey
}

// 获取 X 16进制字符
func (this Curve25519) GetPrivateKeyXHexString() string {
    data := this.privateKey.X

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data)

    return dataHex
}

// 获取 PublicKey
func (this Curve25519) GetPublicKey() *curve25519.PublicKey {
    return this.publicKey
}

// 获取 Y 16进制字符
func (this Curve25519) GetPublicKeyYHexString() string {
    data := this.publicKey.Y

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data)

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

// 获取错误
func (this Curve25519) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
