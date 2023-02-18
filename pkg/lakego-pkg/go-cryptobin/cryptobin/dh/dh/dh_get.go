package dh

import (
    "github.com/deatil/go-cryptobin/dh/dh"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this Dh) GetPrivateKey() *dh.PrivateKey {
    return this.privateKey
}

// 获取 X 16进制字符
func (this Dh) GetPrivateKeyXHexString() string {
    if this.privateKey == nil {
        return ""
    }

    data := this.privateKey.X.Text(16)

    return data
}

// 获取 PublicKey
func (this Dh) GetPublicKey() *dh.PublicKey {
    return this.publicKey
}

// 获取 Y 16进制字符
func (this Dh) GetPublicKeyYHexString() string {
    if this.publicKey == nil {
        return ""
    }

    data := this.publicKey.Y.Text(16)

    return data
}

// 获取 P 16进制字符
func (this Dh) GetPublicKeyParametersPHexString() string {
    if this.publicKey == nil {
        return ""
    }

    data := this.publicKey.Parameters.P.Text(16)

    return data
}

// 获取 G 16进制字符
func (this Dh) GetPublicKeyParametersGHexString() string {
    if this.publicKey == nil {
        return ""
    }

    data := this.publicKey.Parameters.G.Text(16)

    return data
}

// 获取 keyData
func (this Dh) GetKeyData() []byte {
    return this.keyData
}

// 获取分组
func (this Dh) GetGroup() *dh.Group {
    return this.group
}

// 获取 secretData
func (this Dh) GetSecretData() []byte {
    return this.secretData
}

// 获取错误
func (this Dh) GetErrors() []error {
    return this.Errors
}

// 获取错误
func (this Dh) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
