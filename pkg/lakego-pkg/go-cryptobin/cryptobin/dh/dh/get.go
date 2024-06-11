package dh

import (
    "github.com/deatil/go-cryptobin/dh/dh"
)

// 获取 PrivateKey
func (this DH) GetPrivateKey() *dh.PrivateKey {
    return this.privateKey
}

// 获取 X 16进制字符
func (this DH) GetPrivateKeyXHexString() string {
    if this.privateKey == nil {
        return ""
    }

    data := this.privateKey.X.Text(16)

    return data
}

// 获取 PublicKey
func (this DH) GetPublicKey() *dh.PublicKey {
    return this.publicKey
}

// 获取 Y 16进制字符
func (this DH) GetPublicKeyYString() string {
    if this.publicKey == nil {
        return ""
    }

    data := this.publicKey.Y.Text(16)

    return data
}

// 获取 P 16进制字符
func (this DH) GetPublicKeyParametersPHexString() string {
    if this.publicKey == nil {
        return ""
    }

    data := this.publicKey.Parameters.P.Text(16)

    return data
}

// 获取 G 16进制字符
func (this DH) GetPublicKeyParametersGHexString() string {
    if this.publicKey == nil {
        return ""
    }

    data := this.publicKey.Parameters.G.Text(16)

    return data
}

// 获取 keyData
func (this DH) GetKeyData() []byte {
    return this.keyData
}

// 获取分组
func (this DH) GetGroup() *dh.Group {
    return this.group
}

// 获取 secretData
func (this DH) GetSecretData() []byte {
    return this.secretData
}

// 获取错误
func (this DH) GetErrors() []error {
    return this.Errors
}
