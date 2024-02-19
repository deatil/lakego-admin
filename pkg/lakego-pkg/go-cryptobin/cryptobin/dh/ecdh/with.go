package ecdh

import (
    "github.com/deatil/go-cryptobin/dh/ecdh"
)

// 设置 PrivateKey
func (this ECDH) WithPrivateKey(data *ecdh.PrivateKey) ECDH {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this ECDH) WithPublicKey(data *ecdh.PublicKey) ECDH {
    this.publicKey = data

    return this
}

// 设置散列方式
func (this ECDH) WithCurve(data ecdh.Curve) ECDH {
    this.curve = data

    return this
}

// 设置散列方式
// 可用参数 [P521 | P384 | P256 | P224]
func (this ECDH) SetCurve(name string) ECDH {
    var curve ecdh.Curve

    switch name {
        case "P521":
            curve = ecdh.P521()
        case "P384":
            curve = ecdh.P384()
        case "P256":
            curve = ecdh.P256()
        case "P224":
            curve = ecdh.P224()
        default:
            curve = ecdh.P224()
    }

    this.curve = curve

    return this
}

// 设置 keyData
func (this ECDH) WithKeyData(data []byte) ECDH {
    this.keyData = data

    return this
}

// 设置 secretData
func (this ECDH) WithSecretData(data []byte) ECDH {
    this.secretData = data

    return this
}

// 设置错误
func (this ECDH) WithErrors(errs []error) ECDH {
    this.Errors = errs

    return this
}
