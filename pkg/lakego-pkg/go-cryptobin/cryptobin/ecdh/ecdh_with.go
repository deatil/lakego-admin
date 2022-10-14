package ecdh

import (
    "crypto/ecdh"
)

// 设置 PrivateKey
func (this Ecdh) WithPrivateKey(data *ecdh.PrivateKey) Ecdh {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Ecdh) WithPublicKey(data *ecdh.PublicKey) Ecdh {
    this.publicKey = data

    return this
}

// 设置散列方式
func (this Ecdh) WithCurve(data ecdh.Curve) Ecdh {
    this.curve = data

    return this
}

// 设置散列方式
// 可用参数 [P521 | P384 | P256 | X25519]
func (this Ecdh) SetCurve(name string) Ecdh {
    var curve ecdh.Curve

    switch name {
        case "P521":
            curve = ecdh.P521()
        case "P384":
            curve = ecdh.P384()
        case "P256":
            curve = ecdh.P256()
        case "X25519":
            curve = ecdh.X25519()
        default:
            curve = ecdh.P256()
    }

    this.curve = curve

    return this
}

// 设置 keyData
func (this Ecdh) WithKeyData(data []byte) Ecdh {
    this.keyData = data

    return this
}

// 设置 secretData
func (this Ecdh) WithSecretData(data []byte) Ecdh {
    this.secretData = data

    return this
}

// 设置错误
func (this Ecdh) WithErrors(errs []error) Ecdh {
    this.Errors = errs

    return this
}

// 添加错误
func (this Ecdh) AppendError(err ...error) Ecdh {
    this.Errors = append(this.Errors, err...)

    return this
}
