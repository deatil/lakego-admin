package curve25519

import (
    "github.com/deatil/go-cryptobin/dh/curve25519"
)

// 设置 PrivateKey
func (this Curve25519) WithPrivateKey(data *curve25519.PrivateKey) Curve25519 {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Curve25519) WithPublicKey(data *curve25519.PublicKey) Curve25519 {
    this.publicKey = data

    return this
}

// 设置 keyData
func (this Curve25519) WithKeyData(data []byte) Curve25519 {
    this.keyData = data

    return this
}

// 设置 secretData
func (this Curve25519) WithSecretData(data []byte) Curve25519 {
    this.secretData = data

    return this
}

// 设置错误
func (this Curve25519) WithErrors(errs []error) Curve25519 {
    this.Errors = errs

    return this
}

// 添加错误
func (this Curve25519) AppendError(err ...error) Curve25519 {
    this.Errors = append(this.Errors, err...)

    return this
}
