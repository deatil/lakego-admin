package ecdh

import (
    "crypto/ecdh"
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
// 可用参数 [P521 | P384 | P256 | X25519]
func (this ECDH) SetCurve(curve string) ECDH {
    switch curve {
        case "P521":
            this.curve = ecdh.P521()
        case "P384":
            this.curve = ecdh.P384()
        case "P256":
            this.curve = ecdh.P256()
        case "X25519":
            this.curve = ecdh.X25519()
    }

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
