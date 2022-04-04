package cryptobin

import (
    "crypto/ecdsa"
    "crypto/elliptic"
)

// 设置 PrivateKey
func (this Ecdsa) WithPrivateKey(data *ecdsa.PrivateKey) Ecdsa {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Ecdsa) WithPublicKey(data *ecdsa.PublicKey) Ecdsa {
    this.publicKey = data

    return this
}

// 设置 data
// 可选 [P521 | P384 | P256 | P224]
func (this Ecdsa) WithCurve(hash string) Ecdsa {
    var curve elliptic.Curve

    if hash == "P521" {
        curve = elliptic.P521()
    } else if hash == "P384" {
        curve = elliptic.P384()
    } else if hash == "P256" {
        curve = elliptic.P256()
    } else if hash == "P224" {
        curve = elliptic.P224()
    }

    this.curve = curve

    return this
}

// 设置 data
func (this Ecdsa) WithData(data []byte) Ecdsa {
    this.data = data

    return this
}

// 设置 paredData
func (this Ecdsa) WithParedData(data []byte) Ecdsa {
    this.paredData = data

    return this
}

// 设置 hash 类型
func (this Ecdsa) WithSignHash(data string) Ecdsa {
    this.signHash = data

    return this
}

// 设置错误
func (this Ecdsa) WithError(err error) Ecdsa {
    this.Error = err

    return this
}
