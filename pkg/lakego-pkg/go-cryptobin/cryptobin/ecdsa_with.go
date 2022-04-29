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
func (this Ecdsa) WithCurve(curve string) Ecdsa {
    switch {
        case curve == "P521":
            this.curve = elliptic.P521()
        case curve == "P384":
            this.curve = elliptic.P384()
        case curve == "P256":
            this.curve = elliptic.P256()
        case curve == "P224":
            this.curve = elliptic.P224()
    }

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
func (this Ecdsa) WithSignHash(hash string) Ecdsa {
    this.signHash = hash

    return this
}

// 设置错误
func (this Ecdsa) WithError(err error) Ecdsa {
    this.Error = err

    return this
}
