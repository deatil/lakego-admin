package eddsa

import (
    "crypto/ed25519"
)

// 设置 PrivateKey
func (this EdDSA) WithPrivateKey(data ed25519.PrivateKey) EdDSA {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this EdDSA) WithPublicKey(data ed25519.PublicKey) EdDSA {
    this.publicKey = data

    return this
}

// 设置 data
func (this EdDSA) WithData(data []byte) EdDSA {
    this.data = data

    return this
}

// 设置 paredData
func (this EdDSA) WithParedData(data []byte) EdDSA {
    this.paredData = data

    return this
}

// 设置 veryed
func (this EdDSA) WithVeryed(data bool) EdDSA {
    this.veryed = data

    return this
}

// 设置错误
func (this EdDSA) WithError(err error) EdDSA {
    this.Error = err

    return this
}
