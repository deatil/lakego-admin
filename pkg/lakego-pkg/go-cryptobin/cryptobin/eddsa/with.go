package eddsa

import (
    "crypto"
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

// 设置 options
func (this EdDSA) WithOptions(op *Options) EdDSA {
    this.options = op

    return this
}

// 设置 options
// 可用类型 [Ed25519ph | Ed25519ctx | Ed25519]
func (this EdDSA) SetOptions(name string, context ...string) EdDSA {
    ctx := ""
    if len(context) > 0 {
        ctx = context[0]
    }

    switch name {
        case "Ed25519ph":
            this.options = &Options{
                Hash:    crypto.SHA512,
                Context: ctx,
            }
        case "Ed25519ctx":
            this.options = &Options{
                Hash:    crypto.Hash(0),
                Context: ctx,
            }
        case "Ed25519":
            this.options = &Options{
                Hash: crypto.Hash(0),
            }
    }

    return this
}

// 设置 data
func (this EdDSA) WithData(data []byte) EdDSA {
    this.data = data

    return this
}

// 设置 parsedData
func (this EdDSA) WithParedData(data []byte) EdDSA {
    this.parsedData = data

    return this
}

// 设置 verify
func (this EdDSA) WithVerify(data bool) EdDSA {
    this.verify = data

    return this
}

// 设置错误
func (this EdDSA) WithErrors(errs []error) EdDSA {
    this.Errors = errs

    return this
}
