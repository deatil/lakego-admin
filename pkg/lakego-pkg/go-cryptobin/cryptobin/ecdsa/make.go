package ecdsa

import(
    "errors"
)

// 生成公钥
func (this Ecdsa) MakePublicKey() Ecdsa {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("Ecdsa: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}
