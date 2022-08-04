package rsa

import(
    "errors"
)

// 生成公钥
func (this Rsa) MakePublicKey() Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("Rsa: [MakePublicKey()] privateKey error.")
        return this
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}
