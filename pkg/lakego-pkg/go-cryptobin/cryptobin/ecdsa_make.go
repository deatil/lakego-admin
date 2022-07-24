package cryptobin

import(
    "errors"
)

// 生成公钥
func (this Ecdsa) MakePublicKey() Ecdsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}
