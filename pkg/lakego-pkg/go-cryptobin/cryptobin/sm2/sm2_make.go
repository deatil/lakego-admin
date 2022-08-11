package sm2

import(
    "errors"
)

// 生成公钥
func (this SM2) MakePublicKey() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}
