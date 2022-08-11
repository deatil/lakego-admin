package curve25519

import (
    "errors"
)

// 生成公钥
func (this Curve25519) MakePublicKey() Curve25519 {
    if this.privateKey == nil {
        err := errors.New("Curve25519: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}
