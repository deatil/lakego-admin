package dsa

import (
    "errors"
)

// 生成公钥
func (this DSA) MakePublicKey() DSA {
    if this.privateKey == nil {
        err := errors.New("dsa: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}
