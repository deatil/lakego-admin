package ecdh

import (
    "errors"
)

// 生成公钥
func (this Ecdh) MakePublicKey() Ecdh {
    if this.privateKey == nil {
        this.Error = errors.New("Ecdh: [MakePublicKey()] privateKey error.")
        return this
    }

    // 导出公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}
