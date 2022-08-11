package eddsa

import (
    "errors"
    "crypto/ed25519"
)

// 生成公钥
func (this EdDSA) MakePublicKey() EdDSA {
    if this.privateKey == nil {
        err := errors.New("EdDSA: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = this.privateKey.Public().(ed25519.PublicKey)

    return this
}
