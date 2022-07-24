package cryptobin

import (
    "errors"
    "crypto/ed25519"
)

// 生成公钥
func (this EdDSA) MakePublicKey() EdDSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    // 导出公钥
    this.publicKey = this.privateKey.Public().(ed25519.PublicKey)

    return this
}
