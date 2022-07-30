package dsa

import (
    "errors"
)

// 生成公钥
func (this DSA) MakePublicKey() DSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    // 导出公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}
