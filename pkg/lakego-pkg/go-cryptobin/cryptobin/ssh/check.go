package ecgdsa

import (
    "crypto"
    "reflect"
)

type publicKeyEqual interface {
    Equal(x crypto.PublicKey) bool
}

// 检测公钥私钥是否匹配
func (this SSH) CheckKeyPair() bool {
    // 私钥导出的公钥
    pubKeyFromPriKey := this.MakePublicKey().publicKey

    if pubKeyFromPriKey == nil || this.publicKey == nil {
        return false
    }

    if pubkeyEqual, ok := pubKeyFromPriKey.(publicKeyEqual); ok {
        if pubkeyEqual.Equal(this.publicKey) {
            return true
        }
    }

    if reflect.DeepEqual(pubKeyFromPriKey, this.publicKey) {
        return true
    }

    return false
}
