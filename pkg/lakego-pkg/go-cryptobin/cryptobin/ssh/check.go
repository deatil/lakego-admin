package ssh

import (
    "crypto"
    "reflect"
)

type keyEqual interface {
    Equal(x crypto.PublicKey) bool
}

// Check Key Pair
func (this SSH) CheckKeyPair() bool {
    // get publicKey from privateKey
    pubKeyFromPriKey := this.MakePublicKey().publicKey

    if pubKeyFromPriKey == nil || this.publicKey == nil {
        return false
    }

    if pubkeyEqual, ok := pubKeyFromPriKey.(keyEqual); ok {
        if pubkeyEqual.Equal(this.publicKey) {
            return true
        }
    }

    if reflect.DeepEqual(pubKeyFromPriKey, this.publicKey) {
        return true
    }

    return false
}
