package jceks

import (
    "crypto/dsa"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

func init() {
    // add PrivateKey
    AddKey(GetStructName(&dsa.PrivateKey{}), func() Key {
        return new(PublicKeyDSA)
    })
    AddKey(GetStructName(&rsa.PrivateKey{}), func() Key {
        return new(PublicKeyRSA)
    })
    AddKey(GetStructName(&ecdsa.PrivateKey{}), func() Key {
        return new(PublicKeyECDSA)
    })
    AddKey(GetStructName(ed25519.PrivateKey{}), func() Key {
        return new(PublicKeyEdDSA)
    })
    AddKey(GetStructName(&sm2.PrivateKey{}), func() Key {
        return new(PublicKeySM2)
    })

    // add PublicKey
    AddKey(GetStructName(&dsa.PublicKey{}), func() Key {
        return new(PublicKeyDSA)
    })
    AddKey(GetStructName(&rsa.PublicKey{}), func() Key {
        return new(PublicKeyRSA)
    })
    AddKey(GetStructName(&ecdsa.PublicKey{}), func() Key {
        return new(PublicKeyECDSA)
    })
    AddKey(GetStructName(ed25519.PublicKey{}), func() Key {
        return new(PublicKeyEdDSA)
    })
    AddKey(GetStructName(&sm2.PublicKey{}), func() Key {
        return new(PublicKeySM2)
    })
}
