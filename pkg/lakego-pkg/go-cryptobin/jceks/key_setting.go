package jceks

import (
    "crypto/dsa"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "github.com/tjfoc/gmsm/sm2"
)

func init() {
    AddKey(GetStructName(&dsa.PrivateKey{}), func() Key {
        return new(KeyDSA)
    })
    AddKey(GetStructName(&rsa.PrivateKey{}), func() Key {
        return new(KeyRsa)
    })
    AddKey(GetStructName(&ecdsa.PrivateKey{}), func() Key {
        return new(KeyEcdsa)
    })
    AddKey(GetStructName(ed25519.PrivateKey{}), func() Key {
        return new(KeyEdDSA)
    })
    AddKey(GetStructName(&sm2.PrivateKey{}), func() Key {
        return new(KeySM2)
    })

    AddKey(GetStructName(&dsa.PublicKey{}), func() Key {
        return new(KeyDSA)
    })
    AddKey(GetStructName(&rsa.PublicKey{}), func() Key {
        return new(KeyRsa)
    })
    AddKey(GetStructName(&ecdsa.PublicKey{}), func() Key {
        return new(KeyEcdsa)
    })
    AddKey(GetStructName(ed25519.PublicKey{}), func() Key {
        return new(KeyEdDSA)
    })
    AddKey(GetStructName(&sm2.PublicKey{}), func() Key {
        return new(KeySM2)
    })
}
