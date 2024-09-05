package pkcs12

import (
    "crypto/dsa"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/pubkey/gost"
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
    AddKey(GetStructName(&gost.PrivateKey{}), func() Key {
        return new(KeyGost)
    })
}
