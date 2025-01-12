package ssh

import (
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

func init() {
    AddKey(GetStructName(&rsa.PrivateKey{}), func() Key {
        return new(KeyRSA)
    })
    AddKey(ssh.KeyAlgoRSA, func() Key {
        return new(KeyRSA)
    })

    AddKey(GetStructName(&dsa.PrivateKey{}), func() Key {
        return new(KeyDSA)
    })
    AddKey(ssh.KeyAlgoDSA, func() Key {
        return new(KeyDSA)
    })

    AddKey(GetStructName(&ecdsa.PrivateKey{}), func() Key {
        return new(KeyECDSA)
    })
    AddKey(ssh.KeyAlgoECDSA256, func() Key {
        return new(KeyECDSA)
    })
    AddKey(ssh.KeyAlgoECDSA384, func() Key {
        return new(KeyECDSA)
    })
    AddKey(ssh.KeyAlgoECDSA521, func() Key {
        return new(KeyECDSA)
    })

    AddKey(GetStructName(ed25519.PrivateKey{}), func() Key {
        return new(KeyEdDSA)
    })
    AddKey(ssh.KeyAlgoED25519, func() Key {
        return new(KeyEdDSA)
    })

    AddKey(GetStructName(&sm2.PrivateKey{}), func() Key {
        return new(KeySM2)
    })
    AddKey(KeyAlgoSM2, func() Key {
        return new(KeySM2)
    })
}
