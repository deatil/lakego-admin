package ssh

import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "golang.org/x/crypto/ssh"

    "github.com/tjfoc/gmsm/sm2"
)

func init() {
    AddKey(GetStructName(&rsa.PrivateKey{}), func() Key {
        return new(KeyRsa)
    })
    AddKey(ssh.KeyAlgoRSA, func() Key {
        return new(KeyRsa)
    })

    AddKey(GetStructName(&ecdsa.PrivateKey{}), func() Key {
        return new(KeyEcdsa)
    })
    AddKey(ssh.KeyAlgoECDSA256, func() Key {
        return new(KeyEcdsa)
    })
    AddKey(ssh.KeyAlgoECDSA384, func() Key {
        return new(KeyEcdsa)
    })
    AddKey(ssh.KeyAlgoECDSA521, func() Key {
        return new(KeyEcdsa)
    })

    AddKey(GetStructName(ed25519.PrivateKey{}), func() Key {
        return new(KeyEdDsa)
    })
    AddKey(ssh.KeyAlgoED25519, func() Key {
        return new(KeyEdDsa)
    })

    AddKey(GetStructName(&sm2.PrivateKey{}), func() Key {
        return new(KeySM2)
    })
    AddKey(KeyAlgoSM2, func() Key {
        return new(KeySM2)
    })
}
