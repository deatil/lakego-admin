package ecgdsa

import(
    "errors"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// 生成公钥
func (this SSH) MakePublicKey() SSH {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    switch prikey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            this.publicKey = &prikey.PublicKey
        case *dsa.PrivateKey:
            this.publicKey = &prikey.PublicKey
        case *ecdsa.PrivateKey:
            this.publicKey = &prikey.PublicKey
        case ed25519.PrivateKey:
            this.publicKey = prikey.Public().(ed25519.PublicKey)
        case *sm2.PrivateKey:
            this.publicKey = &prikey.PublicKey
    }

    return this
}
