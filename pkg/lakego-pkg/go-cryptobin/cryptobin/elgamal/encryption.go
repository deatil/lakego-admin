package elgamal

import (
    "errors"
    "crypto/rand"
)

// 公钥加密
func (this EIGamal) Encrypt() EIGamal {
    if this.publicKey == nil {
        err := errors.New("EIGamal: publicKey error.")
        return this.AppendError(err)
    }

    paredData, err := this.publicKey.EncryptAsn1(rand.Reader, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this
}

// 私钥解密
func (this EIGamal) Decrypt() EIGamal {
    if this.privateKey == nil {
        err := errors.New("EIGamal: privateKey error.")
        return this.AppendError(err)
    }

    paredData, err := this.privateKey.DecryptAsn1(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this
}
