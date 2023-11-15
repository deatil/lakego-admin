package elgamal

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/elgamal"
)

// 公钥加密
func (this EIGamal) Encrypt() EIGamal {
    if this.publicKey == nil {
        err := errors.New("EIGamal: publicKey error.")
        return this.AppendError(err)
    }

    parsedData, err := elgamal.EncryptAsn1(rand.Reader, this.publicKey, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密
func (this EIGamal) Decrypt() EIGamal {
    if this.privateKey == nil {
        err := errors.New("EIGamal: privateKey error.")
        return this.AppendError(err)
    }

    parsedData, err := elgamal.DecryptAsn1(this.privateKey, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
