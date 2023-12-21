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

    parsedData, err := this.publicKey.Encrypt(rand.Reader, this.data)
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

    parsedData, err := this.privateKey.Decrypt(rand.Reader, this.data, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
