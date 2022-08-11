package sm2

import (
    "errors"
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"
)

// 公钥加密
func (this SM2) Encrypt() SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: [Encrypt()] publicKey error.")
        return this.AppendError(err)
    }

    paredData, err := sm2.EncryptAsn1(this.publicKey, this.data, rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData
    
    return this
}

// 私钥解密
func (this SM2) Decrypt() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [Decrypt()] privateKey error.")
        return this.AppendError(err)
    }

    paredData, err := sm2.DecryptAsn1(this.privateKey, this.data)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.paredData = paredData

    return this
}
