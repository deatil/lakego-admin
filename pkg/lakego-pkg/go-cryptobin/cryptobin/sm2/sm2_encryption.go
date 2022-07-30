package sm2

import (
    "errors"
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"
)

// 公钥加密
func (this SM2) Encrypt() SM2 {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    this.paredData, this.Error = sm2.EncryptAsn1(this.publicKey, this.data, rand.Reader)

    return this
}

// 私钥解密
func (this SM2) Decrypt() SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.paredData, this.Error = sm2.DecryptAsn1(this.privateKey, this.data)

    return this
}
