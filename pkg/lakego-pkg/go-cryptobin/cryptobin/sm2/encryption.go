package sm2

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// 公钥加密
func (this SM2) Encrypt() SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: publicKey error.")
        return this.AppendError(err)
    }

    parsedData, err := sm2.Encrypt(rand.Reader, this.publicKey, this.data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密
func (this SM2) Decrypt() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    parsedData, err := sm2.Decrypt(this.privateKey, this.data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// ================

// 公钥加密，返回 asn.1 编码格式的密文内容
func (this SM2) EncryptAsn1() SM2 {
    parsedData, err := sm2.EncryptAsn1(rand.Reader, this.publicKey, this.data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密，解析 asn.1 编码格式的密文内容
func (this SM2) DecryptAsn1() SM2 {
    parsedData, err := sm2.DecryptAsn1(this.privateKey, this.data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
