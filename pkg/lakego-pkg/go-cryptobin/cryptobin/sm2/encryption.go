package sm2

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// 公钥加密
func (this SM2) Encrypt() SM2 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
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
        err := errors.New("privateKey empty.")
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
func (this SM2) EncryptASN1() SM2 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := sm2.EncryptASN1(rand.Reader, this.publicKey, this.data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密，解析 asn.1 编码格式的密文内容
func (this SM2) DecryptASN1() SM2 {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := sm2.DecryptASN1(this.privateKey, this.data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
