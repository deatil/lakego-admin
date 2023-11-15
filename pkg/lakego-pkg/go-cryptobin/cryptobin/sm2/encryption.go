package sm2

import (
    "errors"
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"
)

// 公钥加密
func (this SM2) Encrypt() SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: publicKey error.")
        return this.AppendError(err)
    }

    parsedData, err := sm2.Encrypt(this.publicKey, this.data, rand.Reader, this.mode)
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
    data, err := sm2.Encrypt(this.publicKey, this.data, rand.Reader, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    var parsedData []byte

    if this.mode == C1C2C3 {
        parsedData, err = cipherC1C2C3Marshal(data)
    } else {
        parsedData, err = sm2.CipherMarshal(data)
    }

    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密，解析 asn.1 编码格式的密文内容
func (this SM2) DecryptAsn1() SM2 {
    var data []byte
    var err error

    if this.mode == C1C2C3 {
        data, err = cipherC1C2C3Unmarshal(this.data)
    } else {
        data, err = sm2.CipherUnmarshal(this.data)
    }

    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := sm2.Decrypt(this.privateKey, data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
