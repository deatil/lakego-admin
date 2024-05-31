package sm2

import (
    "bytes"
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

    parsedData, err := sm2.Encrypt(rand.Reader, this.publicKey, this.data, sm2.EncrypterOpts{
        Mode: this.mode,
        Hash: this.signHash,
    })
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

    parsedData, err := sm2.Decrypt(this.privateKey, this.data, sm2.EncrypterOpts{
        Mode: this.mode,
        Hash: this.signHash,
    })
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

    parsedData, err := sm2.EncryptASN1(rand.Reader, this.publicKey, this.data, sm2.EncrypterOpts{
        Mode: this.mode,
        Hash: this.signHash,
    })
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

    parsedData, err := sm2.DecryptASN1(this.privateKey, this.data, sm2.EncrypterOpts{
        Mode: this.mode,
        Hash: this.signHash,
    })
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// ====================

const ecbSize = 256

// 公钥加密, ECB 模式
func (this SM2) EncryptECB() SM2 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    plainText := this.data
    pubSize, plainTextSize := ecbSize, len(plainText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < plainTextSize {
        endIndex := offSet + pubSize
        if endIndex > plainTextSize {
            endIndex = plainTextSize
        }

        enc := this.FromBytes(plainText[offSet:endIndex]).Encrypt()

        err := enc.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := enc.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// 私钥解密, ECB 模式
func (this SM2) DecryptECB() SM2 {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    cipherText := this.data
    priSize, cipherTextSize := ecbSize, len(cipherText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + priSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        dec := this.FromBytes(cipherText[offSet:endIndex]).Decrypt()

        err := dec.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := dec.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// ====================

// 公钥加密，返回 asn.1 编码格式的密文内容, ECB 模式
func (this SM2) EncryptASN1ECB() SM2 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    plainText := this.data
    pubSize, plainTextSize := ecbSize, len(plainText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < plainTextSize {
        endIndex := offSet + pubSize
        if endIndex > plainTextSize {
            endIndex = plainTextSize
        }

        enc := this.FromBytes(plainText[offSet:endIndex]).EncryptASN1()

        err := enc.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := enc.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// 私钥解密，返回 asn.1 编码格式的密文内容, ECB 模式
func (this SM2) DecryptASN1ECB() SM2 {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    cipherText := this.data
    priSize, cipherTextSize := ecbSize, len(cipherText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + priSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        dec := this.FromBytes(cipherText[offSet:endIndex]).DecryptASN1()

        err := dec.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := dec.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}
