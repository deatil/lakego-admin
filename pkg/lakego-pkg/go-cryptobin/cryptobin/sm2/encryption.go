package sm2

import (
    "bytes"
    "errors"
    "crypto/rand"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// 公钥加密
func (this SM2) Encrypt() SM2 {
    switch this.encoding {
        case EncodingASN1:
            return this.EncryptASN1()
        case EncodingBytes:
            return this.EncryptBytes()
    }

    return this.EncryptBytes()
}

// 私钥解密
func (this SM2) Decrypt() SM2 {
    switch this.encoding {
        case EncodingASN1:
            return this.DecryptASN1()
        case EncodingBytes:
            return this.DecryptBytes()
    }

    return this.DecryptBytes()
}

// ====================

// 公钥加密
func (this SM2) EncryptBytes() SM2 {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/sm2: publicKey empty.")
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
func (this SM2) DecryptBytes() SM2 {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/sm2: privateKey empty.")
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
        err := errors.New("go-cryptobin/sm2: publicKey empty.")
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
        err := errors.New("go-cryptobin/sm2: privateKey empty.")
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

// 公钥加密
func (this SM2) EncryptECB() SM2 {
    switch this.encoding {
        case EncodingASN1:
            return this.EncryptASN1ECB()
        case EncodingBytes:
            return this.EncryptBytesECB()
    }

    return this.EncryptBytesECB()
}

// 私钥解密
func (this SM2) DecryptECB() SM2 {
    switch this.encoding {
        case EncodingASN1:
            return this.DecryptASN1ECB()
        case EncodingBytes:
            return this.DecryptBytesECB()
    }

    return this.DecryptBytesECB()
}

// ====================

const ecbSize = 256

// 公钥加密, ECB 模式
func (this SM2) EncryptBytesECB() SM2 {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/sm2: publicKey empty.")
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

        enc := this.
            FromBytes(plainText[offSet:endIndex]).
            Encrypt()

        err := enc.Error()
        if err != nil {
            return this.AppendError(err)
        }

        buffer.Write(enc.ToBytes())
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// 私钥解密, ECB 模式
func (this SM2) DecryptBytesECB() SM2 {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/sm2: privateKey empty.")
        return this.AppendError(err)
    }

    cipherText := this.data

    size := 32
    if this.signHash != nil {
        size = this.signHash().Size()
    }

    byteLen := (this.privateKey.Curve.Params().BitSize + 7) / 8

    priSize := 1 + 2*byteLen + size + ecbSize
    cipherTextSize := len(cipherText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + priSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        dec := this.
            FromBytes(cipherText[offSet:endIndex]).
            Decrypt()

        err := dec.Error()
        if err != nil {
            return this.AppendError(err)
        }

        buffer.Write(dec.ToBytes())
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// ====================

// 公钥加密，返回 asn.1 编码格式的密文内容, ECB 模式
func (this SM2) EncryptASN1ECB() SM2 {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/sm2: publicKey empty.")
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

        enc := this.
            FromBytes(plainText[offSet:endIndex]).
            EncryptASN1()

        err := enc.Error()
        if err != nil {
            return this.AppendError(err)
        }

        buffer.Write(enc.ToBytes())
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// 私钥解密，返回 asn.1 编码格式的密文内容, ECB 模式
func (this SM2) DecryptASN1ECB() SM2 {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/sm2: privateKey empty.")
        return this.AppendError(err)
    }

    cipherText := this.data

    buffer := bytes.Buffer{}
    for {
        var part asn1.RawValue
        cipherText, _ = asn1.Unmarshal(cipherText, &part)

        dec := this.
            FromBytes(part.FullBytes).
            DecryptASN1()

        err := dec.Error()
        if err != nil {
            return this.AppendError(err)
        }

        buffer.Write(dec.ToBytes())

        if cipherText == nil || len(cipherText) == 0 {
            break
        }
    }

    this.parsedData = buffer.Bytes()

    return this
}
