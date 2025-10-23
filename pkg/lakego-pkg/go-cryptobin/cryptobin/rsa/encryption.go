package rsa

import (
    "bytes"
    "errors"
    "crypto"
    "crypto/rsa"
    "crypto/rand"

    cryptobin_rsa "github.com/deatil/go-cryptobin/pubkey/rsa"
)

type (
    // OAEPOptions is an interface for passing options to OAEP decryption using the
    // crypto.Decrypter interface.
    OAEPOptions = rsa.OAEPOptions

    // PKCS1v15DecryptOptions is for passing options to PKCS #1 v1.5 decryption using
    // the crypto.Decrypter interface.
    PKCS1v15DecryptOptions = rsa.PKCS1v15DecryptOptions
)

// 公钥加密
func (this RSA) Encrypt() RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := cryptobin_rsa.PublicKeyBytes(this.publicKey, this.data, true)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密
func (this RSA) Decrypt() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := cryptobin_rsa.PrivateKeyBytes(this.privateKey, this.data, false)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密带设置
func (this RSA) DecryptWithOpts(opts crypto.DecrypterOpts) RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := this.privateKey.Decrypt(rand.Reader, this.data, opts)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// ====================

// 私钥加密
func (this RSA) PrivateKeyEncrypt() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := cryptobin_rsa.PrivateKeyBytes(this.privateKey, this.data, true)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 公钥解密
func (this RSA) PublicKeyDecrypt() RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := cryptobin_rsa.PublicKeyBytes(this.publicKey, this.data, false)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// ====================

// OAEP公钥加密
func (this RSA) EncryptOAEP() RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := rsa.EncryptOAEP(this.oaepHash, rand.Reader, this.publicKey, this.data, this.oaepLabel)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// OAEP私钥解密
func (this RSA) DecryptOAEP() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := rsa.DecryptOAEP(this.oaepHash, rand.Reader, this.privateKey, this.data, this.oaepLabel)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// ====================

// 公钥加密
// rsa no padding encrypt
func (this RSA) LowerSafeEncrypt() RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := cryptobin_rsa.LowerSafeEncrypt(this.publicKey, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密
// rsa no padding decrypt
func (this RSA) LowerSafeDecrypt() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := cryptobin_rsa.LowerSafeDecrypt(this.privateKey, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// ====================

// 公钥加密, ECB 模式
func (this RSA) EncryptECB() RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    pub := this.GetPublicKey()
    plainText := this.data

    pubSize, plainTextSize := pub.Size()-11, len(plainText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < plainTextSize {
        endIndex := offSet + pubSize
        if endIndex > plainTextSize {
            endIndex = plainTextSize
        }

        rsa := this.FromBytes(plainText[offSet:endIndex]).Encrypt()

        err := rsa.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := rsa.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// 私钥解密, ECB 模式
func (this RSA) DecryptECB() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    pri := this.GetPrivateKey()
    cipherText := this.data

    priSize, cipherTextSize := pri.Size(), len(cipherText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + priSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        rsa := this.FromBytes(cipherText[offSet:endIndex]).Decrypt()

        err := rsa.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := rsa.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// 私钥解密, ECB 模式
func (this RSA) DecryptECBWithOpts(opts crypto.DecrypterOpts) RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    pri := this.GetPrivateKey()
    cipherText := this.data

    priSize, cipherTextSize := pri.Size(), len(cipherText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + priSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        rsa := this.FromBytes(cipherText[offSet:endIndex]).
            DecryptWithOpts(opts)

        err := rsa.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := rsa.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// ====================

// 私钥加密, ECB 模式
func (this RSA) PrivateKeyEncryptECB() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    pri := this.GetPrivateKey()
    plainText := this.data

    priSize, plainTextSize := pri.Size()-11, len(plainText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < plainTextSize {
        endIndex := offSet + priSize
        if endIndex > plainTextSize {
            endIndex = plainTextSize
        }

        rsa := this.FromBytes(plainText[offSet:endIndex]).PrivateKeyEncrypt()

        err := rsa.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := rsa.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this}

// 公钥解密, ECB 模式
func (this RSA) PublicKeyDecryptECB() RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    pub := this.GetPublicKey()
    cipherText := this.data

    pubSize, cipherTextSize := pub.Size(), len(cipherText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + pubSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        rsa := this.FromBytes(cipherText[offSet:endIndex]).PublicKeyDecrypt()

        err := rsa.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := rsa.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// ====================

// OAEP公钥加密, ECB 模式
func (this RSA) EncryptOAEPECB() RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    pub := this.GetPublicKey()
    plainText := this.data

    pubSize, plainTextSize := pub.Size()-2*this.oaepHash.Size()-2, len(plainText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < plainTextSize {
        endIndex := offSet + pubSize
        if endIndex > plainTextSize {
            endIndex = plainTextSize
        }

        rsa := this.FromBytes(plainText[offSet:endIndex]).EncryptOAEP()

        err := rsa.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := rsa.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}

// OAEP私钥解密, ECB 模式
func (this RSA) DecryptOAEPECB() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    pri := this.GetPrivateKey()
    cipherText := this.data

    priSize, cipherTextSize := pri.Size(), len(cipherText)

    offSet := 0
    buffer := bytes.Buffer{}

    for offSet < cipherTextSize {
        endIndex := offSet + priSize
        if endIndex > cipherTextSize {
            endIndex = cipherTextSize
        }

        rsa := this.FromBytes(cipherText[offSet:endIndex]).DecryptOAEP()

        err := rsa.Error()
        if err != nil {
            return this.AppendError(err)
        }

        bytesOnce := rsa.ToBytes()

        buffer.Write(bytesOnce)
        offSet = endIndex
    }

    this.parsedData = buffer.Bytes()

    return this
}
