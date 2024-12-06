package elgamal

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/elgamal"
)

// 公钥加密
func (this ElGamal) Encrypt() ElGamal {
    switch this.encoding {
        case EncodingASN1:
            return this.EncryptASN1()
        case EncodingBytes:
            return this.EncryptBytes()
    }

    return this.EncryptASN1()
}

// 私钥解密
func (this ElGamal) Decrypt() ElGamal {
    switch this.encoding {
        case EncodingASN1:
            return this.DecryptASN1()
        case EncodingBytes:
            return this.DecryptBytes()
    }

    return this.DecryptASN1()
}

// ====================

// 公钥加密
func (this ElGamal) EncryptBytes() ElGamal {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := elgamal.EncryptBytes(rand.Reader, this.publicKey, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密
func (this ElGamal) DecryptBytes() ElGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := elgamal.DecryptBytes(this.privateKey, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// ================

// 公钥加密
func (this ElGamal) EncryptASN1() ElGamal {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
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
func (this ElGamal) DecryptASN1() ElGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := this.privateKey.Decrypt(rand.Reader, this.data, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
