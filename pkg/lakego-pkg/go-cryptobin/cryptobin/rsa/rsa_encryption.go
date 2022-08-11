package rsa

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool"
)

// 公钥加密
func (this Rsa) Encrypt() Rsa {
    if this.publicKey == nil {
        err := errors.New("Rsa: [Encrypt()] publicKey error.")
        return this.AppendError(err)
    }

    paredData, err := pubKeyByte(this.publicKey, this.data, true)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.paredData = paredData
    
    return this
}

// 私钥解密
func (this Rsa) Decrypt() Rsa {
    if this.privateKey == nil {
        err := errors.New("Rsa: [Decrypt()] privateKey error.")
        return this.AppendError(err)
    }

    paredData, err := priKeyByte(this.privateKey, this.data, false)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.paredData = paredData
    
    return this
}

// ====================

// 私钥加密
func (this Rsa) PriKeyEncrypt() Rsa {
    if this.privateKey == nil {
        err := errors.New("Rsa: [PriKeyEncrypt()] privateKey error.")
        return this.AppendError(err)
    }

    paredData, err := priKeyByte(this.privateKey, this.data, true)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.paredData = paredData
    
    return this
}

// 公钥解密
func (this Rsa) PubKeyDecrypt() Rsa {
    if this.publicKey == nil {
        err := errors.New("Rsa: [PubKeyDecrypt()] publicKey error.")
        return this.AppendError(err)
    }

    paredData, err := pubKeyByte(this.publicKey, this.data, false)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.paredData = paredData
    
    return this
}

// ====================

// OAEP公钥加密
func (this Rsa) EncryptOAEP(typ ...string) Rsa {
    if this.publicKey == nil {
        err := errors.New("Rsa: [EncryptOAEP()] publicKey error.")
        return this.AppendError(err)
    }

    hashType := "SHA1"
    if len(typ) > 0 {
        hashType = typ[0]
    }

    newHash := tool.NewHash().GetHash(hashType)

    paredData, err := rsa.EncryptOAEP(newHash(), rand.Reader, this.publicKey, this.data, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this
}

// OAEP私钥解密
func (this Rsa) DecryptOAEP(typ ...string) Rsa {
    if this.privateKey == nil {
        err := errors.New("Rsa: [DecryptOAEP()] privateKey error.")
        return this.AppendError(err)
    }

    hashType := "SHA1"
    if len(typ) > 0 {
        hashType = typ[0]
    }

    newHash := tool.NewHash().GetHash(hashType)

    paredData, err := rsa.DecryptOAEP(newHash(), rand.Reader, this.privateKey, this.data, nil)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.paredData = paredData

    return this
}
