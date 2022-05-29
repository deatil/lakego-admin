package cryptobin

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"
)

// 公钥加密
func (this Rsa) Encrypt() Rsa {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    this.paredData, this.Error = pubKeyByte(this.publicKey, this.data, true)

    return this
}

// 私钥解密
func (this Rsa) Decrypt() Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.paredData, this.Error = priKeyByte(this.privateKey, this.data, false)

    return this
}

// ====================

// 私钥加密
func (this Rsa) PriKeyEncrypt() Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.paredData, this.Error = priKeyByte(this.privateKey, this.data, true)

    return this
}

// 公钥解密
func (this Rsa) PubKeyDecrypt() Rsa {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    this.paredData, this.Error = pubKeyByte(this.publicKey, this.data, false)

    return this
}

// ====================

// OAEP公钥加密
func (this Rsa) EncryptOAEP(typ ...string) Rsa {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    hashType := "SHA1"
    if len(typ) > 0 {
        hashType = typ[0]
    }

    newHash := NewHash().GetHash(hashType)

    this.paredData, this.Error = rsa.EncryptOAEP(newHash(), rand.Reader, this.publicKey, this.data, nil)

    return this
}

// OAEP私钥解密
func (this Rsa) DecryptOAEP(typ ...string) Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    hashType := "SHA1"
    if len(typ) > 0 {
        hashType = typ[0]
    }

    newHash := NewHash().GetHash(hashType)

    this.paredData, this.Error = rsa.DecryptOAEP(newHash(), rand.Reader, this.privateKey, this.data, nil)

    return this
}
