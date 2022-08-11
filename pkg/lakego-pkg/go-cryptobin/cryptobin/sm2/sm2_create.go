package sm2

import (
    "errors"

    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"
)

// 生成私钥 pem 数据
// 使用:
// obj := New().GenerateKey()
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this SM2) CreatePrivateKey() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [CreatePrivateKey()] privateKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePrivateKeyToPem(this.privateKey, nil)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.keyData = keyData
    
    return this
}

// 生成私钥带密码 pem 数据
func (this SM2) CreatePrivateKeyWithPassword(password string) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [CreatePrivateKeyWithPassword()] privateKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePrivateKeyToPem(this.privateKey, []byte(password))
    if err != nil {
        return this.AppendError(err)
    }
    
    this.keyData = keyData
    
    return this
}

// 生成公钥 pem 数据
func (this SM2) CreatePublicKey() SM2 {
    var publicKey *sm2.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            err := errors.New("SM2: [CreatePublicKey()] privateKey error.")
            return this.AppendError(err)
        }

        publicKey = &this.privateKey.PublicKey
    } else {
        publicKey = this.publicKey
    }

    keyData, err := x509.WritePublicKeyToPem(publicKey)
    if err != nil {
        return this.AppendError(err)
    }
    
    this.keyData = keyData

    return this
}
