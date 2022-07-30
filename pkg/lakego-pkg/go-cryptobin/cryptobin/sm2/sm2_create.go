package sm2

import (
    "errors"

    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"
)

// 国密私钥
func (this SM2) CreatePrivateKey() SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.keyData, this.Error = x509.WritePrivateKeyToPem(this.privateKey, nil)

    return this
}

// 国密私钥带密码
func (this SM2) CreatePrivateKeyWithPassword(password string) SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.keyData, this.Error = x509.WritePrivateKeyToPem(this.privateKey, []byte(password))

    return this
}

// 国密公钥
func (this SM2) CreatePublicKey() SM2 {
    var publicKey *sm2.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("privateKey error.")

            return this
        }

        publicKey = &this.privateKey.PublicKey
    } else {
        publicKey = this.publicKey
    }

    this.keyData, this.Error = x509.WritePublicKeyToPem(publicKey)

    return this
}
