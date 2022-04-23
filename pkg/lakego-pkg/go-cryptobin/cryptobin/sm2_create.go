package cryptobin

import (
    "errors"

    "github.com/tjfoc/gmsm/x509"
)

// 国密 PKCS8 私钥
func (this SM2) CreatePrivateKey() SM2 {
    this.keyData, this.Error = x509.WritePrivateKeyToPem(this.privateKey, nil)

    return this
}

// 国密 PKCS8 私钥带密码
func (this SM2) CreatePrivateKeyWithPassword(password string) SM2 {
    this.keyData, this.Error = x509.WritePrivateKeyToPem(this.privateKey, []byte(password))

    return this
}

// 国密 公钥
func (this SM2) CreatePublicKey() SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")

        return this
    }

    publicKey := this.privateKey.PublicKey

    this.keyData, this.Error = x509.WritePublicKeyToPem(&publicKey)

    return this
}
