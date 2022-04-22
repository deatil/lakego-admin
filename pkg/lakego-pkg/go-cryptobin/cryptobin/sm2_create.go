package cryptobin

import (
    "github.com/tjfoc/gmsm/x509"
)

// 国密 PKCS8 私钥
func (this SM2) CreateSM2PrivateKey() SM2 {
    this.keyData, this.Error = x509.WritePrivateKeyToPem(this.privateKey, nil)

    return this
}

// 国密 PKCS8 私钥带密码
func (this SM2) CreateSM2PrivateKeyWithPassword(password string) SM2 {
    this.keyData, this.Error = x509.WritePrivateKeyToPem(this.privateKey, []byte(password))

    return this
}

// 国密 公钥
func (this SM2) CreateSM2PublicKey() SM2 {
    publicKey := this.privateKey.PublicKey

    this.keyData, this.Error = x509.WritePublicKeyToPem(&publicKey)

    return this
}
