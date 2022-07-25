package cryptobin

import (
    "errors"
    "crypto/x509"
    "crypto/ed25519"
    "encoding/pem"
)

// 私钥
func (this EdDSA) CreatePrivateKey() EdDSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "ED PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 公钥
func (this EdDSA) CreatePublicKey() EdDSA {
    var publicKey ed25519.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("privateKey error.")

            return this
        }

        publicKey = this.privateKey.Public().(ed25519.PublicKey)
    } else {
        publicKey = this.publicKey
    }

    x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        this.Error = err
        return this
    }

    publicBlock := &pem.Block{
        Type: "PUBLIC KEY",
        Bytes: x509PublicKey,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}
