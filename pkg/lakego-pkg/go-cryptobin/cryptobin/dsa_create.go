package cryptobin

import (
    "errors"
    "crypto/dsa"
    "encoding/pem"
)

// 私钥
func (this DSA) CreatePrivateKey() DSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    privateKeyBytes, err := this.MarshalPrivateKey(*this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 公钥
func (this DSA) CreatePublicKey() DSA {
    var publicKey *dsa.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("privateKey error.")

            return this
        }

        publicKey = &this.privateKey.PublicKey
    } else {
        publicKey = this.publicKey
    }

    publicKeyBytes, err := this.MarshalPublicKey(*publicKey)
    if err != nil {
        this.Error = err
        return this
    }

    publicBlock := &pem.Block{
        Type: "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}
