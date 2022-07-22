package cryptobin

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
)

// 证书
func (this CA) CreateCA() CA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    if this.publicKey == nil {
        this.publicKey = &this.privateKey.PublicKey
    }

    caBytes, err := x509.CreateCertificate(rand.Reader, this.csr, this.csr, this.publicKey, this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    caBlock := &pem.Block{
        Type: "CERTIFICATE",
        Bytes: caBytes,
    }

    this.keyData = pem.EncodeToMemory(caBlock)

    return this
}

// TLS 证书
func (this CA) CreateTLS(ca *x509.Certificate) CA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    if this.publicKey == nil {
        this.publicKey = &this.privateKey.PublicKey
    }

    caBytes, err := x509.CreateCertificate(rand.Reader, this.csr, ca, this.publicKey, this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    caBlock := &pem.Block{
        Type: "CERTIFICATE",
        Bytes: caBytes,
    }

    this.keyData = pem.EncodeToMemory(caBlock)

    return this
}

// 私钥
func (this CA) CreatePrivateKey() CA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")

        return this
    }

    x509PrivateKey := x509.MarshalPKCS1PrivateKey(this.privateKey)

    privateBlock := &pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 公钥
func (this CA) CreatePublicKey() CA {
    var publicKey *rsa.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("privateKey error.")

            return this
        }

        publicKey = &this.privateKey.PublicKey
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
