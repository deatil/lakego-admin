package cryptobin

import (
    "fmt"
    "errors"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/tjfoc/gmsm/sm2"
    sm2X509 "github.com/tjfoc/gmsm/x509"
)

// 证书请求
func (this CA) CreateCSR() CA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    var csrBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            certRequest := this.certRequest.(*sm2X509.CertificateRequest)
            csrBytes, err = sm2X509.CreateCertificateRequest(rand.Reader, certRequest, privateKey)

        default:
            certRequest := this.certRequest.(*x509.CertificateRequest)
            csrBytes, err = x509.CreateCertificateRequest(rand.Reader, certRequest, this.privateKey)
    }

    if err != nil {
        this.Error = err
        return this
    }

    csrBlock := &pem.Block{
        Type: "CERTIFICATE REQUEST",
        Bytes: csrBytes,
    }

    this.keyData = pem.EncodeToMemory(csrBlock)

    return this
}

// CA 证书
func (this CA) CreateCA() CA {
    if this.publicKey == nil || this.privateKey == nil {
        this.Error = errors.New("publicKey or privateKey error.")
        return this
    }

    var caBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            cert := this.cert.(*sm2X509.Certificate)
            publicKey := &privateKey.PublicKey

            caBytes, err = sm2X509.CreateCertificate(cert, cert, publicKey, privateKey)

        default:
            cert := this.cert.(*x509.Certificate)

            caBytes, err = x509.CreateCertificate(rand.Reader, cert, cert, this.publicKey, this.privateKey)
    }

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

// 自签名证书
func (this CA) CreateCert(ca any) CA {
    if this.publicKey == nil || this.privateKey == nil {
        this.Error = errors.New("publicKey or privateKey error.")
        return this
    }

    var certBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            newCert := this.cert.(*sm2X509.Certificate)
            newCa := ca.(*sm2X509.Certificate)
            publicKey := &privateKey.PublicKey

            certBytes, err = sm2X509.CreateCertificate(newCert, newCa, publicKey, privateKey)

        default:
            newCert := this.cert.(*x509.Certificate)
            newCa := ca.(*x509.Certificate)

            certBytes, err = x509.CreateCertificate(rand.Reader, newCert, newCa, this.publicKey, this.privateKey)
    }

    if err != nil {
        this.Error = err
        return this
    }

    certBlock := &pem.Block{
        Type: "CERTIFICATE",
        Bytes: certBytes,
    }

    this.keyData = pem.EncodeToMemory(certBlock)

    return this
}

// 私钥
func (this CA) CreatePrivateKey() CA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")

        return this
    }

    var x509PrivateKey []byte

    switch privateKey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            x509PrivateKey = x509.MarshalPKCS1PrivateKey(privateKey)

        case *ecdsa.PrivateKey:
            var err error
            x509PrivateKey, err = x509.MarshalECPrivateKey(privateKey)
            if err != nil {
                this.Error = err
                return this
            }

        case ed25519.PrivateKey:
            var err error
            x509PrivateKey, err = x509.MarshalPKCS8PrivateKey(privateKey)
            if err != nil {
                this.Error = err
                return this
            }

        case *sm2.PrivateKey:
            this.keyData, this.Error = sm2X509.WritePrivateKeyToPem(privateKey, nil)
            return this

        default:
            this.Error = fmt.Errorf("x509: unsupported private key type: %T", privateKey)
            return this
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}
