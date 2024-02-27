package ca

import (
    "fmt"
    "errors"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs12"
    "github.com/deatil/go-cryptobin/gm/sm2"
    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
)

// 证书请求
func (this CA) CreateCSR() CA {
    if this.privateKey == nil {
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    var csrBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            certRequest, ok := this.certRequest.(*cryptobin_x509.CertificateRequest)
            if !ok {
                err := errors.New("sm2 certRequest error.")
                return this.AppendError(err)
            }

            csrBytes, err = cryptobin_x509.CreateCertificateRequest(rand.Reader, certRequest, privateKey)

        default:
            certRequest, ok := this.certRequest.(*x509.CertificateRequest)
            if !ok {
                err := errors.New("certRequest error.")
                return this.AppendError(err)
            }

            csrBytes, err = x509.CreateCertificateRequest(rand.Reader, certRequest, this.privateKey)
    }

    if err != nil {
        return this.AppendError(err)
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
        err := errors.New("publicKey or privateKey error.")
        return this.AppendError(err)
    }

    var caBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            cert, ok := this.cert.(*cryptobin_x509.Certificate)
            if !ok {
                err := errors.New("sm2 cert error.")
                return this.AppendError(err)
            }

            publicKey := &privateKey.PublicKey

            caBytes, err = cryptobin_x509.CreateCertificate(cert, cert, publicKey, privateKey)

        default:
            cert, ok := this.cert.(*x509.Certificate)
            if !ok {
                err := errors.New("cert error.")
                return this.AppendError(err)
            }

            caBytes, err = x509.CreateCertificate(rand.Reader, cert, cert, this.publicKey, this.privateKey)
    }

    if err != nil {
        return this.AppendError(err)
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
        err := errors.New("publicKey or privateKey error.")
        return this.AppendError(err)
    }

    var certBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            newCert, certOk := this.cert.(*cryptobin_x509.Certificate)
            if !certOk {
                err := errors.New("sm2 cert error.")
                return this.AppendError(err)
            }

            newCa, caOk := ca.(*cryptobin_x509.Certificate)
            if !caOk {
                err := errors.New("sm2 ca error.")
                return this.AppendError(err)
            }

            publicKey := &privateKey.PublicKey

            certBytes, err = cryptobin_x509.CreateCertificate(newCert, newCa, publicKey, privateKey)

        default:
            newCert, certOk := this.cert.(*x509.Certificate)
            if !certOk {
                err := errors.New("cert error.")
                return this.AppendError(err)
            }

            newCa, caOk := ca.(*x509.Certificate)
            if !caOk {
                err := errors.New("ca error.")
                return this.AppendError(err)
            }

            certBytes, err = x509.CreateCertificate(rand.Reader, newCert, newCa, this.publicKey, this.privateKey)
    }

    if err != nil {
        return this.AppendError(err)
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
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    var privateBlock *pem.Block

    switch privateKey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

            privateBlock = &pem.Block{
                Type: "RSA PRIVATE KEY",
                Bytes: privateKeyBytes,
            }

        case *ecdsa.PrivateKey:
            privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
            if err != nil {
                return this.AppendError(err)
            }

            privateBlock = &pem.Block{
                Type: "EC PRIVATE KEY",
                Bytes: privateKeyBytes,
            }

        case ed25519.PrivateKey:
            privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
            if err != nil {
                return this.AppendError(err)
            }

            privateBlock = &pem.Block{
                Type: "PRIVATE KEY",
                Bytes: privateKeyBytes,
            }

        case *sm2.PrivateKey:
            privateKeyBytes, err := sm2.MarshalPrivateKey(privateKey)
            if err != nil {
                return this.AppendError(err)
            }

            privateBlock = &pem.Block{
                Type: "PRIVATE KEY",
                Bytes: privateKeyBytes,
            }

        default:
            err := fmt.Errorf("unsupported private key type: %T", privateKey)
            return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// =======================

// pkcs12 密钥
// caCerts 通常保留为空
// 支持 [rsa | ecdsa | sm2]
func (this CA) CreatePKCS12Cert(caCerts []*x509.Certificate, pwd string) CA {
    if this.privateKey == nil {
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    var pfxData []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            cert, ok := this.cert.(*cryptobin_x509.Certificate)
            if !ok {
                err := errors.New("sm2 cert error.")
                return this.AppendError(err)
            }

            pfxData, err = pkcs12.EncodeChain(rand.Reader, privateKey, cert.ToX509Certificate(), caCerts, pwd)

        default:
            cert, ok := this.cert.(*x509.Certificate)
            if !ok {
                err := errors.New("cert error.")
                return this.AppendError(err)
            }

            pfxData, err = pkcs12.EncodeChain(rand.Reader, privateKey, cert, caCerts, pwd)
    }

    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pfxData

    return this
}

// pkcs12 密钥
func (this CA) CreatePKCS12CertTrustStore(certs []*x509.Certificate, password string) CA {
    pfxData, err := pkcs12.EncodeTrustStore(rand.Reader, certs, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pfxData

    return this
}

