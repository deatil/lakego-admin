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

    "github.com/tjfoc/gmsm/sm2"
    sm2_x509 "github.com/tjfoc/gmsm/x509"
    sm2_pkcs12 "github.com/tjfoc/gmsm/pkcs12"

    cryptobin_pkcs12 "github.com/deatil/go-cryptobin/pkcs12"
)

// 证书请求
func (this CA) CreateCSR() CA {
    if this.privateKey == nil {
        err := errors.New("CA: [CreateCSR()] privateKey error.")
        return this.AppendError(err)
    }

    var csrBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            certRequest, ok := this.certRequest.(*sm2_x509.CertificateRequest)
            if !ok {
                err := errors.New("CA: [CreateCSR()] sm2 certRequest error.")
                return this.AppendError(err)
            }

            csrBytes, err = sm2_x509.CreateCertificateRequest(rand.Reader, certRequest, privateKey)

        default:
            certRequest, ok := this.certRequest.(*x509.CertificateRequest)
            if !ok {
                err := errors.New("CA: [CreateCSR()] certRequest error.")
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
        err := errors.New("CA: [CreateCA()] publicKey or privateKey error.")
        return this.AppendError(err)
    }

    var caBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            cert, ok := this.cert.(*sm2_x509.Certificate)
            if !ok {
                err := errors.New("CA: [CreateCA()] sm2 cert error.")
                return this.AppendError(err)
            }

            publicKey := &privateKey.PublicKey

            caBytes, err = sm2_x509.CreateCertificate(cert, cert, publicKey, privateKey)

        default:
            cert, ok := this.cert.(*x509.Certificate)
            if !ok {
                err := errors.New("CA: [CreateCA()] cert error.")
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
        err := errors.New("CA: [CreateCert()] publicKey or privateKey error.")
        return this.AppendError(err)
    }

    var certBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *sm2.PrivateKey:
            newCert, certOk := this.cert.(*sm2_x509.Certificate)
            if !certOk {
                err := errors.New("CA: [CreateCert()] sm2 cert error.")
                return this.AppendError(err)
            }

            newCa, caOk := ca.(*sm2_x509.Certificate)
            if !caOk {
                err := errors.New("CA: [CreateCert()] sm2 ca error.")
                return this.AppendError(err)
            }

            publicKey := &privateKey.PublicKey

            certBytes, err = sm2_x509.CreateCertificate(newCert, newCa, publicKey, privateKey)

        default:
            newCert, certOk := this.cert.(*x509.Certificate)
            if !certOk {
                err := errors.New("CA: [CreateCert()] cert error.")
                return this.AppendError(err)
            }

            newCa, caOk := ca.(*x509.Certificate)
            if !caOk {
                err := errors.New("CA: [CreateCert()] ca error.")
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
        err := errors.New("CA: [CreatePrivateKey()] privateKey error.")
        return this.AppendError(err)
    }

    var privateBlock *pem.Block

    switch privateKey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

            privateBlock = &pem.Block{
                Type: "RSA PRIVATE KEY",
                Bytes: x509PrivateKey,
            }

        case *ecdsa.PrivateKey:
            x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)
            if err != nil {
                return this.AppendError(err)
            }

            privateBlock = &pem.Block{
                Type: "EC PRIVATE KEY",
                Bytes: x509PrivateKey,
            }

        case ed25519.PrivateKey:
            x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
            if err != nil {
                return this.AppendError(err)
            }

            privateBlock = &pem.Block{
                Type: "ED PRIVATE KEY",
                Bytes: x509PrivateKey,
            }

        case *sm2.PrivateKey:
            keyData, err := sm2_x509.WritePrivateKeyToPem(privateKey, nil)
            if err != nil {
                return this.AppendError(err)
            }

            this.keyData = keyData

            return this

        default:
            err := fmt.Errorf("CA: [CreatePrivateKey()] unsupported private key type: %T", privateKey)
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
            cert, ok := this.cert.(*sm2_x509.Certificate)
            if !ok {
                err := errors.New("sm2 cert error.")
                return this.AppendError(err)
            }

            pfxData, err = sm2_pkcs12.Encode(privateKey, cert, caCerts, pwd)

        default:
            cert, ok := this.cert.(*x509.Certificate)
            if !ok {
                err := errors.New("cert error.")
                return this.AppendError(err)
            }

            pfxData, err = cryptobin_pkcs12.EncodeChain(rand.Reader, privateKey, cert, caCerts, pwd)
    }

    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pfxData

    return this
}

// pkcs12 密钥
func (this CA) CreatePKCS12CertTrustStore(certs []*x509.Certificate, password string) CA {
    pfxData, err := cryptobin_pkcs12.EncodeTrustStore(rand.Reader, certs, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pfxData

    return this
}
