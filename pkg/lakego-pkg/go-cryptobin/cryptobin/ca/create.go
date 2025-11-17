package ca

import (
    "fmt"
    "errors"
    "crypto"
    "crypto/dsa"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pkcs12"
    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/pubkey/gost"
    "github.com/deatil/go-cryptobin/pubkey/elgamal"
    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
    pubkey_dsa "github.com/deatil/go-cryptobin/pubkey/dsa"
)

type (
    // options
    Opts       = pkcs8.Opts
    // PBKDF2 options
    PBKDF2Opts = pkcs8.PBKDF2Opts
    // Scrypt options
    ScryptOpts = pkcs8.ScryptOpts
)

var (
    // get Cipher type
    GetCipherFromName = pkcs8.GetCipherFromName
    // get hash type
    GetHashFromName   = pkcs8.GetHashFromName
)

// Create CA PEM
func (this CA) CreateCA() CA {
    return this.CreateCAWithIssuer(nil, nil)
}

// Create CA PEM With Issuer
func (this CA) CreateCAWithIssuer(issuer *cryptobin_x509.Certificate, issuerKey crypto.PrivateKey) CA {
    if this.publicKey == nil || this.privateKey == nil {
        err := errors.New("go-cryptobin/ca: publicKey or privateKey error.")
        return this.AppendError(err)
    }

    if issuer == nil {
        issuer = this.cert
        issuerKey = this.privateKey
    }

    caBytes, err := cryptobin_x509.CreateCertificate(rand.Reader, this.cert, issuer, this.publicKey, issuerKey)

    if err != nil {
        return this.AppendError(err)
    }

    caBlock := &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: caBytes,
    }

    this.keyData = pem.EncodeToMemory(caBlock)

    return this
}

// Create Cert PEM
func (this CA) CreateCert(issuer *cryptobin_x509.Certificate, issuerKey crypto.PrivateKey) CA {
    if this.publicKey == nil || this.privateKey == nil {
        err := errors.New("go-cryptobin/ca: publicKey or privateKey error.")
        return this.AppendError(err)
    }

    certBytes, err := cryptobin_x509.CreateCertificate(rand.Reader, this.cert, issuer, this.publicKey, issuerKey)
    if err != nil {
        return this.AppendError(err)
    }

    certBlock := &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certBytes,
    }

    this.keyData = pem.EncodeToMemory(certBlock)

    return this
}

// Create CSR PEM
func (this CA) CreateCSR() CA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ca: privateKey error.")
        return this.AppendError(err)
    }

    csrBytes, err := cryptobin_x509.CreateCertificateRequest(rand.Reader, this.certRequest, this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    csrBlock := &pem.Block{
        Type:  "CERTIFICATE REQUEST",
        Bytes: csrBytes,
    }

    this.keyData = pem.EncodeToMemory(csrBlock)

    return this
}

// Create PrivateKey PEM
func (this CA) CreatePrivateKey() CA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ca: privateKey empty.")
        return this.AppendError(err)
    }

    var privateKeyBytes []byte
    var err error

    switch privateKey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
        case *dsa.PrivateKey:
            privateKeyBytes, err = pubkey_dsa.MarshalPKCS8PrivateKey(privateKey)
        case *ecdsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
        case ed25519.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
        case *sm2.PrivateKey:
            privateKeyBytes, err = sm2.MarshalPrivateKey(privateKey)
        case *gost.PrivateKey:
            privateKeyBytes, err = gost.MarshalPrivateKey(privateKey)
        case *elgamal.PrivateKey:
            privateKeyBytes, err = elgamal.MarshalPKCS8PrivateKey(privateKey)
        default:
            err = fmt.Errorf("unsupported private key type: %T", privateKey)
    }

    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PrivateKey PEM With Password
func (this CA) CreatePrivateKeyWithPassword(password []byte, opts ...any) CA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ca: privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    var privateKeyBytes []byte

    // 生成私钥
    switch prikey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case *dsa.PrivateKey:
            privateKeyBytes, err = pubkey_dsa.MarshalPKCS8PrivateKey(prikey)
        case *ecdsa.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case ed25519.PrivateKey:
            privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(prikey)
        case *sm2.PrivateKey:
            privateKeyBytes, err = sm2.MarshalPrivateKey(prikey)
        case *gost.PrivateKey:
            privateKeyBytes, err = gost.MarshalPrivateKey(prikey)
        case *elgamal.PrivateKey:
            privateKeyBytes, err = elgamal.MarshalPKCS8PrivateKey(prikey)
        default:
            err = errors.New("go-cryptobin/ca: privateKey error.")
    }

    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs8.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKeyBytes,
        []byte(password),
        opt,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PublicKey PEM
func (this CA) CreatePublicKey() CA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ca: publicKey empty.")
        return this.AppendError(err)
    }

    var publicKeyBytes []byte
    var err error

    switch pubkey := this.publicKey.(type) {
        case *rsa.PublicKey:
            publicKeyBytes, err = x509.MarshalPKIXPublicKey(pubkey)
        case *dsa.PublicKey:
            publicKeyBytes, err = pubkey_dsa.MarshalPKCS8PublicKey(pubkey)
        case *ecdsa.PublicKey:
            publicKeyBytes, err = x509.MarshalPKIXPublicKey(pubkey)
        case ed25519.PublicKey:
            publicKeyBytes, err = x509.MarshalPKIXPublicKey(pubkey)
        case *sm2.PublicKey:
            publicKeyBytes, err = sm2.MarshalPublicKey(pubkey)
        case *gost.PublicKey:
            publicKeyBytes, err = gost.MarshalPublicKey(pubkey)
        case *elgamal.PublicKey:
            publicKeyBytes, err = elgamal.MarshalPKCS8PublicKey(pubkey)
        default:
            err = errors.New("go-cryptobin/ca: privateKey error.")
    }

    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// Create PKCS12 Cert PEM
// caCerts 通常保留为空
func (this CA) CreatePKCS12Cert(caCerts []*x509.Certificate, password string) CA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ca: privateKey error.")
        return this.AppendError(err)
    }

    pfxData, err := pkcs12.EncodeChain(rand.Reader, this.privateKey, this.cert.ToX509Certificate(), caCerts, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pfxData

    return this
}
