package jceks

import (
    "errors"
    "crypto"
    "crypto/x509"
)

// ECDSA PublicKey
type PublicKeyECDSA struct {}

// algorithm name
func (this PublicKeyECDSA) Algorithm() string {
    return "ECDSA"
}

// MarshalPKCS8PrivateKey
func (this PublicKeyECDSA) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    pkData, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// ParsePKCS8PrivateKey
func (this PublicKeyECDSA) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}

// MarshalPKCS8PublicKey
func (this PublicKeyECDSA) MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error) {
    pkData, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error encoding PKCS#8 public key: " + err.Error())
    }

    return pkData, nil
}

// ParsePKCS8PublicKey
func (this PublicKeyECDSA) ParsePKCS8PublicKey(pkData []byte) (crypto.PublicKey, error) {
    publicKey, err := x509.ParsePKIXPublicKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 public key: " + err.Error())
    }

    return publicKey, nil
}
