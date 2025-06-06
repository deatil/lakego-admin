package jceks

import (
    "errors"
    "crypto"
    "crypto/dsa"

    cryptobin_dsa "github.com/deatil/go-cryptobin/pubkey/dsa"
)

// DSA PublicKey
type PublicKeyDSA struct {}

// algorithm name
func (this PublicKeyDSA) Algorithm() string {
    return "DSA"
}

// MarshalPKCS8PrivateKey
func (this PublicKeyDSA) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*dsa.PrivateKey)
    if !ok {
        return nil, errors.New("go-cryptobin/jceks: private key is err")
    }

    pkData, err := cryptobin_dsa.MarshalPKCS8PrivateKey(priKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// ParsePKCS8PrivateKey
func (this PublicKeyDSA) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := cryptobin_dsa.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}

// MarshalPKCS8PublicKey
func (this PublicKeyDSA) MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error) {
    pubKey, ok := publicKey.(*dsa.PublicKey)
    if !ok {
        return nil, errors.New("go-cryptobin/jceks: public key is err")
    }

    pkData, err := cryptobin_dsa.MarshalPKCS8PublicKey(pubKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error encoding PKCS#8 public key: " + err.Error())
    }

    return pkData, nil
}

// ParsePKCS8PublicKey
func (this PublicKeyDSA) ParsePKCS8PublicKey(pkData []byte) (crypto.PublicKey, error) {
    publicKey, err := cryptobin_dsa.ParsePKCS8PublicKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 public key: " + err.Error())
    }

    return publicKey, nil
}
