package jceks

import (
    "errors"
    "crypto"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// SM2 PublicKey
type PublicKeySM2 struct {}

// algorithm name
func (this PublicKeySM2) Algorithm() string {
    return "SM2"
}

// MarshalPKCS8PrivateKey
func (this PublicKeySM2) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*sm2.PrivateKey)
    if !ok {
        return nil, errors.New("go-cryptobin/jceks: private key is err")
    }

    pkData, err := sm2.MarshalPrivateKey(priKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// ParsePKCS8PrivateKey
func (this PublicKeySM2) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := sm2.ParsePrivateKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}

// MarshalPKCS8PublicKey
func (this PublicKeySM2) MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error) {
    pubKey, ok := publicKey.(*sm2.PublicKey)
    if !ok {
        return nil, errors.New("go-cryptobin/jceks: public key is err")
    }

    pkData, err := sm2.MarshalPublicKey(pubKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error encoding PKCS#8 public key: " + err.Error())
    }

    return pkData, nil
}

// ParsePKCS8PublicKey
func (this PublicKeySM2) ParsePKCS8PublicKey(pkData []byte) (crypto.PublicKey, error) {
    publicKey, err := sm2.ParsePublicKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 public key: " + err.Error())
    }

    return publicKey, nil
}
