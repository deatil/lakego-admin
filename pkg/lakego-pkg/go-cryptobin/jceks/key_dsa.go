package jceks

import (
    "errors"
    "crypto"
    "crypto/dsa"

    cryptobin_dsa "github.com/deatil/go-cryptobin/dsa"
)

// DSA
type KeyDSA struct {}

// 包装
func (this KeyDSA) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*dsa.PrivateKey)
    if !ok {
        return nil, errors.New("jceks: private key is err")
    }

    pkData, err := cryptobin_dsa.MarshalPKCS8PrivateKey(priKey)
    if err != nil {
        return nil, errors.New("jceks: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyDSA) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := cryptobin_dsa.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("jceks: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}

// ============

// 包装公钥
func (this KeyDSA) MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error) {
    pubKey, ok := publicKey.(*dsa.PublicKey)
    if !ok {
        return nil, errors.New("jceks: public key is err")
    }

    pkData, err := cryptobin_dsa.MarshalPKCS8PublicKey(pubKey)
    if err != nil {
        return nil, errors.New("jceks: error encoding PKCS#8 public key: " + err.Error())
    }

    return pkData, nil
}

// 解析公钥
func (this KeyDSA) ParsePKCS8PublicKey(pkData []byte) (crypto.PublicKey, error) {
    publicKey, err := cryptobin_dsa.ParsePKCS8PublicKey(pkData)
    if err != nil {
        return nil, errors.New("jceks: error parsing PKCS#8 public key: " + err.Error())
    }

    return publicKey, nil
}

// 名称
func (this KeyDSA) Algorithm() string {
    return "DSA"
}
