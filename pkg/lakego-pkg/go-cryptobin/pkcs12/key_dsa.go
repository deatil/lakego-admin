package pkcs12

import (
    "errors"
    "crypto"
    "crypto/dsa"

    cryptobin_dsa "github.com/deatil/go-cryptobin/dsa"
)

// DSA
type KeyDSA struct {}

// 包装
func (this KeyDSA) MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*dsa.PrivateKey)
    if !ok {
        return nil, errors.New("pkcs12: private key is err")
    }

    pkData, err := cryptobin_dsa.MarshalPrivateKey(priKey)
    if err != nil {
        return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 包装
func (this KeyDSA) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*dsa.PrivateKey)
    if !ok {
        return nil, errors.New("pkcs12: private key is err")
    }

    pkData, err := cryptobin_dsa.MarshalPKCS8PrivateKey(priKey)
    if err != nil {
        return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyDSA) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := cryptobin_dsa.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
