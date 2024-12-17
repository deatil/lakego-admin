package pkcs12

import (
    "errors"
    "crypto"

    "github.com/deatil/go-cryptobin/pubkey/gost"
)

// Gost
type KeyGost struct {}

// 包装
func (this KeyGost) MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*gost.PrivateKey)
    if !ok {
        return nil, errors.New("go-cryptobin/pkcs12: private key is err")
    }

    pkData, err := gost.MarshalPrivateKey(priKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 包装
func (this KeyGost) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*gost.PrivateKey)
    if !ok {
        return nil, errors.New("go-cryptobin/pkcs12: private key is err")
    }

    pkData, err := gost.MarshalPrivateKey(priKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyGost) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := gost.ParsePrivateKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
