package jceks

import (
    "errors"
    "crypto"

    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"
)

// SM2
type KeySM2 struct {}

// 包装
func (this KeySM2) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*sm2.PrivateKey)
    if !ok {
        return nil, errors.New("jceks: private key is err")
    }

    pkData, err := x509.MarshalSm2UnecryptedPrivateKey(priKey)
    if err != nil {
        return nil, errors.New("jceks: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeySM2) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := x509.ParsePKCS8UnecryptedPrivateKey(pkData)
    if err != nil {
        return nil, errors.New("jceks: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
