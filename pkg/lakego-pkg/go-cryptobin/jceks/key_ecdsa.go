package jceks

import (
    "errors"
    "crypto"
    "crypto/x509"
)

// Ecdsa
type KeyEcdsa struct {}

// 包装
func (this KeyEcdsa) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    pkData, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, errors.New("jceks: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyEcdsa) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("jceks: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
