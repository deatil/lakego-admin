package pkcs12

import (
    "errors"
    "crypto"
    "crypto/x509"
)

// EdDSA
type KeyEdDSA struct {}

// 包装
func (this KeyEdDSA) MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    pkData, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 包装
func (this KeyEdDSA) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    pkData, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyEdDSA) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
