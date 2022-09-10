package pkcs12

import (
    "errors"
    "crypto"
    "crypto/rsa"
    "crypto/x509"
)

// rsa
type KeyRsa struct {}

// 包装
func (this KeyRsa) MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*rsa.PrivateKey)
    if !ok {
        return nil, errors.New("pkcs12: private key is err")
    }

    pkData := x509.MarshalPKCS1PrivateKey(priKey)

    return pkData, nil
}

// 包装
func (this KeyRsa) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    pkData, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyRsa) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
