package pkcs12

import (
    "errors"
    "crypto"
    "crypto/x509"
    "crypto/ecdsa"
)

// Ecdsa
type KeyEcdsa struct {}

// 包装
func (this KeyEcdsa) MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*ecdsa.PrivateKey)
    if !ok {
        return nil, errors.New("pkcs12: private key is err")
    }

    pkData, err := x509.MarshalECPrivateKey(priKey)
    if err != nil {
        return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 包装
func (this KeyEcdsa) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    pkData, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyEcdsa) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
