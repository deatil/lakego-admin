package jceks

import (
    "errors"
    "crypto"
    "crypto/x509"
)

// rsa
type KeyRsa struct {}

// 包装
func (this KeyRsa) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    pkData, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, errors.New("jceks: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeyRsa) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := x509.ParsePKCS8PrivateKey(pkData)
    if err != nil {
        return nil, errors.New("jceks: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}

// ============

// 包装公钥
func (this KeyRsa) MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error) {
    pkData, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return nil, errors.New("jceks: error encoding PKCS#8 public key: " + err.Error())
    }

    return pkData, nil
}

// 解析公钥
func (this KeyRsa) ParsePKCS8PublicKey(pkData []byte) (crypto.PublicKey, error) {
    publicKey, err := x509.ParsePKIXPublicKey(pkData)
    if err != nil {
        return nil, errors.New("jceks: error parsing PKCS#8 public key: " + err.Error())
    }

    return publicKey, nil
}

// 名称
func (this KeyRsa) Algorithm() string {
    return "RSA"
}
