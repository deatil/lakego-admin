package pkcs12

import (
    "errors"
    "crypto"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// SM2
type KeySM2 struct {}

// 包装
func (this KeySM2) MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*sm2.PrivateKey)
    if !ok {
        return nil, errors.New("go-cryptobin/pkcs12: private key is err")
    }

    pkData, err := sm2.MarshalSM2PrivateKey(priKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 包装
func (this KeySM2) MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    priKey, ok := privateKey.(*sm2.PrivateKey)
    if !ok {
        return nil, errors.New("go-cryptobin/pkcs12: private key is err")
    }

    pkData, err := sm2.MarshalPrivateKey(priKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error encoding PKCS#8 private key: " + err.Error())
    }

    return pkData, nil
}

// 解析
func (this KeySM2) ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error) {
    privateKey, err := sm2.ParsePrivateKey(pkData)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: error parsing PKCS#8 private key: " + err.Error())
    }

    return privateKey, nil
}
