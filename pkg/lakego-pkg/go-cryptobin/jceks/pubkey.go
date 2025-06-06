package jceks

import (
    "errors"
    "crypto"
    "reflect"
)

// 反射获取结构体名称
// get struct name
func GetStructName(s any) (name string) {
    p := reflect.TypeOf(s)

    if p.Kind() == reflect.Pointer {
        p = p.Elem()
        name = "*"
    }

    pkgPath := p.PkgPath()

    if pkgPath != "" {
        name += pkgPath + "."
    }

    return name + p.Name()
}

// 从注册的证书列表解析证书
// Parse PKCS8 PrivateKey from keys
func ParsePKCS8PrivateKey(pkData []byte) (privateKey crypto.PrivateKey, err error) {
    for _, key := range keys {
        if privateKey, err = key().ParsePKCS8PrivateKey(pkData); err == nil {
            return privateKey, nil
        }
    }

    return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 private key: " + err.Error())
}

// 根据证书名称编码证书
// Marshal PKCS8 PrivateKey
func MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    keytype := GetStructName(privateKey)

    key, ok := keys[keytype]
    if !ok {
        return nil, errors.New("go-cryptobin/jceks: unsupported private key type " + keytype)
    }

    return key().MarshalPKCS8PrivateKey(privateKey)
}

// 从注册的证书列表解析公钥证书
// ParsePKCS8PublicKey
func ParsePKCS8PublicKey(pkData []byte) (publicKey crypto.PublicKey, err error) {
    for _, key := range keys {
        if publicKey, err = key().ParsePKCS8PublicKey(pkData); err == nil {
            return publicKey, nil
        }
    }

    return nil, errors.New("go-cryptobin/jceks: error parsing PKCS#8 public key: " + err.Error())
}

// 从注册的证书列表编码公钥证书
// MarshalPKCS8PublicKey
func MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error) {
    keytype := GetStructName(publicKey)

    key, ok := keys[keytype]
    if !ok {
        return nil, errors.New("go-cryptobin/jceks: unsupported public key type " + keytype)
    }

    return key().MarshalPKCS8PublicKey(publicKey)
}

// 私钥名称
// GetPKCS8PrivateKeyAlgorithm
func GetPKCS8PrivateKeyAlgorithm(privateKey crypto.PrivateKey) (string, error) {
    keytype := GetStructName(privateKey)

    key, ok := keys[keytype]
    if !ok {
        return "", errors.New("go-cryptobin/jceks: unsupported private key type " + keytype)
    }

    return key().Algorithm(), nil
}

// 公钥名称
// GetPKCS8PublicKeyAlgorithm
func GetPKCS8PublicKeyAlgorithm(publicKey crypto.PublicKey) (string, error) {
    keytype := GetStructName(publicKey)

    key, ok := keys[keytype]
    if !ok {
        return "", errors.New("go-cryptobin/jceks: unsupported private key type " + keytype)
    }

    return key().Algorithm(), nil
}

