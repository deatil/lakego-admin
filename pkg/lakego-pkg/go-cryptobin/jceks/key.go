package jceks

import (
    "errors"
    "crypto"
    "reflect"
)

// 反射获取结构体名称
func GetStructName(name any) string {
    elem := reflect.TypeOf(name).Elem()

    return elem.PkgPath() + "." + elem.Name()
}

// 从注册的 key 列表解析证书
func ParsePKCS8PrivateKey(pkData []byte) (privateKey crypto.PrivateKey, err error) {
    for _, key := range keys {
        if privateKey, err = key().ParsePKCS8PrivateKey(pkData); err == nil {
            return privateKey, nil
        }
    }

    return nil, errors.New("jceks: error parsing PKCS#8 private key: " + err.Error())
}

// 从注册的 key 列表编码证书
func MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    keytype := GetStructName(privateKey)

    key, ok := keys[keytype]
    if !ok {
        return nil, errors.New("jceks: unsupported private key type " + keytype)
    }

    return key().MarshalPKCS8PrivateKey(privateKey)
}

// 从注册的 key 列表解析公钥证书
func ParsePKCS8PublicKey(pkData []byte) (publicKey crypto.PublicKey, err error) {
    for _, key := range keys {
        if publicKey, err = key().ParsePKCS8PublicKey(pkData); err == nil {
            return publicKey, nil
        }
    }

    return nil, errors.New("jceks: error parsing PKCS#8 public key: " + err.Error())
}

// 从注册的 key 列表编码公钥证书
func MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error) {
    keytype := GetStructName(publicKey)

    key, ok := keys[keytype]
    if !ok {
        return nil, errors.New("jceks: unsupported public key type " + keytype)
    }

    return key().MarshalPKCS8PublicKey(publicKey)
}

// 私钥名称
func GetPKCS8PrivateKeyAlgorithm(privateKey crypto.PrivateKey) (string, error) {
    keytype := GetStructName(privateKey)

    key, ok := keys[keytype]
    if !ok {
        return "", errors.New("jceks: unsupported private key type " + keytype)
    }

    return key().Algorithm(), nil
}

// 公钥名称
func GetPKCS8PublicKeyAlgorithm(publicKey crypto.PublicKey) (string, error) {
    keytype := GetStructName(publicKey)

    key, ok := keys[keytype]
    if !ok {
        return "", errors.New("jceks: unsupported private key type " + keytype)
    }

    return key().Algorithm(), nil
}

