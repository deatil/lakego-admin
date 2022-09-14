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
        return nil, errors.New("jceks: unsupported key type " + keytype)
    }

    return key().MarshalPKCS8PrivateKey(privateKey)
}

