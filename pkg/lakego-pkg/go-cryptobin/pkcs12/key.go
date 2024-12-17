package pkcs12

import (
    "errors"
    "crypto"
    "reflect"
)

// 反射获取结构体名称
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

// 从注册的 key 列表解析证书
func ParsePKCS8PrivateKey(pkData []byte) (privateKey crypto.PrivateKey, err error) {
    allkey := AllKey()

    for _, key := range allkey {
        if privateKey, err = key().ParsePKCS8PrivateKey(pkData); err == nil {
            return privateKey, nil
        }
    }

    return nil, errors.New("go-cryptobin/pkcs12: error parsing PKCS#8 private key: " + err.Error())
}

// 从注册的 key 列表编码证书
func MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    keytype := GetStructName(privateKey)

    key, err := GetKey(keytype)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: unsupported key type " + keytype)
    }

    return key().MarshalPKCS8PrivateKey(privateKey)
}

// 从注册的 key 列表编码证书
func MarshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
    keytype := GetStructName(privateKey)

    key, err := GetKey(keytype)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: unsupported key type " + keytype)
    }

    return key().MarshalPrivateKey(privateKey)
}

