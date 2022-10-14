package jceks

import (
    "crypto"
    "encoding/asn1"
)

// 加密接口
type Cipher interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 值大小
    KeySize() int

    // 加密, 返回: [加密后数据, 参数, error]
    Encrypt(key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, params, ciphertext []byte) ([]byte, error)
}

// Key 接口
type Key interface {
    // 包装 PKCS8 私钥证书
    MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) (pkData []byte, err error)

    // 解析 PKCS8 私钥证书
    ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error)

    // 包装 PKCS8 公钥证书
    MarshalPKCS8PublicKey(publicKey crypto.PublicKey) ([]byte, error)

    // 解析 PKCS8 公钥证书
    ParsePKCS8PublicKey(pkData []byte) (crypto.PublicKey, error)

    // 名称
    Algorithm() string
}

var keys = make(map[string]func() Key)

// 添加Key
func AddKey(name string, key func() Key) {
    keys[name] = key
}

var ciphers = make(map[string]func() Cipher)

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher func() Cipher) {
    ciphers[oid.String()] = cipher
}

// ===============

// 默认配置
var DefaultCipher = CipherMD5And3DES
