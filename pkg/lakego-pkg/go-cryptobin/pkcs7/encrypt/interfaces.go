package encrypt

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

// 非对称加密
type KeyEncrypt interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 加密, 返回: [加密后数据, error]
    Encrypt(plaintext []byte, pkey crypto.PublicKey) ([]byte, error)

    // 解密
    Decrypt(ciphertext []byte, pkey crypto.PrivateKey) ([]byte, error)
}

var ciphers = make(map[string]func() Cipher)

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher func() Cipher) {
    ciphers[oid.String()] = cipher
}

var keyens = make(map[string]func() KeyEncrypt)

// 添加 key 加密方式
func AddkeyEncrypt(oid asn1.ObjectIdentifier, fn func() KeyEncrypt) {
    keyens[oid.String()] = fn
}
