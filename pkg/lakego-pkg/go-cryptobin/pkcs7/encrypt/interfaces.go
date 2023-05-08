package encrypt

import (
    "crypto"
    "encoding/asn1"
)

// 非对称加密
type KeyEncrypt interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 加密, 返回: [加密后数据, error]
    Encrypt(plaintext []byte, pkey crypto.PublicKey) ([]byte, error)

    // 解密
    Decrypt(ciphertext []byte, pkey crypto.PrivateKey) ([]byte, error)
}

var keyens = make(map[string]func() KeyEncrypt)

// 添加 key 加密方式
func AddkeyEncrypt(oid asn1.ObjectIdentifier, fn func() KeyEncrypt) {
    keyens[oid.String()] = fn
}
