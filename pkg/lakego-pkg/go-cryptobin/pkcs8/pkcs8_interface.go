package pkcs8

import (
    "encoding/asn1"
)

// KDF 设置接口
type KDFOpts interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 生成密钥
    DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error)

    // 随机数大小
    GetSaltSize() int
}

// 数据接口
type KDFParameters interface {
    // 生成密钥
    DeriveKey(password []byte, size int) (key []byte, err error)
}

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

var kdfs = make(map[string]func() KDFParameters)

// 添加 kdf 方式
func AddKDF(oid asn1.ObjectIdentifier, params func() KDFParameters) {
    kdfs[oid.String()] = params
}

var ciphers = make(map[string]func() Cipher)

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher func() Cipher) {
    ciphers[oid.String()] = cipher
}
