package pkcs8pbe

import (
    "encoding/asn1"
)

// 加密接口
type PEMCipher interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 值大小
    KeySize() int

    // 加密, 返回: [加密后数据, 参数, error]
    Encrypt(key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, params, ciphertext []byte) ([]byte, error)
}

var ciphers = make(map[string]func() PEMCipher)

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher func() PEMCipher) {
    ciphers[oid.String()] = cipher
}
