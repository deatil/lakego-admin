package sign

import (
    "crypto"
    "encoding/asn1"
)

// hash 接口
type SignHash interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 加密
    Sum(data []byte) []byte
}

// 签名接口
type KeySign interface {
    // oid
    OID() asn1.ObjectIdentifier

    // HashOID
    HashOID() asn1.ObjectIdentifier

    // 签名
    Sign(pkey crypto.PrivateKey, data []byte) (hashData []byte, signData []byte, err error)

    // 解密
    Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error)
}

var signHashs = make(map[string]func() SignHash)

// 添加 hash
func AddSignHash(oid asn1.ObjectIdentifier, signHash func() SignHash) {
    signHashs[oid.String()] = signHash
}

var keySigns = make(map[string]func() KeySign)

// 添加签名
func AddKeySign(oid asn1.ObjectIdentifier, keySign func() KeySign) {
    keySigns[oid.String()] = keySign
}
