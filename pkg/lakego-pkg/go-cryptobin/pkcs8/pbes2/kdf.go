package pbes2

import (
    "encoding/asn1"
)

// KDF 设置接口
type KDFOpts interface {
    // 随机数大小
    GetSaltSize() int

    // oid
    OID() asn1.ObjectIdentifier

    // PBES oid
    PBESOID() asn1.ObjectIdentifier

    // 设置是否有 KeyLength
    WithHasKeyLength(hasKeyLength bool) KDFOpts

    // 生成密钥
    DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error)
}

// 数据接口
type KDFParameters interface {
    // PBES oid
    PBESOID() asn1.ObjectIdentifier

    // 生成密钥
    DeriveKey(password []byte, size int) (key []byte, err error)
}

var kdfs = make(map[string]func() KDFParameters)

// 添加 kdf 方式
// add kdf type
func AddKDF(oid asn1.ObjectIdentifier, params func() KDFParameters) {
    kdfs[oid.String()] = params
}
