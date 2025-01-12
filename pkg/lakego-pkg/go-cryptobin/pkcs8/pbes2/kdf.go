package pbes2

import (
    "encoding/asn1"
)

// KDF options interface
type KDFOpts interface {
    // Salt Size
    GetSaltSize() int

    // oid
    OID() asn1.ObjectIdentifier

    // PBES oid
    PBESOID() asn1.ObjectIdentifier

    // with HasKeyLength option
    WithHasKeyLength(hasKeyLength bool) KDFOpts

    // DeriveKey
    DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error)
}

// KDFParameters
type KDFParameters interface {
    // PBES oid
    PBESOID() asn1.ObjectIdentifier

    // DeriveKey
    DeriveKey(password []byte, size int) (key []byte, err error)
}

var kdfs = make(map[string]func() KDFParameters)

// add kdf type
func AddKDF(oid asn1.ObjectIdentifier, params func() KDFParameters) {
    kdfs[oid.String()] = params
}
