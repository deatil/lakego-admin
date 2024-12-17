package bip0340

import (
    "errors"
)

// ParseECPrivateKey parses an EC private key in SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
func ParseECPrivateKey(der []byte) (*PrivateKey, error) {
    return parseECPrivateKey(nil, der)
}

// MarshalECPrivateKey converts an EC private key to SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
// For a more flexible key format which is not EC specific, use
// MarshalPKCS8PrivateKey.
func MarshalECPrivateKey(key *PrivateKey) ([]byte, error) {
    oid, ok := OidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("ecgdsa: unknown elliptic curve")
    }

    return marshalECPrivateKeyWithOID(key, oid)
}
