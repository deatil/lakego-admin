package gost

import (
    "errors"
)

// pkcs1
func ParseGostPrivateKey(der []byte) (*PrivateKey, error) {
    return parseGostPrivateKey(nil, der)
}

// pkcs1
func MarshalGostPrivateKey(key *PrivateKey) ([]byte, error) {
    oid, ok := OidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("x509: unknown elliptic curve")
    }

    return marshalGostPrivateKeyWithOID(key, oid)
}
