package key

import (
    "errors"

    "github.com/deatil/go-cryptobin/gost"
)

// pkcs1
func ParseGostPrivateKey(der []byte) (*gost.PrivateKey, error) {
    return parseGostPrivateKey(nil, der)
}

// pkcs1
func MarshalGostPrivateKey(key *gost.PrivateKey) ([]byte, error) {
    oid, ok := OidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("x509: unknown elliptic curve")
    }

    return marshalGostPrivateKeyWithOID(key, oid)
}
