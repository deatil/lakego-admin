package ecsdsa

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

const ecPrivKeyVersion = 1

// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
    Version       int
    PrivateKey    []byte
    NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
    PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

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
        return nil, errors.New("go-cryptobin/ecsdsa: unknown elliptic curve")
    }

    return marshalECPrivateKeyWithOID(key, oid)
}

// marshalECPrivateKeyWithOID marshals an SM2 private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key *PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
    if !key.Curve.IsOnCurve(key.X, key.Y) {
        return nil, errors.New("go-cryptobin/ecsdsa: invalid elliptic key public key")
    }

    privateKey := make([]byte, bitsToBytes(key.D.BitLen()))

    return asn1.Marshal(ecPrivateKey{
        Version:       1,
        PrivateKey:    key.D.FillBytes(privateKey),
        NamedCurveOID: oid,
        PublicKey:     asn1.BitString{
            Bytes: elliptic.Marshal(key.Curve, key.X, key.Y),
        },
    })
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *PrivateKey, err error) {
    var privKey ecPrivateKey
    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, errors.New("go-cryptobin/ecsdsa: failed to parse EC private key: " + err.Error())
    }

    if privKey.Version != ecPrivKeyVersion {
        return nil, fmt.Errorf("go-cryptobin/ecsdsa: unknown EC private key version %d", privKey.Version)
    }

    var curve elliptic.Curve
    if namedCurveOID != nil {
        curve = NamedCurveFromOid(*namedCurveOID)
    } else {
        curve = NamedCurveFromOid(privKey.NamedCurveOID)
    }

    if curve == nil {
        return nil, errors.New("go-cryptobin/ecsdsa: unknown elliptic curve")
    }

    k := new(big.Int).SetBytes(privKey.PrivateKey)

    curveOrder := curve.Params().N
    if k.Cmp(curveOrder) >= 0 {
        return nil, errors.New("go-cryptobin/ecsdsa: invalid elliptic curve private key value")
    }

    priv := new(PrivateKey)
    priv.Curve = curve
    priv.D = k

    privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

    for len(privKey.PrivateKey) > len(privateKey) {
        if privKey.PrivateKey[0] != 0 {
            return nil, errors.New("go-cryptobin/ecsdsa: invalid private key length")
        }

        privKey.PrivateKey = privKey.PrivateKey[1:]
    }

    copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)

    d := new(big.Int).SetBytes(privateKey)
    priv.X, priv.Y = curve.ScalarBaseMult(d.Bytes())

    return priv, nil
}

func bitsToBytes(bits int) int {
    return (bits + 7) / 8
}
