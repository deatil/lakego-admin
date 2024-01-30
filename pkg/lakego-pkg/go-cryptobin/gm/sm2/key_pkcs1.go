package sm2

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/sm2curve"
)

const sm2PrivKeyVersion = 1

// sm2PrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//
//  RFC 5915
//  SEC1 - http://www.secg.org/sec1-v2.pdf
//
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type sm2PrivateKey struct {
    Version       int
    PrivateKey    []byte
    NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
    PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParseSM2PrivateKey parses an SM2 private key in SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "SM2 PRIVATE KEY".
func ParseSM2PrivateKey(der []byte) (*PrivateKey, error) {
    return parseSM2PrivateKey(nil, der)
}

// MarshalSM2PrivateKey converts an SM2 private key to SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "SM2 PRIVATE KEY".
// For a more flexible key format which is not SM2 specific, use
// MarshalPKCS8PrivateKey.
func MarshalSM2PrivateKey(key *PrivateKey) ([]byte, error) {
    oid, ok := oidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("sm2: unknown curve")
    }

    return marshalSM2PrivateKeyWithOID(key, oid)
}

// marshalSM2PrivateKeyWithOID marshals an SM2 private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalSM2PrivateKeyWithOID(key *PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
    if !key.Curve.IsOnCurve(key.X, key.Y) {
        return nil, errors.New("sm2: invalid key public key")
    }

    privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)

    return asn1.Marshal(sm2PrivateKey{
        Version:       sm2PrivKeyVersion,
        PrivateKey:    key.D.FillBytes(privateKey),
        NamedCurveOID: oid,
        PublicKey:     asn1.BitString{
            Bytes: sm2curve.Marshal(key.Curve, key.X, key.Y),
        },
    })
}

// parseSM2PrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the SM2 private key structure.
func parseSM2PrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *PrivateKey, err error) {
    var privKey sm2PrivateKey
    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, errors.New("sm2: failed to parse SM2 private key: " + err.Error())
    }

    if privKey.Version != sm2PrivKeyVersion {
        return nil, fmt.Errorf("sm2: unknown SM2 private key version %d", privKey.Version)
    }

    var curve elliptic.Curve
    if namedCurveOID != nil {
        curve = namedCurveFromOID(*namedCurveOID)
    } else {
        curve = namedCurveFromOID(privKey.NamedCurveOID)
    }

    if curve == nil {
        return nil, errors.New("sm2: unknown curve")
    }

    k := new(big.Int).SetBytes(privKey.PrivateKey)
    curveOrder := curve.Params().N
    if k.Cmp(curveOrder) >= 0 {
        return nil, errors.New("sm2: invalid curve private key value")
    }

    priv := new(PrivateKey)
    priv.Curve = curve
    priv.D = k

    privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

    // Some private keys have leading zero padding. This is invalid
    // according to [SEC1], but this code will ignore it.
    for len(privKey.PrivateKey) > len(privateKey) {
        if privKey.PrivateKey[0] != 0 {
            return nil, errors.New("sm2: invalid private key length")
        }
        privKey.PrivateKey = privKey.PrivateKey[1:]
    }

    // Some private keys remove all leading zeros, this is also invalid
    // according to [SEC1] but since OpenSSL used to do this, we ignore
    // this too.
    copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
    priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

    return priv, nil
}

var (
    oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
    switch {
        case oid.Equal(oidNamedCurveP256SM2):
            return P256()
    }

    return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
    switch curve {
        case P256():
            return oidNamedCurveP256SM2, true
    }

    return nil, false
}
