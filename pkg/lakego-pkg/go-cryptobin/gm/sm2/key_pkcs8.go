package sm2

import (
    "errors"
    "encoding/asn1"
    "crypto/elliptic"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/gm/sm2/sm2curve"
)

var (
    oidSM2          = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
    oidPublicKeySM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// pkcs8 info
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

// pkcs8 attribute info
type pkcs8Attribute struct {
    Id     asn1.ObjectIdentifier
    Values []asn1.RawValue `asn1:"set"`
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

func ParsePrivateKey(der []byte) (*PrivateKey, error) {
    var privKey pkcs8
    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, err
    }

    // check PrivateKey OID
    if !privKey.Algo.Algorithm.Equal(oidSM2) &&
        !privKey.Algo.Algorithm.Equal(oidPublicKeySM2) {
        return nil, errors.New("sm2: unknown private key algorithm")
    }

    bytes := privKey.Algo.Parameters.FullBytes

    namedCurveOID := new(asn1.ObjectIdentifier)
    if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
        namedCurveOID = nil
    }

    return parseSM2PrivateKey(namedCurveOID, privKey.PrivateKey)
}

func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var r pkcs8
    var algo pkix.AlgorithmIdentifier

    oid, ok := oidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("sm2: unsupported SM2 curve")
    }

    oidBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("sm2: failed to marshal algo param")
    }

    algo.Algorithm = oidSM2
    algo.Parameters.Class = 0
    algo.Parameters.Tag = 6
    algo.Parameters.IsCompound = false
    algo.Parameters.FullBytes = oidBytes

    r.Version = 0
    r.Algo = algo
    r.PrivateKey, err = marshalSM2PrivateKeyWithOID(key, nil)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(r)
}

func ParsePublicKey(der []byte) (*PublicKey, error) {
    var pubkey pkixPublicKey

    if _, err := asn1.Unmarshal(der, &pubkey); err != nil {
        return nil, err
    }

    // check PublicKey OID
    if !pubkey.Algo.Algorithm.Equal(oidSM2) &&
        !pubkey.Algo.Algorithm.Equal(oidPublicKeySM2) {
        return nil, errors.New("sm2: unknown publicKey key algorithm")
    }

    bytes := pubkey.Algo.Parameters.FullBytes

    namedCurveOID := new(asn1.ObjectIdentifier)
    if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
        namedCurveOID = nil
    }

    // get curve from oid
    c := namedCurveFromOID(*namedCurveOID)
    if c == nil {
        return nil, errors.New("sm2: unknown curve")
    }

    x, y := sm2curve.Unmarshal(c, pubkey.BitString.Bytes)

    pub := PublicKey{
        Curve: c,
        X:     x,
        Y:     y,
    }

    return &pub, nil
}

func MarshalPublicKey(key *PublicKey) ([]byte, error) {
    var r pkixPublicKey
    var algo pkix.AlgorithmIdentifier

    oid, ok := oidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("sm2: unsupported SM2 curve")
    }

    oidBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("sm2: failed to marshal algo param")
    }

    algo.Algorithm = oidSM2
    algo.Parameters.Class = 0
    algo.Parameters.Tag = 6
    algo.Parameters.IsCompound = false
    algo.Parameters.FullBytes = oidBytes

    r.Algo = algo
    r.BitString = asn1.BitString{
        Bytes: sm2curve.Marshal(key.Curve, key.X, key.Y),
    }

    return asn1.Marshal(r)
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
