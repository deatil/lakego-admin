package sm2

import (
    "errors"
    "encoding/asn1"
    "crypto/elliptic"
    "crypto/x509/pkix"
)

var (
    oidSM2          = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
    oidPublicKeySM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// pkcs8
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
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

    if !privKey.Algo.Algorithm.Equal(oidSM2) &&
        !privKey.Algo.Algorithm.Equal(oidPublicKeySM2) {
        err := errors.New("sm2: unknown private key algorithm")
        return nil, err
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

    if key.Curve != P256() {
        return nil, errors.New("sm2: unsupported SM2 curve")
    }

    oidBytes, err := asn1.Marshal(oidPublicKeySM2)
    if err != nil {
        return nil, errors.New("sm2: failed to marshal algo param: " + err.Error())
    }

    algo.Algorithm = oidSM2
    algo.Parameters.Class = 0
    algo.Parameters.Tag = 6
    algo.Parameters.IsCompound = false
    algo.Parameters.FullBytes = oidBytes

    oid, ok := oidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("sm2: unknown elliptic curve")
    }

    r.Version = 0
    r.Algo = algo
    r.PrivateKey, err = marshalSM2PrivateKeyWithOID(key, oid)
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

    if !pubkey.Algo.Algorithm.Equal(oidSM2) &&
        !pubkey.Algo.Algorithm.Equal(oidPublicKeySM2) {
        return nil, errors.New("sm2: not sm2 elliptic curve")
    }

    curve := P256()

    x, y := elliptic.Unmarshal(curve, pubkey.BitString.Bytes)

    pub := PublicKey{
        Curve: curve,
        X:     x,
        Y:     y,
    }

    return &pub, nil
}

func MarshalPublicKey(key *PublicKey) ([]byte, error) {
    var r pkixPublicKey
    var algo pkix.AlgorithmIdentifier

    if key.Curve != P256() {
        return nil, errors.New("sm2: unsupported SM2 curve")
    }

    oidBytes, err := asn1.Marshal(oidPublicKeySM2)
    if err != nil {
        return nil, errors.New("sm2: failed to marshal algo param: " + err.Error())
    }

    algo.Algorithm = oidSM2
    algo.Parameters.Class = 0
    algo.Parameters.Tag = 6
    algo.Parameters.IsCompound = false
    algo.Parameters.FullBytes = oidBytes

    r.Algo = algo
    r.BitString = asn1.BitString{
        Bytes: elliptic.Marshal(key.Curve, key.X, key.Y),
    }

    return asn1.Marshal(r)
}
