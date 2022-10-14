package ecdh

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
)

var (
    // DH 公钥 oid
    oidPublicKeyDH = asn1.ObjectIdentifier{1, 3, 132, 1, 12}

    oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
    oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
    oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
    oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// 私钥 - 包装
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// 公钥 - 包装
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// 公钥信息 - 解析
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// 包装公钥
func MarshalPublicKey(key *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    oid, ok := oidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("x509: unsupported elliptic curve")
    }

    var paramBytes []byte
    paramBytes, err = asn1.Marshal(oid)
    if err != nil {
        return nil, err
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyDH
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    publicKeyBytes = key.Y

    pkix := pkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    return asn1.Marshal(pkix)
}

// 解析公钥
func ParsePublicKey(derBytes []byte) (pub *PublicKey, err error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
    if err != nil {
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyDH)
    if !algoEq {
        err = errors.New("ecdh: unknown public key algorithm")
        return
    }

    // 解析
    keyData := &pki

    paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        err = errors.New("ecdh: invalid ECDSA parameters")
        return
    }

    namedCurve := namedCurveFromOID(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("ecdh: unsupported elliptic curve")
        return
    }

    y := []byte(keyData.PublicKey.RightAlign())

    pub = &PublicKey{}
    pub.Y = y
    pub.Curve = namedCurve

    return
}

// ====================

// 包装私钥
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    oid, ok := oidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("x509: unsupported elliptic curve")
    }

    // 创建数据
    paramBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("ecdh: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyDH,
        Parameters: asn1.RawValue{
            FullBytes: paramBytes,
        },
    }

    privKey.PrivateKey = key.X

    return asn1.Marshal(privKey)
}

// 解析私钥
func ParsePrivateKey(derBytes []byte) (*PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeyDH):
            x := privKey.PrivateKey

            priv := &PrivateKey{}
            priv.X = x

            paramsDer := cryptobyte.String(privKey.Algo.Parameters.FullBytes)
            namedCurveOID := new(asn1.ObjectIdentifier)
            if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
                err = errors.New("ecdh: invalid ECDSA parameters")
                return nil, err
            }

            namedCurve := namedCurveFromOID(*namedCurveOID)
            if namedCurve == nil {
                err = errors.New("ecdh: unsupported elliptic curve")
                return nil, err
            }

            N := namedCurve.Params().N

            if new(big.Int).SetBytes(x).Cmp(N) >= 0 {
                err = errors.New("ecdh: private key cannot used with given curve")
                return nil, err
            }

            cx, cy := namedCurve.ScalarBaseMult(x)
            priv.PublicKey.Y = elliptic.Marshal(namedCurve, cx, cy)
            priv.PublicKey.Curve = namedCurve

            return priv, nil

        default:
            err = fmt.Errorf("ecdh: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
            return nil, err
    }
}

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
    switch {
        case oid.Equal(oidNamedCurveP224):
            return elliptic.P224()
        case oid.Equal(oidNamedCurveP256):
            return elliptic.P256()
        case oid.Equal(oidNamedCurveP384):
            return elliptic.P384()
        case oid.Equal(oidNamedCurveP521):
            return elliptic.P521()
    }
    return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
    switch curve {
        case elliptic.P224():
            return oidNamedCurveP224, true
        case elliptic.P256():
            return oidNamedCurveP256, true
        case elliptic.P384():
            return oidNamedCurveP384, true
        case elliptic.P521():
            return oidNamedCurveP521, true
    }

    return nil, false
}

