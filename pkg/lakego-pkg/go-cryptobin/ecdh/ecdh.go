package ecdh

import (
    "errors"
    "crypto/ecdh"
    "crypto/x509/pkix"
    "encoding/asn1"

    "golang.org/x/crypto/cryptobyte"
)

var (
    // ECDH
    oidPublicKeyECDH  = asn1.ObjectIdentifier{1, 3, 132, 1, 12}

    // ECMQV
    oidPublicKeyECMQV = asn1.ObjectIdentifier{1, 3, 132, 1, 13}

    oidNamedCurveP256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
    oidNamedCurveP384   = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
    oidNamedCurveP521   = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
    oidNamedCurveX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
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
func MarshalPublicKey(key *ecdh.PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    oid, ok := oidFromNamedCurve(key.Curve())
    if !ok {
        return nil, errors.New("x509: unsupported ecdh curve")
    }

    var paramBytes []byte
    paramBytes, err = asn1.Marshal(oid)
    if err != nil {
        return nil, err
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyECDH
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    publicKeyBytes = key.Bytes()

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
func ParsePublicKey(derBytes []byte) (pub *ecdh.PublicKey, err error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
    if err != nil {
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyECDH)
    if !algoEq {
        err = errors.New("ecdh: unknown public key algorithm")
        return
    }

    // 解析
    keyData := &pki

    paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        return nil, errors.New("ecdh: invalid ECDH parameters")
    }

    namedCurve := namedCurveFromOid(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("ecdh: unsupported ecdh curve")
        return
    }

    publicKeyBytes := []byte(keyData.PublicKey.RightAlign())

    pub, err = namedCurve.NewPublicKey(publicKeyBytes)
    if err != nil {
        return
    }

    return
}

// ====================

// 包装私钥
func MarshalPrivateKey(key *ecdh.PrivateKey) ([]byte, error) {
    var privKey pkcs8

    oid, ok := oidFromNamedCurve(key.Curve())
    if !ok {
        return nil, errors.New("x509: unsupported ecdh curve")
    }

    // 创建数据
    paramBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("ecdh: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyECDH,
        Parameters: asn1.RawValue{
            FullBytes: paramBytes,
        },
    }

    privKey.PrivateKey = key.Bytes()

    return asn1.Marshal(privKey)
}

// 解析私钥
func ParsePrivateKey(derBytes []byte) (*ecdh.PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    algoEq := privKey.Algo.Algorithm.Equal(oidPublicKeyECDH)
    if !algoEq {
        err = errors.New("ecdh: unknown private key algorithm")
        return nil, err
    }

    paramsDer := cryptobyte.String(privKey.Algo.Parameters.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        return nil, errors.New("ecdh: invalid ECDH parameters")
    }

    namedCurve := namedCurveFromOid(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("ecdh: unsupported ecdh curve")
        return nil, err
    }

    priv, err := namedCurve.NewPrivateKey(privKey.PrivateKey)
    if err != nil {
        return nil, err
    }

    return priv, nil
}

// ====================

func namedCurveFromOid(oid asn1.ObjectIdentifier) ecdh.Curve {
    switch {
        case oid.Equal(oidNamedCurveP256):
            return ecdh.P256()
        case oid.Equal(oidNamedCurveP384):
            return ecdh.P384()
        case oid.Equal(oidNamedCurveP521):
            return ecdh.P521()
        case oid.Equal(oidNamedCurveX25519):
            return ecdh.X25519()
    }

    return nil
}

func oidFromNamedCurve(curve ecdh.Curve) (asn1.ObjectIdentifier, bool) {
    switch curve {
        case ecdh.P256():
            return oidNamedCurveP256, true
        case ecdh.P384():
            return oidNamedCurveP384, true
        case ecdh.P521():
            return oidNamedCurveP521, true
        case ecdh.X25519():
            return oidNamedCurveX25519, true
    }

    return asn1.ObjectIdentifier{}, false
}

