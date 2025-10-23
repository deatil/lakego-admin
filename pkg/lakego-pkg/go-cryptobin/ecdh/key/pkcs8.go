package key

import (
    "errors"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"

    "github.com/deatil/go-cryptobin/ecdh"
)

// Marshal and Parse ECDH key
// 私钥和公钥生成，OID 包含 ECDH 的 OID 和 EC 曲线的 OID，
// 非 EC 曲线单独证书

var (
    // ECDH
    oidPublicKeyECDH      = asn1.ObjectIdentifier{1, 3, 132, 1, 12}
    oidPublicKeyX25519    = asn1.ObjectIdentifier{1, 3, 101, 110}
    oidPublicKeyX448      = asn1.ObjectIdentifier{1, 3, 101, 111}
    oidPublicKeyEd25519   = asn1.ObjectIdentifier{1, 3, 101, 112}
    oidPublicKeyEd448     = asn1.ObjectIdentifier{1, 3, 101, 113}
    oidPublicKeyEd25519ph = asn1.ObjectIdentifier{1, 3, 101, 114}
    oidPublicKeyEd448ph   = asn1.ObjectIdentifier{1, 3, 101, 115}

    // ECMQV
    oidPublicKeyECMQV = asn1.ObjectIdentifier{1, 3, 132, 1, 13}

    oidNamedCurveP256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
    oidNamedCurveP384   = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
    oidNamedCurveP521   = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
    oidNamedCurveX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
    oidNamedCurveX448   = asn1.ObjectIdentifier{1, 3, 101, 111}
    oidNamedCurveGmSM2  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

func init() {
    AddNamedCurve(ecdh.P256(), oidNamedCurveP256)
    AddNamedCurve(ecdh.P384(), oidNamedCurveP384)
    AddNamedCurve(ecdh.P521(), oidNamedCurveP521)
    AddNamedCurve(ecdh.X25519(), oidNamedCurveX25519)
    AddNamedCurve(ecdh.X448(), oidNamedCurveX448)
    AddNamedCurve(ecdh.GmSM2(), oidNamedCurveGmSM2)
}

type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// Marshal PublicKey
func MarshalPublicKey(key *ecdh.PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    oid, ok := OidFromNamedCurve(key.Curve())
    if !ok {
        return nil, errors.New("go-cryptobin/ecdh: unsupported ecdh curve")
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

// Parse PublicKey
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
        err = errors.New("go-cryptobin/ecdh: unknown public key algorithm")
        return
    }

    paramsDer := cryptobyte.String(pki.Algorithm.Parameters.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        return nil, errors.New("go-cryptobin/ecdh: invalid ECDH parameters")
    }

    namedCurve := NamedCurveFromOid(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("go-cryptobin/ecdh: unsupported ecdh curve")
        return
    }

    publicKeyBytes := []byte(pki.PublicKey.RightAlign())

    pub, err = namedCurve.NewPublicKey(publicKeyBytes)
    if err != nil {
        return
    }

    return
}

// ====================

// Marshal PrivateKey
func MarshalPrivateKey(key *ecdh.PrivateKey) ([]byte, error) {
    var privKey pkcs8

    oid, ok := OidFromNamedCurve(key.Curve())
    if !ok {
        return nil, errors.New("go-cryptobin/ecdh: unsupported ecdh curve")
    }

    // 创建数据
    paramBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("go-cryptobin/ecdh: failed to marshal algo param: " + err.Error())
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

// Parse PrivateKey
func ParsePrivateKey(derBytes []byte) (*ecdh.PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    algoEq := privKey.Algo.Algorithm.Equal(oidPublicKeyECDH)
    if !algoEq {
        err = errors.New("go-cryptobin/ecdh: unknown private key algorithm")
        return nil, err
    }

    paramsDer := cryptobyte.String(privKey.Algo.Parameters.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        return nil, errors.New("go-cryptobin/ecdh: invalid ECDH parameters")
    }

    namedCurve := NamedCurveFromOid(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("go-cryptobin/ecdh: unsupported ecdh curve")
        return nil, err
    }

    priv, err := namedCurve.NewPrivateKey(privKey.PrivateKey)
    if err != nil {
        return nil, err
    }

    return priv, nil
}
