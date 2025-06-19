package elgamalecc

import (
    "errors"
    "encoding/asn1"
    "crypto/elliptic"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"

    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
)

var (
    // public-key algorithm
    oidPublicKeyElGamal = asn1.ObjectIdentifier{1, 3, 14, 7, 2, 1, 1}

    oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
    oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
    oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
    oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func init() {
    AddNamedCurve(elliptic.P224(), oidNamedCurveP224)
    AddNamedCurve(elliptic.P256(), oidNamedCurveP256)
    AddNamedCurve(elliptic.P384(), oidNamedCurveP384)
    AddNamedCurve(elliptic.P521(), oidNamedCurveP521)

    AddNamedCurve(secp256k1.S256(), secp256k1.OIDNamedCurveSecp256k1)
}

// Marshal privateKey struct
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

// Marshal publicKey struct
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// Parse publicKey struct
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// Marshal PublicKey to der
func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    oid, ok := OidFromNamedCurve(pub.Curve)
    if !ok {
        return nil, errors.New("go-cryptobin/elgamalecc: unsupported ecgdsa curve")
    }

    var paramBytes []byte
    paramBytes, err = asn1.Marshal(oid)
    if err != nil {
        return nil, err
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyElGamal
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return nil, errors.New("go-cryptobin/elgamalecc: invalid elliptic curve public key")
    }

    publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)

    pkix := pkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    return asn1.Marshal(pkix)
}

// Parse PublicKey der
func ParsePublicKey(derBytes []byte) (pub *PublicKey, err error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
    if err != nil {
        return
    } else if len(rest) != 0 {
        err = errors.New("go-cryptobin/elgamalecc: trailing data after ASN.1 of public-key")
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    oid := pki.Algorithm.Algorithm
    params := pki.Algorithm.Parameters
    der := cryptobyte.String(pki.PublicKey.RightAlign())

    if !oid.Equal(oidPublicKeyElGamal) {
        err = errors.New("go-cryptobin/elgamalecc: unknown public key algorithm")
        return
    }

    paramsDer := cryptobyte.String(params.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        return nil, errors.New("go-cryptobin/elgamalecc: invalid parameters")
    }

    namedCurve := NamedCurveFromOid(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("go-cryptobin/elgamalecc: unsupported ecgdsa curve")
        return
    }

    x, y := elliptic.Unmarshal(namedCurve, der)
    if x == nil {
        err = errors.New("go-cryptobin/elgamalecc: failed to unmarshal elliptic curve point")
        return
    }

    pub = &PublicKey{
        Curve: namedCurve,
        X:     x,
        Y:     y,
    }

    return
}

// Marshal PrivateKey to der
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    oid, ok := OidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("go-cryptobin/elgamalecc: unsupported ecgdsa curve")
    }

    // 创建数据
    oidBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("go-cryptobin/elgamalecc: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyElGamal,
        Parameters: asn1.RawValue{
            FullBytes: oidBytes,
        },
    }

    privKey.PrivateKey, err = marshalECPrivateKeyWithOID(key, nil)
    if err != nil {
        return nil, errors.New("go-cryptobin/elgamalecc: failed to marshal EC private key while building PKCS#8: " + err.Error())
    }

    return asn1.Marshal(privKey)
}

// Parse PrivateKey der
func ParsePrivateKey(derBytes []byte) (*PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    if !privKey.Algo.Algorithm.Equal(oidPublicKeyElGamal) {
        err = errors.New("go-cryptobin/elgamalecc: unknown private key algorithm")
        return nil, err
    }

    bytes := privKey.Algo.Parameters.FullBytes

    namedCurveOID := new(asn1.ObjectIdentifier)
    if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
        namedCurveOID = nil
    }

    key, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/elgamalecc: failed to parse EC private key embedded in PKCS#8: " + err.Error())
    }

    return key, nil
}
