package bip0340

import (
    "errors"
    "encoding/asn1"
    "crypto/elliptic"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"

    "github.com/deatil/go-cryptobin/elliptic/frp256v1"
    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
    "github.com/deatil/go-cryptobin/elliptic/brainpool"
)

var (
    oidPublicKeyBIP0340 = asn1.ObjectIdentifier{1, 0, 14888, 3, 0, 14}

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

    AddNamedCurve(frp256v1.FRP256v1(), frp256v1.OIDNamedCurveFRP256v1)
    AddNamedCurve(secp256k1.S256(), secp256k1.OIDNamedCurveSecp256k1)

    AddNamedCurve(brainpool.P256r1(), brainpool.OIDBrainpoolP256r1)
    AddNamedCurve(brainpool.P256t1(), brainpool.OIDBrainpoolP256t1)
    AddNamedCurve(brainpool.P320r1(), brainpool.OIDBrainpoolP320r1)
    AddNamedCurve(brainpool.P320t1(), brainpool.OIDBrainpoolP320t1)
    AddNamedCurve(brainpool.P384r1(), brainpool.OIDBrainpoolP384r1)
    AddNamedCurve(brainpool.P384t1(), brainpool.OIDBrainpoolP384t1)
    AddNamedCurve(brainpool.P512r1(), brainpool.OIDBrainpoolP512r1)
    AddNamedCurve(brainpool.P512t1(), brainpool.OIDBrainpoolP512t1)
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
        return nil, errors.New("go-cryptobin/bip0340: unsupported ecgdsa curve")
    }

    var paramBytes []byte
    paramBytes, err = asn1.Marshal(oid)
    if err != nil {
        return nil, err
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyBIP0340
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return nil, errors.New("go-cryptobin/bip0340: invalid elliptic curve public key")
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
        err = errors.New("go-cryptobin/bip0340: trailing data after ASN.1 of public-key")
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    oid := pki.Algorithm.Algorithm
    params := pki.Algorithm.Parameters
    der := cryptobyte.String(pki.PublicKey.RightAlign())

    if !oid.Equal(oidPublicKeyBIP0340) {
        err = errors.New("go-cryptobin/bip0340: unknown public key algorithm")
        return
    }

    paramsDer := cryptobyte.String(params.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        return nil, errors.New("go-cryptobin/bip0340: invalid parameters")
    }

    namedCurve := NamedCurveFromOid(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("go-cryptobin/bip0340: unsupported ecgdsa curve")
        return
    }

    x, y := elliptic.Unmarshal(namedCurve, der)
    if x == nil {
        err = errors.New("go-cryptobin/bip0340: failed to unmarshal elliptic curve point")
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
        return nil, errors.New("go-cryptobin/bip0340: unsupported ecgdsa curve")
    }

    oidBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("go-cryptobin/bip0340: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyBIP0340,
        Parameters: asn1.RawValue{
            FullBytes: oidBytes,
        },
    }

    privKey.PrivateKey, err = marshalECPrivateKeyWithOID(key, nil)
    if err != nil {
        return nil, errors.New("go-cryptobin/bip0340: failed to marshal EC private key while building PKCS#8: " + err.Error())
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

    if !privKey.Algo.Algorithm.Equal(oidPublicKeyBIP0340) {
        err = errors.New("go-cryptobin/bip0340: unknown private key algorithm")
        return nil, err
    }

    bytes := privKey.Algo.Parameters.FullBytes

    namedCurveOID := new(asn1.ObjectIdentifier)
    if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
        namedCurveOID = nil
    }

    key, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
    if err != nil {
        return nil, errors.New("go-cryptobin/bip0340: failed to parse EC private key embedded in PKCS#8: " + err.Error())
    }

    return key, nil
}
