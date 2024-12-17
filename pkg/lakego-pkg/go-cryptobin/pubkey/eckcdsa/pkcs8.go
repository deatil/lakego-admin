package eckcdsa

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
)

const ecPrivKeyVersion = 1

var (
    oidPublicKeyECKCDSA        = asn1.ObjectIdentifier{1, 0, 14888, 3, 0, 5} // {iso(1) standard(0) digital-signature-with-appendix(14888) part3(3) algorithm(0) ec-kcdsa(5)}
    oidPublicKeyECKCDSAAlteGOV = asn1.ObjectIdentifier{1, 2, 410, 200004, 1, 100, 2, 1} // eGOV-C01.0008

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

// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
    Version       int
    PrivateKey    []byte
    NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
    PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// Marshal PublicKey to der
func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    oid, ok := OidFromNamedCurve(pub.Curve)
    if !ok {
        return nil, errors.New("eckcdsa: unsupported eckcdsa curve")
    }

    var paramBytes []byte
    paramBytes, err = asn1.Marshal(oid)
    if err != nil {
        return nil, err
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyECKCDSA
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return nil, errors.New("eckcdsa: invalid elliptic curve public key")
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
        err = errors.New("eckcdsa: trailing data after ASN.1 of public-key")
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    oid := pki.Algorithm.Algorithm
    params := pki.Algorithm.Parameters
    der := cryptobyte.String(pki.PublicKey.RightAlign())

    if !oid.Equal(oidPublicKeyECKCDSA) &&
        !oid.Equal(oidPublicKeyECKCDSAAlteGOV) {
        err = errors.New("eckcdsa: unknown public key algorithm")
        return
    }

    paramsDer := cryptobyte.String(params.FullBytes)
    namedCurveOID := new(asn1.ObjectIdentifier)
    if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
        return nil, errors.New("eckcdsa: invalid parameters")
    }

    namedCurve := NamedCurveFromOid(*namedCurveOID)
    if namedCurve == nil {
        err = errors.New("eckcdsa: unsupported eckcdsa curve")
        return
    }

    x, y := elliptic.Unmarshal(namedCurve, der)
    if x == nil {
        err = errors.New("eckcdsa: failed to unmarshal elliptic curve point")
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
        return nil, errors.New("eckcdsa: unsupported eckcdsa curve")
    }

    oidBytes, err := asn1.Marshal(oid)
    if err != nil {
        return nil, errors.New("eckcdsa: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyECKCDSA,
        Parameters: asn1.RawValue{
            FullBytes: oidBytes,
        },
    }

    privKey.PrivateKey, err = marshalECPrivateKeyWithOID(key, nil)
    if err != nil {
        return nil, errors.New("eckcdsa: failed to marshal EC private key while building PKCS#8: " + err.Error())
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

    if !privKey.Algo.Algorithm.Equal(oidPublicKeyECKCDSA) &&
        !privKey.Algo.Algorithm.Equal(oidPublicKeyECKCDSAAlteGOV) {
        err = errors.New("eckcdsa: unknown private key algorithm")
        return nil, err
    }

    bytes := privKey.Algo.Parameters.FullBytes

    namedCurveOID := new(asn1.ObjectIdentifier)
    if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
        namedCurveOID = nil
    }

    key, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
    if err != nil {
        return nil, errors.New("eckcdsa: failed to parse EC private key embedded in PKCS#8: " + err.Error())
    }

    return key, nil
}

// marshalECPrivateKeyWithOID marshals an SM2 private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key *PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
    if !key.Curve.IsOnCurve(key.X, key.Y) {
        return nil, errors.New("eckcdsa: invalid elliptic key public key")
    }

    privateKey := make([]byte, BitsToBytes(key.D.BitLen()))

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
        return nil, errors.New("eckcdsa: failed to parse EC private key: " + err.Error())
    }

    if privKey.Version != ecPrivKeyVersion {
        return nil, fmt.Errorf("eckcdsa: unknown EC private key version %d", privKey.Version)
    }

    var curve elliptic.Curve
    if namedCurveOID != nil {
        curve = NamedCurveFromOid(*namedCurveOID)
    } else {
        curve = NamedCurveFromOid(privKey.NamedCurveOID)
    }

    if curve == nil {
        return nil, errors.New("eckcdsa: unknown elliptic curve")
    }

    k := new(big.Int).SetBytes(privKey.PrivateKey)

    curveOrder := curve.Params().N
    if k.Cmp(curveOrder) >= 0 {
        return nil, errors.New("eckcdsa: invalid elliptic curve private key value")
    }

    priv := new(PrivateKey)
    priv.Curve = curve
    priv.D = k

    privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

    for len(privKey.PrivateKey) > len(privateKey) {
        if privKey.PrivateKey[0] != 0 {
            return nil, errors.New("eckcdsa: invalid private key length")
        }

        privKey.PrivateKey = privKey.PrivateKey[1:]
    }

    copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)

    d := new(big.Int).SetBytes(privateKey)
    priv.X, priv.Y = XY(d, curve)

    return priv, nil
}

func BitsToBytes(bits int) int {
    return (bits + 7) / 8
}
