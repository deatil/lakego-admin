package e521

import (
    "errors"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"

    "github.com/deatil/go-cryptobin/elliptic/e521"
)

var (
    // E-521 EdDSA oid
    oidPublicKeyE521 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44588, 2, 1}
)

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
    if pub.Curve != e521.E521() {
        return nil, errors.New("go-cryptobin/e521: unsupported curve")
    }

    publicKeyBytes := e521.Marshal(pub.Curve, pub.X, pub.Y)

    pkix := pkixPublicKey{
        Algo: pkix.AlgorithmIdentifier{
            Algorithm:  oidPublicKeyE521,
            Parameters: asn1.RawValue{Tag: asn1.TagOID},
        },
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
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyE521)
    if !algoEq {
        err = errors.New("go-cryptobin/e521: unknown public key algorithm")
        return
    }

    curve := e521.E521()

    der := cryptobyte.String(pki.PublicKey.RightAlign())

    x, y := e521.Unmarshal(curve, der)
    if x == nil {
        err = errors.New("go-cryptobin/e521: failed to unmarshal elliptic curve point")
        return
    }

    pub = &PublicKey{
        Curve: curve,
        X:     x,
        Y:     y,
    }

    return
}

// Marshal PrivateKey to der
func MarshalPrivateKey(priv *PrivateKey) ([]byte, error) {
    if priv.Curve != e521.E521() {
        return nil, errors.New("go-cryptobin/e521: unsupported curve")
    }

    var privKey pkcs8

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyE521,
        Parameters: asn1.RawValue{
            Tag: asn1.TagOID,
        },
    }

    curveSize := (priv.Curve.Params().BitSize + 7) / 8
    dBytes := e521.FromBigint(priv.D, curveSize)

    privKey.PrivateKey = dBytes

    return asn1.Marshal(privKey)
}

// Parse PrivateKey der
func ParsePrivateKey(der []byte) (*PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(der, &privKey)
    if err != nil {
        return nil, err
    }

    algoEq := privKey.Algo.Algorithm.Equal(oidPublicKeyE521)
    if !algoEq {
        err = errors.New("go-cryptobin/e521: unknown private key algorithm")
        return nil, err
    }

    curve := e521.E521()

    D := e521.ToBigint(privKey.PrivateKey)

    curveSize := (curve.Params().BitSize + 7) / 8
    x, y := curve.ScalarBaseMult(e521.FromBigint(D, curveSize))

    if x == nil || y == nil {
        return nil, errors.New("go-cryptobin/e521: failed to unmarshal public key")
    }

    if !curve.IsOnCurve(x, y) {
        return nil, errors.New("go-cryptobin/e521: private key is not on the curve")
    }

    priv := new(PrivateKey)
    priv.Curve = curve
    priv.D = D
    priv.PublicKey.X = x
    priv.PublicKey.Y = y

    return priv, nil
}
