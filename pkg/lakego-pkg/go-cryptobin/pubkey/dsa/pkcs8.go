package dsa

import (
    "fmt"
    "errors"
    "math/big"
    "crypto/dsa"
    "crypto/x509/pkix"
    "encoding/asn1"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
    // dsa PublicKey oid
    oidPublicKeyDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
)

// dsa Parameters
type dsaAlgorithmParameters struct {
    // ANSI_X9_57 for DSA PARAMETERS
    P, Q, G *big.Int
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

var (
    defaultPKCS8Key = NewPKCS8Key()
)

/**
 * dsa pkcs8
 *
 * @create 2022-3-19
 * @author deatil
 */
type PKCS8Key struct {}

// NewPKCS8Key
func NewPKCS8Key() PKCS8Key {
    return PKCS8Key{}
}

// Marshal PublicKey to der
func (this PKCS8Key) MarshalPublicKey(key *dsa.PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    // 创建数据
    paramBytes, err := asn1.Marshal(dsaAlgorithmParameters{
        P: key.P,
        Q: key.Q,
        G: key.G,
    })
    if err != nil {
        return nil, errors.New("dsa: failed to marshal algo param: " + err.Error())
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyDSA
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    var yInt cryptobyte.Builder
    yInt.AddASN1BigInt(key.Y)

    publicKeyBytes, err = yInt.Bytes()
    if err != nil {
        return nil, errors.New("dsa: failed to builder PrivateKey: " + err.Error())
    }

    pkix := pkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    return asn1.Marshal(pkix)
}

// Marshal PublicKey to der
func MarshalPKCS8PublicKey(pub *dsa.PublicKey) ([]byte, error) {
    return defaultPKCS8Key.MarshalPublicKey(pub)
}

// Parse PublicKey der
func (this PKCS8Key) ParsePublicKey(der []byte) (*dsa.PublicKey, error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(der, &pki)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyDSA)
    if !algoEq {
        return nil, errors.New("dsa: unknown public key algorithm")
    }

    yDer := cryptobyte.String(pki.PublicKey.RightAlign())

    y := new(big.Int)
    if !yDer.ReadASN1Integer(y) {
        return nil, errors.New("dsa: invalid DSA public key")
    }

    pub := &dsa.PublicKey{
        Y: y,
        Parameters: dsa.Parameters{
            P: new(big.Int),
            Q: new(big.Int),
            G: new(big.Int),
        },
    }

    paramsDer := cryptobyte.String(pki.Algorithm.Parameters.FullBytes)
    if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
        !paramsDer.ReadASN1Integer(pub.P) ||
        !paramsDer.ReadASN1Integer(pub.Q) ||
        !paramsDer.ReadASN1Integer(pub.G) {
        return nil, errors.New("dsa: invalid DSA parameters")
    }

    if pub.Y.Sign() <= 0 || pub.P.Sign() <= 0 ||
        pub.Q.Sign() <= 0 || pub.G.Sign() <= 0 {
        return nil, errors.New("dsa: zero or negative DSA parameter")
    }

    return pub, nil
}

// Parse PublicKey der
func ParsePKCS8PublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    return defaultPKCS8Key.ParsePublicKey(derBytes)
}

// Marshal PrivateKey to der
func (this PKCS8Key) MarshalPrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    var privKey pkcs8

    // params
    paramBytes, err := asn1.Marshal(dsaAlgorithmParameters{
        P: key.P,
        Q: key.Q,
        G: key.G,
    })
    if err != nil {
        return nil, errors.New("dsa: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyDSA,
        Parameters: asn1.RawValue{
            FullBytes: paramBytes,
        },
    }

    var xInt cryptobyte.Builder
    xInt.AddASN1BigInt(key.X)

    privateKeyBytes, err := xInt.Bytes()
    if err != nil {
        return nil, errors.New("dsa: failed to builder PrivateKey: " + err.Error())
    }

    privKey.PrivateKey = privateKeyBytes

    return asn1.Marshal(privKey)
}

// Marshal PrivateKey to der
func MarshalPKCS8PrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    return defaultPKCS8Key.MarshalPrivateKey(key)
}

// Parse PrivateKey der
func (this PKCS8Key) ParsePrivateKey(der []byte) (key *dsa.PrivateKey, err error) {
    var privKey pkcs8
    _, err = asn1.Unmarshal(der, &privKey)
    if err != nil {
        return nil, err
    }

    if !privKey.Algo.Algorithm.Equal(oidPublicKeyDSA) {
        return nil, fmt.Errorf("dsa: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }

    xDer := cryptobyte.String(string(privKey.PrivateKey))

    x := new(big.Int)
    if !xDer.ReadASN1Integer(x) {
        return nil, errors.New("dsa: invalid DSA public key")
    }

    priv := &dsa.PrivateKey{
        PublicKey: dsa.PublicKey{
            Parameters: dsa.Parameters{
                P: new(big.Int),
                Q: new(big.Int),
                G: new(big.Int),
            },
            Y: new(big.Int),
        },
        X: x,
    }

    // get p,q,g data
    paramsDer := cryptobyte.String(privKey.Algo.Parameters.FullBytes)
    if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
        !paramsDer.ReadASN1Integer(priv.P) ||
        !paramsDer.ReadASN1Integer(priv.Q) ||
        !paramsDer.ReadASN1Integer(priv.G) {
        return nil, errors.New("dsa: invalid DSA parameters")
    }

    // get Y data
    priv.Y.Exp(priv.G, x, priv.P)

    if priv.Y.Sign() <= 0 || priv.P.Sign() <= 0 ||
        priv.Q.Sign() <= 0 || priv.G.Sign() <= 0 {
        return nil, errors.New("dsa: zero or negative DSA parameter")
    }

    return priv, nil
}

// Parse PrivateKey der
func ParsePKCS8PrivateKey(derBytes []byte) (key *dsa.PrivateKey, err error) {
    return defaultPKCS8Key.ParsePrivateKey(derBytes)
}
