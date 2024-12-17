package elgamal

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
    // Unsure about this OID
    // oidPublicKeyElGamal = asn1.ObjectIdentifier{1, 3, 14, 7, 2, 1, 1}
    // oidMD2WithRSA       = asn1.ObjectIdentifier{1, 3, 14, 7, 2, 3, 1}
    // oidMD2WithElGamal   = asn1.ObjectIdentifier{1, 3, 14, 7, 2, 3, 2}

    // cryptlib public-key algorithm
    oidPublicKeyElGamal     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3029, 1, 2, 1}
    oidElGamalWithSHA1      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3029, 1, 2, 1, 1}
    oidElGamalWithRIPEMD160 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3029, 1, 2, 1, 2}
)

// elgamal Parameters
type elgamalAlgorithmParameters struct {
    // PKCS_3 for DH PARAMETERS (p || g)
    P, G *big.Int

    // ANSI_X9_42 only for X9.42 DH PARAMETERS (p || g || q)
    Q *big.Int `asn1:"optional"`
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
 * elgamal pkcs8
 *
 * @create 2023-6-16
 * @author deatil
 */
type PKCS8Key struct {}

// NewPKCS8Key
func NewPKCS8Key() PKCS8Key {
    return PKCS8Key{}
}

// Marshal PKCS8 PublicKey
func (this PKCS8Key) MarshalPublicKey(key *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    // q = (p - 1) / 2
    q := new(big.Int).Set(key.P)
    q.Sub(q, one)
    q.Div(q, two)

    // params
    paramBytes, err := asn1.Marshal(elgamalAlgorithmParameters{
        P: key.P,
        G: key.G,
        Q: q,
    })
    if err != nil {
        return nil, errors.New("cryptobin/elgamal: failed to marshal algo param: " + err.Error())
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyElGamal
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    var yInt cryptobyte.Builder
    yInt.AddASN1BigInt(key.Y)

    publicKeyBytes, err = yInt.Bytes()
    if err != nil {
        return nil, errors.New("cryptobin/elgamal: failed to builder PrivateKey: " + err.Error())
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

// Marshal PKCS8 PublicKey
func MarshalPKCS8PublicKey(pub *PublicKey) ([]byte, error) {
    return defaultPKCS8Key.MarshalPublicKey(pub)
}

// Parse PKCS8 PublicKey
func (this PKCS8Key) ParsePublicKey(der []byte) (*PublicKey, error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(der, &pki)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyElGamal)
    if !algoEq {
        return nil, errors.New("cryptobin/elgamal: unknown public key algorithm")
    }

    yDer := cryptobyte.String(pki.PublicKey.RightAlign())

    y := new(big.Int)
    if !yDer.ReadASN1Integer(y) {
        return nil, errors.New("cryptobin/elgamal: invalid ElGamal public key")
    }

    pub := &PublicKey{
        G: new(big.Int),
        P: new(big.Int),
        Y: y,
    }

    paramsDer := cryptobyte.String(pki.Algorithm.Parameters.FullBytes)
    if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
        !paramsDer.ReadASN1Integer(pub.P) ||
        !paramsDer.ReadASN1Integer(pub.G) {
        return nil, errors.New("cryptobin/elgamal: invalid ElGamal public key")
    }

    if pub.Y.Sign() <= 0 ||
        pub.G.Sign() <= 0 ||
        pub.P.Sign() <= 0 {
        return nil, errors.New("cryptobin/elgamal: zero or negative ElGamal parameter")
    }

    return pub, nil
}

// Parse PKCS8 PublicKey
func ParsePKCS8PublicKey(derBytes []byte) (*PublicKey, error) {
    return defaultPKCS8Key.ParsePublicKey(derBytes)
}

// Marshal PKCS8 PrivateKey
func (this PKCS8Key) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    // q = (p - 1) / 2
    q := new(big.Int).Set(key.P)
    q.Sub(q, one)
    q.Div(q, two)

    // params
    paramBytes, err := asn1.Marshal(elgamalAlgorithmParameters{
        P: key.P,
        G: key.G,
        Q: q,
    })
    if err != nil {
        return nil, errors.New("cryptobin/elgamal: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyElGamal,
        Parameters: asn1.RawValue{
            FullBytes: paramBytes,
        },
    }

    var xInt cryptobyte.Builder
    xInt.AddASN1BigInt(key.X)

    privateKeyBytes, err := xInt.Bytes()
    if err != nil {
        return nil, errors.New("cryptobin/elgamal: failed to builder PrivateKey: " + err.Error())
    }

    privKey.PrivateKey = privateKeyBytes

    return asn1.Marshal(privKey)
}

// Marshal PKCS8 PrivateKey
func MarshalPKCS8PrivateKey(key *PrivateKey) ([]byte, error) {
    return defaultPKCS8Key.MarshalPrivateKey(key)
}

// Parse PKCS8 PrivateKey
func (this PKCS8Key) ParsePrivateKey(der []byte) (key *PrivateKey, err error) {
    var privKey pkcs8
    _, err = asn1.Unmarshal(der, &privKey)
    if err != nil {
        return nil, err
    }

    if !privKey.Algo.Algorithm.Equal(oidPublicKeyElGamal) {
        return nil, fmt.Errorf("cryptobin/elgamal: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }

    xDer := cryptobyte.String(string(privKey.PrivateKey))

    x := new(big.Int)
    if !xDer.ReadASN1Integer(x) {
        return nil, errors.New("cryptobin/elgamal: invalid ElGamal public key")
    }

    priv := &PrivateKey{
        PublicKey: PublicKey{
            G: new(big.Int),
            P: new(big.Int),
            Y: new(big.Int),
        },
        X: x,
    }

    // 找出 g, p 数据
    paramsDer := cryptobyte.String(privKey.Algo.Parameters.FullBytes)
    if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
        !paramsDer.ReadASN1Integer(priv.P) ||
        !paramsDer.ReadASN1Integer(priv.G) {
        return nil, errors.New("cryptobin/elgamal: invalid ElGamal private key")
    }

    // 算出 Y 值
    priv.Y.Exp(priv.G, priv.X, priv.P)

    if priv.Y.Sign() <= 0 || priv.G.Sign() <= 0 ||
        priv.P.Sign() <= 0 || priv.X.Sign() <= 0 {
        return nil, errors.New("cryptobin/elgamal: zero or negative ElGamal parameter")
    }

    return priv, nil
}

// Parse PKCS8 PrivateKey
func ParsePKCS8PrivateKey(derBytes []byte) (key *PrivateKey, err error) {
    return defaultPKCS8Key.ParsePrivateKey(derBytes)
}
