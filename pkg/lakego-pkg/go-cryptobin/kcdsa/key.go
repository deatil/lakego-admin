package kcdsa

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
)

var (
    oidPublicKeyKCDSA        = asn1.ObjectIdentifier{1, 0, 14888, 3, 0, 2}    // {iso(1) standard(0) digital-signature-with-appendix(14888) part3(3) algorithm(0) kcdsa(2)}
    oidPublicKeyKCDSAAlteGOV = asn1.ObjectIdentifier{1, 2, 410, 200004, 1, 1} // eGOV-C01.0008
)

/**
https://patents.google.com/patent/KR20040064780A/ko

P-KCDSASignatureValue ::= SEQUENCE {
    r BIT STRING,
    s INTEGER }

P-KCDSAParameters ::= SEQUENCE {
    p INTEGER, -- odd prime p = 2Jq+1
    q INTEGER, -- odd prime
    g INTEGER, -- generator of order q
    J INTEGER OPTIONAL, -- odd prime
    Seed OCTET STRING OPTIONAL
    Count INTEGER OPTIONAL }

P-KCDSAPublicKey ::= INTEGER -- Public key y
*/
// kcdsa Parameters
type kcdsaAlgorithmParameters struct {
    P, Q, G *big.Int

    J     *big.Int `asn1:"optional"`
    Seed  []byte   `asn1:"optional"`
    Count int      `asn1:"optional"`
}

// 私钥 - 包装
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
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

var (
    defaultPKCS8Key = NewPKCS8Key()
)

/**
 * pkcs8 密钥
 *
 * @create 2024-8-12
 * @author deatil
 */
type PKCS8Key struct {}

// 构造函数
func NewPKCS8Key() PKCS8Key {
    return PKCS8Key{}
}

// PKCS8 包装公钥
func (this PKCS8Key) MarshalPublicKey(key *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    params := kcdsaAlgorithmParameters{
        P: key.P,
        Q: key.Q,
        G: key.G,
    }
    if key.GenParameters.IsValid() {
        params.J = key.GenParameters.J
        params.Seed = key.GenParameters.Seed
        params.Count = key.GenParameters.Count
    }

    // Marshal params
    paramBytes, err := asn1.Marshal(params)
    if err != nil {
        return nil, errors.New("kcdsa: failed to marshal algo param: " + err.Error())
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyKCDSA
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    var yInt cryptobyte.Builder
    yInt.AddASN1BigInt(key.Y)

    publicKeyBytes, err = yInt.Bytes()
    if err != nil {
        return nil, errors.New("kcdsa: failed to builder PrivateKey: " + err.Error())
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

// PKCS8 包装公钥
func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
    return defaultPKCS8Key.MarshalPublicKey(pub)
}

// PKCS8 解析公钥
func (this PKCS8Key) ParsePublicKey(der []byte) (*PublicKey, error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(der, &pki)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    if !pki.Algorithm.Algorithm.Equal(oidPublicKeyKCDSA) &&
        !pki.Algorithm.Algorithm.Equal(oidPublicKeyKCDSAAlteGOV) {
        return nil, errors.New("kcdsa: unknown public key algorithm")
    }

    // 解析
    keyData := &pki

    yDer := cryptobyte.String(keyData.PublicKey.RightAlign())

    y := new(big.Int)
    if !yDer.ReadASN1Integer(y) {
        return nil, errors.New("kcdsa: invalid KCDSA public key")
    }

    // Parse parameters
    bytes := keyData.Algorithm.Parameters.FullBytes
    var params kcdsaAlgorithmParameters
    if _, err = asn1.Unmarshal(bytes, &params); err != nil {
        return nil, errors.New("kcdsa: invalid KCDSA parameter")
    }

    pub := &PublicKey{
        Y: y,
        Parameters: Parameters{
            P: params.P,
            Q: params.Q,
            G: params.G,

            GenParameters: GenerationParameters{
                J:     params.J,
                Seed:  params.Seed,
                Count: params.Count,
            },
        },
    }

    if pub.Y.Sign() <= 0 || pub.P.Sign() <= 0 ||
        pub.Q.Sign() <= 0 || pub.G.Sign() <= 0 {
        return nil, errors.New("kcdsa: zero or negative KCDSA parameter")
    }

    return pub, nil
}

// PKCS8 解析公钥
func ParsePublicKey(derBytes []byte) (*PublicKey, error) {
    return defaultPKCS8Key.ParsePublicKey(derBytes)
}

// ====================

// PKCS8 包装私钥
func (this PKCS8Key) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    params := kcdsaAlgorithmParameters{
        P: key.P,
        Q: key.Q,
        G: key.G,
    }
    if key.GenParameters.IsValid() {
        params.J = key.GenParameters.J
        params.Seed = key.GenParameters.Seed
        params.Count = key.GenParameters.Count
    }

    // Marshal params
    paramBytes, err := asn1.Marshal(params)
    if err != nil {
        return nil, errors.New("kcdsa: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyKCDSA,
        Parameters: asn1.RawValue{
            FullBytes: paramBytes,
        },
    }

    var xInt cryptobyte.Builder
    xInt.AddASN1BigInt(key.X)

    privateKeyBytes, err := xInt.Bytes()
    if err != nil {
        return nil, errors.New("kcdsa: failed to builder PrivateKey: " + err.Error())
    }

    privKey.PrivateKey = privateKeyBytes

    return asn1.Marshal(privKey)
}

// PKCS8 包装私钥
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    return defaultPKCS8Key.MarshalPrivateKey(key)
}

// PKCS8 解析私钥
func (this PKCS8Key) ParsePrivateKey(der []byte) (key *PrivateKey, err error) {
    var privKey pkcs8
    _, err = asn1.Unmarshal(der, &privKey)
    if err != nil {
        return nil, err
    }

    if !privKey.Algo.Algorithm.Equal(oidPublicKeyKCDSA) &&
        !privKey.Algo.Algorithm.Equal(oidPublicKeyKCDSAAlteGOV) {
        return nil, fmt.Errorf("kcdsa: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }

    xDer := cryptobyte.String(string(privKey.PrivateKey))

    x := new(big.Int)
    if !xDer.ReadASN1Integer(x) {
        return nil, errors.New("kcdsa: invalid KCDSA public key")
    }

    // Parse parameters
    bytes := privKey.Algo.Parameters.FullBytes
    var params kcdsaAlgorithmParameters
    if _, err = asn1.Unmarshal(bytes, &params); err != nil {
        return nil, errors.New("kcdsa: invalid KCDSA parameter")
    }

    priv := &PrivateKey{
        PublicKey: PublicKey{
            Parameters: Parameters{
                P: params.P,
                Q: params.Q,
                G: params.G,

                GenParameters: GenerationParameters{
                    J:     params.J,
                    Seed:  params.Seed,
                    Count: params.Count,
                },
            },
            Y: new(big.Int),
        },
        X: x,
    }

    // 算出 Y 值
    GenerateY(priv.Y, priv.P, priv.Q, priv.G, x)

    if priv.Y.Sign() <= 0 || priv.P.Sign() <= 0 ||
        priv.Q.Sign() <= 0 || priv.G.Sign() <= 0 {
        return nil, errors.New("kcdsa: zero or negative KCDSA parameter")
    }

    return priv, nil
}

// PKCS8 解析私钥
func ParsePrivateKey(derBytes []byte) (key *PrivateKey, err error) {
    return defaultPKCS8Key.ParsePrivateKey(derBytes)
}
