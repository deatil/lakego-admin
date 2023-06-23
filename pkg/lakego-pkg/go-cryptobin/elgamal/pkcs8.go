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
    // elgamal 公钥 oid
    oidPublicKeyEIGamal = asn1.ObjectIdentifier{1, 3, 14, 7, 2, 1, 1}
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

var (
    defaultPKCS8Key = NewPKCS8Key()
)

/**
 * elgamal pkcs8 密钥
 *
 * @create 2023-6-16
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

    publicKeyAlgorithm.Algorithm = oidPublicKeyEIGamal
    publicKeyAlgorithm.Parameters = asn1.NullRawValue

    var p cryptobyte.Builder
    p.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
        addASN1IntBytes(b, key.G.Bytes())
        addASN1IntBytes(b, key.P.Bytes())
        addASN1IntBytes(b, key.Y.Bytes())
    })

    publicKeyBytes, err = p.Bytes()
    if err != nil {
        return nil, errors.New("elgamal: failed to builder PrivateKey: " + err.Error())
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
func MarshalPKCS8PublicKey(pub *PublicKey) ([]byte, error) {
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

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyEIGamal)
    if !algoEq {
        return nil, errors.New("elgamal: unknown public key algorithm")
    }

    // 解析
    keyData := &pki

    pub := &PublicKey{
        G: new(big.Int),
        P: new(big.Int),
        Y: new(big.Int),
    }

    pubDer := cryptobyte.String(keyData.PublicKey.RightAlign())
    if !pubDer.ReadASN1(&pubDer, cryptobyte_asn1.SEQUENCE) ||
        !pubDer.ReadASN1Integer(pub.G) ||
        !pubDer.ReadASN1Integer(pub.P) ||
        !pubDer.ReadASN1Integer(pub.Y) {
        return nil, errors.New("x509: invalid EIGamal public key")
    }

    if pub.Y.Sign() <= 0 ||
        pub.G.Sign() <= 0 ||
        pub.P.Sign() <= 0 {
        return nil, errors.New("x509: zero or negative EIGamal parameter")
    }

    return pub, nil
}

// PKCS8 解析公钥
func ParsePKCS8PublicKey(derBytes []byte) (*PublicKey, error) {
    return defaultPKCS8Key.ParsePublicKey(derBytes)
}

// ====================

// PKCS8 包装私钥
func (this PKCS8Key) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyEIGamal,
        Parameters: asn1.NullRawValue,
    }

    var p cryptobyte.Builder
    p.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
        addASN1IntBytes(b, key.G.Bytes())
        addASN1IntBytes(b, key.P.Bytes())
        addASN1IntBytes(b, key.X.Bytes())
    })

    privateKeyBytes, err := p.Bytes()
    if err != nil {
        return nil, errors.New("elgamal: failed to builder PrivateKey: " + err.Error())
    }

    privKey.PrivateKey = privateKeyBytes

    return asn1.Marshal(privKey)
}

// PKCS8 包装私钥
func MarshalPKCS8PrivateKey(key *PrivateKey) ([]byte, error) {
    return defaultPKCS8Key.MarshalPrivateKey(key)
}

// PKCS8 解析私钥
func (this PKCS8Key) ParsePrivateKey(der []byte) (key *PrivateKey, err error) {
    var privKey pkcs8
    _, err = asn1.Unmarshal(der, &privKey)
    if err != nil {
        return nil, err
    }

    if !privKey.Algo.Algorithm.Equal(oidPublicKeyEIGamal) {
        return nil, fmt.Errorf("elgamal: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }

    priv := &PrivateKey{
        PublicKey: PublicKey{
            G: new(big.Int),
            P: new(big.Int),
            Y: new(big.Int),
        },
        X: new(big.Int),
    }

    // 找出 g,p,x 数据
    priDer := cryptobyte.String(string(privKey.PrivateKey))
    if !priDer.ReadASN1(&priDer, cryptobyte_asn1.SEQUENCE) ||
        !priDer.ReadASN1Integer(priv.G) ||
        !priDer.ReadASN1Integer(priv.P) ||
        !priDer.ReadASN1Integer(priv.X) {
        return nil, errors.New("x509: invalid EIGamal private key")
    }

    if priv.X.Sign() <= 0 ||
        priv.G.Sign() <= 0 ||
        priv.P.Sign() <= 0 {
        return nil, errors.New("x509: zero or negative EIGamal parameter")
    }

    // 算出 Y 值
    priv.Y.Exp(priv.G, priv.X, priv.P)

    if priv.Y.Sign() <= 0 || priv.G.Sign() <= 0 ||
        priv.P.Sign() <= 0 || priv.X.Sign() <= 0 {
        return nil, errors.New("x509: zero or negative EIGamal parameter")
    }

    return priv, nil
}

// PKCS8 解析私钥
func ParsePKCS8PrivateKey(derBytes []byte) (key *PrivateKey, err error) {
    return defaultPKCS8Key.ParsePrivateKey(derBytes)
}
