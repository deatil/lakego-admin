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
    // dsa 公钥 oid
    oidPublicKeyDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
)

// dsa Parameters
type dsaAlgorithmParameters struct {
    P, Q, G *big.Int
}

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

/**
 * dsa pkcs8 密钥
 *
 * @create 2022-3-19
 * @author deatil
 */
type PKCS8Key struct {}

// PKCS8 包装公钥
func (this PKCS8Key) MarshalPKCS8PublicKey(key *dsa.PublicKey) ([]byte, error) {
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

// PKCS8 解析公钥
func (this PKCS8Key) ParsePKCS8PublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
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

    // 解析
    keyData := &pki

    der := cryptobyte.String(keyData.PublicKey.RightAlign())

    y := new(big.Int)
    if !der.ReadASN1Integer(y) {
        return nil, errors.New("x509: invalid DSA public key")
    }

    pub := &dsa.PublicKey{
        Y: y,
        Parameters: dsa.Parameters{
            P: new(big.Int),
            Q: new(big.Int),
            G: new(big.Int),
        },
    }

    paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
    if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
        !paramsDer.ReadASN1Integer(pub.P) ||
        !paramsDer.ReadASN1Integer(pub.Q) ||
        !paramsDer.ReadASN1Integer(pub.G) {
        return nil, errors.New("x509: invalid DSA parameters")
    }

    if pub.Y.Sign() <= 0 || pub.P.Sign() <= 0 ||
        pub.Q.Sign() <= 0 || pub.G.Sign() <= 0 {
        return nil, errors.New("x509: zero or negative DSA parameter")
    }

    return pub, nil
}

// ====================

// PKCS8 包装私钥
func (this PKCS8Key) MarshalPKCS8PrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    var privKey pkcs8

    // 创建数据
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

// PKCS8 解析私钥
func (this PKCS8Key) ParsePKCS8PrivateKey(derBytes []byte) (key *dsa.PrivateKey, err error) {
    var privKey pkcs8
    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeyDSA):
            der := cryptobyte.String(string(privKey.PrivateKey))

            x := new(big.Int)
            if !der.ReadASN1Integer(x) {
                return nil, errors.New("x509: invalid DSA public key")
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

            // 找出 p,q,g 数据
            paramsDer := cryptobyte.String(privKey.Algo.Parameters.FullBytes)
            if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
                !paramsDer.ReadASN1Integer(priv.P) ||
                !paramsDer.ReadASN1Integer(priv.Q) ||
                !paramsDer.ReadASN1Integer(priv.G) {
                return nil, errors.New("x509: invalid DSA parameters")
            }

            // 算出 Y 值
            priv.Y.Exp(priv.G, x, priv.P)

            if priv.Y.Sign() <= 0 || priv.P.Sign() <= 0 ||
                priv.Q.Sign() <= 0 || priv.G.Sign() <= 0 {
                return nil, errors.New("x509: zero or negative DSA parameter")
            }

            return priv, nil

        default:
            return nil, fmt.Errorf("dsa: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }
}

// 构造函数
func NewPKCS8Key() PKCS8Key {
    return PKCS8Key{}
}
