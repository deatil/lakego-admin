package dh

import (
    "fmt"
    "errors"
    "math/big"
    "crypto/x509/pkix"
    "encoding/asn1"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
    // DH 公钥 oid
    oidPublicKeyDH = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1}
)

// dh Parameters
type dhAlgorithmParameters struct {
    P, G *big.Int
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

// 包装公钥
func MarshalPublicKey(key *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    // 创建数据
    paramBytes, err := asn1.Marshal(dhAlgorithmParameters{
        P: key.P,
        G: key.G,
    })
    if err != nil {
        return nil, errors.New("dsa: failed to marshal algo param: " + err.Error())
    }

    publicKeyAlgorithm.Algorithm = oidPublicKeyDH
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    var yInt cryptobyte.Builder
    yInt.AddASN1BigInt(key.Y)

    publicKeyBytes, err = yInt.Bytes()
    if err != nil {
        return nil, errors.New("DH: failed to builder PrivateKey: " + err.Error())
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

// 解析公钥
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

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyDH)
    if !algoEq {
        err = errors.New("DH: unknown public key algorithm")
        return
    }

    // 解析
    keyData := &pki

    der := cryptobyte.String(keyData.PublicKey.RightAlign())

    y := new(big.Int)
    if !der.ReadASN1Integer(y) {
        err = errors.New("DH: invalid DSA public key")
        return
    }

    pub = &PublicKey{
        Y: y,
        Parameters: Parameters{
            P: new(big.Int),
            G: new(big.Int),
        },
    }

    paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
    if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
        !paramsDer.ReadASN1Integer(pub.P) ||
        !paramsDer.ReadASN1Integer(pub.G) {
        err = errors.New("DH: invalid DSA parameters")
        return
    }

    if pub.Y.Sign() <= 0 ||
        pub.P.Sign() <= 0 ||
        pub.G.Sign() <= 0 {
        err = errors.New("DH: zero or negative DSA parameter")
        return
    }

    return
}

// ====================

// 包装私钥
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    // 创建数据
    paramBytes, err := asn1.Marshal(dhAlgorithmParameters{
        P: key.P,
        G: key.G,
    })
    if err != nil {
        return nil, errors.New("dsa: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyDH,
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

// 解析私钥
func ParsePrivateKey(derBytes []byte) (*PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, errors.New("DH: " + err.Error())
    }

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeyDH):
            der := cryptobyte.String(string(privKey.PrivateKey))

            x := new(big.Int)
            if !der.ReadASN1Integer(x) {
                err = errors.New("DH: invalid DH public key")
                return nil, err
            }

            priv := &PrivateKey{
                PublicKey: PublicKey{
                    Parameters: Parameters{
                        P: new(big.Int),
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
                !paramsDer.ReadASN1Integer(priv.G) {
                err = errors.New("DH: invalid DSA parameters")
                return nil, err
            }

            // 算出 Y 值
            priv.Y.Exp(priv.G, x, priv.P)

            if priv.Y.Sign() <= 0 ||
                priv.P.Sign() <= 0 ||
                priv.G.Sign() <= 0 {
                err = errors.New("DH: zero or negative DSA parameter")
                return nil, err
            }

            return priv, nil

        default:
            err = fmt.Errorf("DH: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
            return nil, err
    }
}
