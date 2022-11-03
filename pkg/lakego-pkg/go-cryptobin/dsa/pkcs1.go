package dsa

import (
    "fmt"
    "math/big"
    "crypto/dsa"
    "encoding/asn1"
)

// 序列号
var dsaPrivKeyVersion = 0

// 私钥
type dsaPrivateKey struct {
    Version int
    P       *big.Int
    Q       *big.Int
    G       *big.Int
    Y       *big.Int
    X       *big.Int
}

// 公钥
type dsaPublicKey struct {
    P *big.Int
    Q *big.Int
    G *big.Int
    Y *big.Int
}

/**
 * dsa pkcs1 密钥
 *
 * @create 2022-3-19
 * @author deatil
 */
type PKCS1Key struct {}

// 包装公钥
func (this PKCS1Key) MarshalPublicKey(key *dsa.PublicKey) ([]byte, error) {
    publicKey := dsaPublicKey{
        P: key.P,
        Q: key.Q,
        G: key.G,
        Y: key.Y,
    }

    return asn1.Marshal(publicKey)
}

// 解析公钥
func (this PKCS1Key) ParsePublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    var key dsaPublicKey
    rest, err := asn1.Unmarshal(derBytes, &key)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    publicKey := &dsa.PublicKey{
        Parameters: dsa.Parameters{
            P: key.P,
            Q: key.Q,
            G: key.G,
        },
        Y: key.Y,
    }

    return publicKey, nil
}

// ====================

// 包装私钥
func (this PKCS1Key) MarshalPrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    // 版本号
    version := dsaPrivKeyVersion

    // 构造私钥信息
    privateKey := dsaPrivateKey{
        Version: version,
        P:       key.P,
        Q:       key.Q,
        G:       key.G,
        Y:       key.Y,
        X:       key.X,
    }

    return asn1.Marshal(privateKey)
}

// 解析私钥
func (this PKCS1Key) ParsePrivateKey(derBytes []byte) (*dsa.PrivateKey, error) {
    var key dsaPrivateKey
    rest, err := asn1.Unmarshal(derBytes, &key)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    if key.Version != dsaPrivKeyVersion {
        return nil, fmt.Errorf("DSA: unknown DSA private key version %d", key.Version)
    }

    privateKey := &dsa.PrivateKey{
        PublicKey: dsa.PublicKey{
            Parameters: dsa.Parameters{
                P: key.P,
                Q: key.Q,
                G: key.G,
            },
            Y: key.Y,
        },
        X: key.X,
    }

    return privateKey, nil
}

// 构造函数
func NewPKCS1Key() PKCS1Key {
    return PKCS1Key{}
}
