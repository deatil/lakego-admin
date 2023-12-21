package elgamal

import (
    "fmt"
    "math/big"
    "encoding/asn1"
)

// 序列号
var elgamalPrivKeyVersion = 0

// 私钥
type elgamalPrivateKey struct {
    Version int
    G       *big.Int
    P       *big.Int
    Y       *big.Int
    X       *big.Int
}

// 公钥
type elgamalPublicKey struct {
    G *big.Int
    P *big.Int
    Y *big.Int
}

var (
    // 默认
    defaultPKCS1Key = NewPKCS1Key()

    // 默认为 pkcs1 模式
    MarshalPublicKey  = MarshalPKCS1PublicKey
    ParsePublicKey    = ParsePKCS1PublicKey

    MarshalPrivateKey = MarshalPKCS1PrivateKey
    ParsePrivateKey   = ParsePKCS1PrivateKey
)

/**
 * elgamal pkcs1 密钥
 *
 * @create 2023-6-16
 * @author deatil
 */
type PKCS1Key struct {}

// 构造函数
func NewPKCS1Key() PKCS1Key {
    return PKCS1Key{}
}

// 包装公钥
func (this PKCS1Key) MarshalPublicKey(key *PublicKey) ([]byte, error) {
    publicKey := elgamalPublicKey{
        G: key.G,
        P: key.P,
        Y: key.Y,
    }

    return asn1.Marshal(publicKey)
}

// 包装公钥
func MarshalPKCS1PublicKey(key *PublicKey) ([]byte, error) {
    return defaultPKCS1Key.MarshalPublicKey(key)
}

// 解析公钥
func (this PKCS1Key) ParsePublicKey(der []byte) (*PublicKey, error) {
    var key elgamalPublicKey
    rest, err := asn1.Unmarshal(der, &key)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    publicKey := &PublicKey{
        G: key.G,
        P: key.P,
        Y: key.Y,
    }

    return publicKey, nil
}

// 解析公钥
func ParsePKCS1PublicKey(derBytes []byte) (*PublicKey, error) {
    return defaultPKCS1Key.ParsePublicKey(derBytes)
}

// ====================

// 包装私钥
func (this PKCS1Key) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    // 版本号
    version := elgamalPrivKeyVersion

    // 构造私钥信息
    privateKey := elgamalPrivateKey{
        Version: version,
        G:       key.G,
        P:       key.P,
        Y:       key.Y,
        X:       key.X,
    }

    return asn1.Marshal(privateKey)
}

// 包装私钥
func MarshalPKCS1PrivateKey(key *PrivateKey) ([]byte, error) {
    return defaultPKCS1Key.MarshalPrivateKey(key)
}

// 解析私钥
func (this PKCS1Key) ParsePrivateKey(der []byte) (*PrivateKey, error) {
    var key elgamalPrivateKey
    rest, err := asn1.Unmarshal(der, &key)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    if key.Version != elgamalPrivKeyVersion {
        return nil, fmt.Errorf("EIGamal: unknown EIGamal private key version %d", key.Version)
    }

    privateKey := &PrivateKey{
        PublicKey: PublicKey{
            G: key.G,
            P: key.P,
            Y: key.Y,
        },
        X: key.X,
    }

    return privateKey, nil
}

// 解析私钥
func ParsePKCS1PrivateKey(derBytes []byte) (*PrivateKey, error) {
    return defaultPKCS1Key.ParsePrivateKey(derBytes)
}
