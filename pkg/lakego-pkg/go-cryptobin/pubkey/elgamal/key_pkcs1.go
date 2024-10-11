package elgamal

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// 序列号
var elgamalPrivKeyVersion = 0

// 私钥
type elgamalPrivateKey struct {
    Version int
    P       *big.Int
    G       *big.Int
    Q       *big.Int `asn1:"optional"`
    Y       *big.Int
    X       *big.Int
}

// 公钥
type elgamalPublicKey struct {
    P *big.Int
    G *big.Int
    Q *big.Int `asn1:"optional"`
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
        P: key.P,
        G: key.G,
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
    publicKey := &PublicKey{
        G: new(big.Int),
        P: new(big.Int),
        Y: new(big.Int),
    }

    var q big.Int
    defaultQ := big.NewInt(0)

    keyDer := cryptobyte.String(der)
    if !keyDer.ReadASN1(&keyDer, cryptobyte_asn1.SEQUENCE) ||
        !keyDer.ReadASN1Integer(publicKey.P) ||
        !keyDer.ReadASN1Integer(publicKey.G) ||
        !keyDer.ReadOptionalASN1Integer(&q, 0xa0, defaultQ) ||
        !keyDer.ReadASN1Integer(publicKey.Y) {
        return nil, errors.New("cryptobin/elgamal: invalid EIGamal public key")
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
        P:       key.P,
        G:       key.G,
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
    privateKey := &PrivateKey{
        PublicKey: PublicKey{
            G: new(big.Int),
            P: new(big.Int),
            Y: new(big.Int),
        },
        X: new(big.Int),
    }

    var version int
    var q big.Int
    defaultQ := big.NewInt(0)

    keyDer := cryptobyte.String(der)
    if !keyDer.ReadASN1(&keyDer, cryptobyte_asn1.SEQUENCE) ||
        !keyDer.ReadASN1Integer(&version) ||
        !keyDer.ReadASN1Integer(privateKey.P) ||
        !keyDer.ReadASN1Integer(privateKey.G) ||
        !keyDer.ReadOptionalASN1Integer(&q, 0xa0, defaultQ) ||
        !keyDer.ReadASN1Integer(privateKey.Y) ||
        !keyDer.ReadASN1Integer(privateKey.X) {
        return nil, errors.New("cryptobin/elgamal: invalid EIGamal private key")
    }

    if version != elgamalPrivKeyVersion {
        return nil, fmt.Errorf("cryptobin/elgamal: unknown EIGamal private key version %d", version)
    }

    return privateKey, nil
}

// 解析私钥
func ParsePKCS1PrivateKey(derBytes []byte) (*PrivateKey, error) {
    return defaultPKCS1Key.ParsePrivateKey(derBytes)
}
