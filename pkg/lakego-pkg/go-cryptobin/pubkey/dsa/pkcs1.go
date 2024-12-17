package dsa

import (
    "fmt"
    "math/big"
    "crypto/dsa"
    "encoding/asn1"
)

var dsaPrivKeyVersion = 0

// PrivateKey
type dsaPrivateKey struct {
    Version int
    P       *big.Int
    Q       *big.Int
    G       *big.Int
    Y       *big.Int
    X       *big.Int
}

// PublicKey
type dsaPublicKey struct {
    P *big.Int
    Q *big.Int
    G *big.Int
    Y *big.Int
}

var (
    // default
    defaultPKCS1Key = NewPKCS1Key()

    // pkcs1 default
    MarshalPublicKey  = MarshalPKCS1PublicKey
    ParsePublicKey    = ParsePKCS1PublicKey

    MarshalPrivateKey = MarshalPKCS1PrivateKey
    ParsePrivateKey   = ParsePKCS1PrivateKey
)

/**
 * dsa pkcs1
 *
 * @create 2022-3-19
 * @author deatil
 */
type PKCS1Key struct {}

// NewPKCS1Key
func NewPKCS1Key() PKCS1Key {
    return PKCS1Key{}
}

// Marshal PKCS1 PublicKey
func (this PKCS1Key) MarshalPublicKey(key *dsa.PublicKey) ([]byte, error) {
    publicKey := dsaPublicKey{
        P: key.P,
        Q: key.Q,
        G: key.G,
        Y: key.Y,
    }

    return asn1.Marshal(publicKey)
}

// Marshal PKCS1 PublicKey
func MarshalPKCS1PublicKey(key *dsa.PublicKey) ([]byte, error) {
    return defaultPKCS1Key.MarshalPublicKey(key)
}

// Parse PKCS1 PublicKey
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

// Parse PKCS1 PublicKey
func ParsePKCS1PublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    return defaultPKCS1Key.ParsePublicKey(derBytes)
}

// Marshal PKCS1 PrivateKey
func (this PKCS1Key) MarshalPrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    version := dsaPrivKeyVersion

    // privateKey data
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

// Marshal PKCS1 PrivateKey
func MarshalPKCS1PrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    return defaultPKCS1Key.MarshalPrivateKey(key)
}

// Parse PKCS1 PrivateKey
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

// Parse PKCS1 PrivateKey
func ParsePKCS1PrivateKey(derBytes []byte) (*dsa.PrivateKey, error) {
    return defaultPKCS1Key.ParsePrivateKey(derBytes)
}
