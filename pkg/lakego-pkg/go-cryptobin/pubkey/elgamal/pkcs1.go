package elgamal

import (
    "fmt"
    "errors"
    "math/big"
    "encoding/asn1"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// elgamal PrivKey Version
var elgamalPrivKeyVersion = 0

// elgamal PrivateKey
type elgamalPrivateKey struct {
    Version int
    P       *big.Int
    G       *big.Int
    Q       *big.Int
    Y       *big.Int
    X       *big.Int
}

// elgamal PublicKey
type elgamalPublicKey struct {
    P *big.Int
    G *big.Int
    Q *big.Int
    Y *big.Int
}

var (
    // default PKCS1Key
    defaultPKCS1Key = NewPKCS1Key()

    // default is pkcs1 mode
    MarshalPublicKey  = MarshalPKCS1PublicKey
    ParsePublicKey    = ParsePKCS1PublicKey

    MarshalPrivateKey = MarshalPKCS1PrivateKey
    ParsePrivateKey   = ParsePKCS1PrivateKey
)

/**
 * elgamal pkcs1
 *
 * @create 2023-6-16
 * @author deatil
 */
type PKCS1Key struct {}

// NewPKCS1Key
func NewPKCS1Key() PKCS1Key {
    return PKCS1Key{}
}

// Marshal PKCS1 PublicKey
func (this PKCS1Key) MarshalPublicKey(key *PublicKey) ([]byte, error) {
    // q = (p - 1) / 2
    q := new(big.Int).Set(key.P)
    q.Sub(q, one)
    q.Div(q, two)

    publicKey := elgamalPublicKey{
        P: key.P,
        G: key.G,
        Q: q,
        Y: key.Y,
    }

    return asn1.Marshal(publicKey)
}

// Marshal PKCS1 PublicKey
func MarshalPKCS1PublicKey(key *PublicKey) ([]byte, error) {
    return defaultPKCS1Key.MarshalPublicKey(key)
}

// Parse PKCS1 PublicKey
func (this PKCS1Key) ParsePublicKey(der []byte) (*PublicKey, error) {
    publicKey := &PublicKey{
        G: new(big.Int),
        P: new(big.Int),
        Y: new(big.Int),
    }

    q := new(big.Int)

    keyDer := cryptobyte.String(der)
    if !keyDer.ReadASN1(&keyDer, cryptobyte_asn1.SEQUENCE) ||
        !keyDer.ReadASN1Integer(publicKey.P) ||
        !keyDer.ReadASN1Integer(publicKey.G) ||
        !keyDer.ReadASN1Integer(q) ||
        !keyDer.ReadASN1Integer(publicKey.Y) {
        return nil, errors.New("cryptobin/elgamal: invalid ElGamal public key")
    }

    return publicKey, nil
}

// Parse PKCS1 PublicKey
func ParsePKCS1PublicKey(derBytes []byte) (*PublicKey, error) {
    return defaultPKCS1Key.ParsePublicKey(derBytes)
}

// Marshal PKCS1 PrivateKey
func (this PKCS1Key) MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    // q = (p - 1) / 2
    q := new(big.Int).Set(key.P)
    q.Sub(q, one)
    q.Div(q, two)

    // privateKey data
    privateKey := elgamalPrivateKey{
        Version: elgamalPrivKeyVersion,
        P:       key.P,
        G:       key.G,
        Q:       q,
        Y:       key.Y,
        X:       key.X,
    }

    return asn1.Marshal(privateKey)
}

// Marshal PKCS1 PrivateKey
func MarshalPKCS1PrivateKey(key *PrivateKey) ([]byte, error) {
    return defaultPKCS1Key.MarshalPrivateKey(key)
}

// Parse PKCS1 PrivateKey
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
    q := new(big.Int)

    keyDer := cryptobyte.String(der)
    if !keyDer.ReadASN1(&keyDer, cryptobyte_asn1.SEQUENCE) ||
        !keyDer.ReadASN1Integer(&version) ||
        !keyDer.ReadASN1Integer(privateKey.P) ||
        !keyDer.ReadASN1Integer(privateKey.G) ||
        !keyDer.ReadASN1Integer(q) ||
        !keyDer.ReadASN1Integer(privateKey.Y) ||
        !keyDer.ReadASN1Integer(privateKey.X) {
        return nil, errors.New("cryptobin/elgamal: invalid ElGamal private key")
    }

    if version != elgamalPrivKeyVersion {
        return nil, fmt.Errorf("cryptobin/elgamal: unknown ElGamal private key version %d", version)
    }

    return privateKey, nil
}

// Parse PKCS1 PrivateKey
func ParsePKCS1PrivateKey(derBytes []byte) (*PrivateKey, error) {
    return defaultPKCS1Key.ParsePrivateKey(derBytes)
}
