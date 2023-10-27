package test_curue

import (
    "io"
    "errors"

    "github.com/deatil/go-cryptobin/x448"
    "github.com/deatil/go-cryptobin/ecdh"
)

var (
    x448PublicKeySize    = 56
    x448PrivateKeySize   = 56
    x448SharedSecretSize = 56
)

// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
func X448D() ecdh.Curve {
    return defaultX448
}

var defaultX448 = &x448Curve{}

type x448Curve struct{}

func (c *x448Curve) String() string {
    return "X448D"
}

func (c *x448Curve) GenerateKey(rand io.Reader) (*ecdh.PrivateKey, error) {
    _, key, err := x448.GenerateKey(rand)
    if err != nil {
        return nil, err
    }

    return c.NewPrivateKey(key.Seed())
}

func (c *x448Curve) NewPrivateKey(key []byte) (*ecdh.PrivateKey, error) {
    if len(key) != x448PrivateKeySize {
        return nil, errors.New("crypto/ecdh: invalid private key size")
    }

    return &ecdh.PrivateKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, key...),
    }, nil
}

func (c *x448Curve) PrivateKeyToPublicKey(key *ecdh.PrivateKey) *ecdh.PublicKey {
    if key.NamedCurve != c {
        panic("crypto/ecdh: internal error: converting the wrong key type")
    }

    x := x448.NewKeyFromSeed(key.Bytes()).Public()

    xx := x.(x448.PublicKey)

    k := &ecdh.PublicKey{
        NamedCurve: key.NamedCurve,
        KeyBytes:   xx[:],
    }

    return k
}

func (c *x448Curve) NewPublicKey(key []byte) (*ecdh.PublicKey, error) {
    if len(key) != x448PublicKeySize {
        return nil, errors.New("crypto/ecdh: invalid public key")
    }

    return &ecdh.PublicKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, key...),
    }, nil
}

func (c *x448Curve) ECDH(local *ecdh.PrivateKey, remote *ecdh.PublicKey) ([]byte, error) {
    out, err := x448.X448(local.KeyBytes, remote.KeyBytes)
    if err != nil {
        return nil, errors.New("crypto/ecdh: bad X448 remote ECDH input: " + err.Error())
    }

    if len(out) != x448SharedSecretSize {
        return nil, errors.New("crypto/ecdh: bad X448 remote ECDH input: low order point")
    }

    return out, nil
}
