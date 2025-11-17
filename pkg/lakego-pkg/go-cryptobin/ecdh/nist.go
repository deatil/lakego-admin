package ecdh

import (
    "io"
    "fmt"
    "crypto/ecdh"
)

type nistCurve struct{
    curve ecdh.Curve
}

func NewNistCurve(curve ecdh.Curve) Curve {
    return &nistCurve{curve}
}

func (c *nistCurve) String() string {
    return fmt.Sprintf("%s", c.curve)
}

func (c *nistCurve) GenerateKey(rand io.Reader) (*PrivateKey, error) {
    key, err := c.curve.GenerateKey(rand)
    if err != nil {
        return nil, err
    }

    return c.NewPrivateKey(key.Bytes())
}

func (c *nistCurve) NewPrivateKey(key []byte) (*PrivateKey, error) {
    x, err := c.curve.NewPrivateKey(key)
    if err != nil {
        return nil, err
    }

    xx := x.Bytes()

    return &PrivateKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, xx...),
    }, nil
}

func (c *nistCurve) PrivateKeyToPublicKey(key *PrivateKey) *PublicKey {
    if key.NamedCurve != c {
        panic("go-cryptobin/ecdh: internal error: converting the wrong key type")
    }

    x, err := c.curve.NewPrivateKey(key.Bytes())
    if err != nil {
        panic("go-cryptobin/ecdh: internal error: " + err.Error())
    }

    xx := x.PublicKey().Bytes()

    k := &PublicKey{
        NamedCurve: key.NamedCurve,
        KeyBytes:   xx[:],
    }

    return k
}

func (c *nistCurve) NewPublicKey(key []byte) (*PublicKey, error) {
    x, err := c.curve.NewPublicKey(key)
    if err != nil {
        return nil, err
    }

    xx := x.Bytes()

    return &PublicKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, xx...),
    }, nil
}

func (c *nistCurve) ECDH(local *PrivateKey, remote *PublicKey) ([]byte, error) {
    prikey, err := c.curve.NewPrivateKey(local.Bytes())
    if err != nil {
        return nil, err
    }

    pubkey, err := c.curve.NewPublicKey(remote.Bytes())
    if err != nil {
        return nil, err
    }

    return prikey.ECDH(pubkey)
}

// wrap go ecdh Curves.
func P256() Curve {
    return defaultP256
}
var defaultP256 = NewNistCurve(ecdh.P256())

func P384() Curve {
    return defaultP384
}
var defaultP384 = NewNistCurve(ecdh.P384())

func P521() Curve {
    return defaultP521
}
var defaultP521 = NewNistCurve(ecdh.P521())
