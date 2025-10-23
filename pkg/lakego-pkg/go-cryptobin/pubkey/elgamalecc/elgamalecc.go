package elgamalecc

import (
    "io"
    "errors"
    "math/big"
    "crypto"
    "crypto/subtle"
    "crypto/elliptic"
    "encoding/asn1"
)

var (
    ErrPrivateKey = errors.New("go-cryptobin/elgamalecc: incorrect private key")
    ErrPublicKey  = errors.New("go-cryptobin/elgamalecc: incorrect public key")
)

var one = big.NewInt(1)

// bign PublicKey
type PublicKey struct {
    elliptic.Curve

    X, Y *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return bigIntEqual(pub.X, xx.X) &&
        bigIntEqual(pub.Y, xx.Y) &&
        pub.Curve == xx.Curve
}

// bign PrivateKey
type PrivateKey struct {
    PublicKey

    D *big.Int
}

// Equal reports whether pub and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return bigIntEqual(priv.D, xx.D) &&
        priv.PublicKey.Equal(&xx.PublicKey)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Decrypt decrypts ciphertext with priv.
func (priv *PrivateKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
    return DecryptASN1(priv, ciphertext)
}

// Generate the PrivateKey
func GenerateKey(random io.Reader, c elliptic.Curve) (*PrivateKey, error) {
    d, err := randFieldElement(random, c)
    if err != nil {
        return nil, err
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = d
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(d.Bytes())

    return priv, nil
}

// New a PrivateKey from privatekey data
func NewPrivateKey(curve elliptic.Curve, k []byte) (*PrivateKey, error) {
    d := new(big.Int).SetBytes(k)

    n := new(big.Int).Sub(curve.Params().N, one)
    if d.Cmp(n) >= 0 {
        return nil, errors.New("go-cryptobin/elgamalecc: privateKey's D is overflow")
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = d
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

    return priv, nil
}

// output PrivateKey data
func PrivateKeyTo(key *PrivateKey) []byte {
    privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
    return key.D.FillBytes(privateKey)
}

// New a PublicKey from publicKey data
func NewPublicKey(curve elliptic.Curve, k []byte) (*PublicKey, error) {
    x, y := elliptic.Unmarshal(curve, k)
    if x == nil || y == nil {
        return nil, errors.New("go-cryptobin/elgamalecc: incorrect public key")
    }

    pub := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    return pub, nil
}

// output PublicKey data
func PublicKeyTo(key *PublicKey) []byte {
    return elliptic.Marshal(key.Curve, key.X, key.Y)
}

// Encrypt with Elgamal
func Encrypt(random io.Reader, pub *PublicKey, data []byte) (C1x, C1y *big.Int, C2 *big.Int, err error) {
    x := new(big.Int).SetBytes(data)

    curve := pub.Curve

    r, err := randFieldElement(random, curve)
    if err != nil {
        err = errors.New("go-cryptobin/elgamalecc: invalid rand r")
        return
    }

    rYx, rYy := curve.ScalarMult(pub.X, pub.Y, r.Bytes())
    rGx, rGy := curve.ScalarBaseMult(r.Bytes())

    rYBytes := elliptic.Marshal(curve, rYx, rYy)

    rYval := new(big.Int).SetBytes(rYBytes)
    C2 = new(big.Int).Add(rYval, x)

    C1x, C1y = new(big.Int).Set(rGx), new(big.Int).Set(rGy)

    return
}

// Decrypt with Elgamal
func Decrypt(priv *PrivateKey, C1x, C1y *big.Int, C2 *big.Int) (plain []byte, err error) {
    curve := priv.Curve

    xCx, xCy := curve.ScalarMult(C1x, C1y, priv.D.Bytes())

    xCBytes := elliptic.Marshal(curve, xCx, xCy)

    xCval := new(big.Int).SetBytes(xCBytes)

    p := new(big.Int).Set(C2)
    p.Sub(p, xCval)

    plain = p.Bytes()

    return
}

type encryptedData struct {
    C1 []byte
    C2 *big.Int
}

// Encrypted and return asn.1 data
func EncryptASN1(random io.Reader, pub *PublicKey, data []byte) ([]byte, error) {
    if pub == nil {
        return nil, ErrPublicKey
    }

    C1x, C1y, C2, err := Encrypt(random, pub, data)
    if err != nil {
        return nil, err
    }

    C1 := elliptic.Marshal(pub.Curve, C1x, C1y)

    enc, err := asn1.Marshal(encryptedData{
        C1: C1,
        C2: C2,
    })
    if err != nil {
        return nil, err
    }

    return enc, nil
}

// Decrypt asn.1 marshal data
func DecryptASN1(priv *PrivateKey, data []byte) ([]byte, error) {
    if priv == nil {
        return nil, ErrPrivateKey
    }

    var enc encryptedData
    _, err := asn1.Unmarshal(data, &enc)
    if err != nil {
        return nil, err
    }

    C1x, C1y := elliptic.Unmarshal(priv.Curve, enc.C1)

    return Decrypt(priv, C1x, C1y, enc.C2)
}

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(rand io.Reader, c elliptic.Curve) (k *big.Int, err error) {
    for {
        N := c.Params().N
        b := make([]byte, (N.BitLen()+7)/8)
        if _, err = io.ReadFull(rand, b); err != nil {
            return
        }

        if excess := len(b)*8 - N.BitLen(); excess > 0 {
            b[0] >>= excess
        }

        k = new(big.Int).SetBytes(b)
        if k.Sign() != 0 && k.Cmp(N) < 0 {
            return
        }
    }
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
