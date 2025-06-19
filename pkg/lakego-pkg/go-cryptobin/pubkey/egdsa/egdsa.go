package egdsa

import (
    "io"
    "time"
    "errors"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
    "encoding/asn1"
    math_rand "math/rand"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)
var three = big.NewInt(3)

// egdsa PublicKey
type PublicKey struct {
    P, G, Y *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return bigIntEqual(pub.G, xx.G) &&
        bigIntEqual(pub.P, xx.P) &&
        bigIntEqual(pub.Y, xx.Y)
}

// Verify verifies signature over the given hash and signature values (r & s).
// It returns true as a boolean value if signature is verify correctly. Otherwise
// it returns false along with error message.
func (pub *PublicKey) Verify(hash, sig []byte) (bool, error) {
    return VerifyASN1(pub, hash, sig)
}

// egdsa PrivateKey
type PrivateKey struct {
    PublicKey

    X *big.Int
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.PublicKey.Equal(&xx.PublicKey) &&
        bigIntEqual(priv.X, xx.X)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Signature generates signature over the given hash. It returns signature
// value consisting of two parts "r" and "s" as byte arrays.
func (priv *PrivateKey) Sign(random io.Reader, hash []byte, opts crypto.SignerOpts) (signature []byte, err error) {
    return SignASN1(random, priv, hash)
}

// GenerateKey generates egdsa private key according
// to given bit size and probability.
func GenerateKey(random io.Reader, bitsize, probability int) (*PrivateKey, error) {
    p, q, g, err := generatePQZp(random, bitsize, probability)
    if err != nil {
        return nil, err
    }

    randSource := math_rand.New(math_rand.NewSource(time.Now().UnixNano()))
    // choose random integer x from {1...(q-1)}
    priv := new(big.Int).Rand(randSource, new(big.Int).Sub(q, one))
    // y = g^p mod p
    y := new(big.Int).Exp(g, priv, p)

    return &PrivateKey{
        PublicKey: PublicKey{
            P: p,
            G: g,
            Y: y,
        },
        X: priv,
    }, nil
}

// r and s data
type egdsaSignature struct {
    R, S *big.Int
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
    r, s, err := Sign(rand, priv, hash)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(egdsaSignature{
        R: r,
        S: s,
    })
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *PublicKey, hash, sig []byte) (bool, error) {
    var sign egdsaSignature
    _, err := asn1.Unmarshal(sig, &sign)
    if err != nil {
        return false, err
    }

    return Verify(pub, hash, sign.R, sign.S)
}

// Sign hash
func Sign(random io.Reader, priv *PrivateKey, hash []byte) (*big.Int, *big.Int, error) {
    k := new(big.Int)
    gcd := new(big.Int)

    var err error

    // gcd(k,(p-1)) should be equal to 1.
    for {
        k, err = rand.Int(random, priv.P)
        if err != nil {
            return nil, nil, err
        }

        k.Sub(k, three)
        k.Add(k, two)

        gcd = gcd.GCD(nil, nil, k, new(big.Int).Sub(priv.P, one))
        if gcd.Cmp(one) == 0 {
            break
        }
    }

    // m = m % (p - THREE) + TWO
    m := new(big.Int).SetBytes(hash)
    m.Mod(m, new(big.Int).Sub(priv.P, three))
    m.Add(m, two)

    // r = g^k mod p
    r := new(big.Int).Exp(priv.G, k, priv.P)
    // xr = x * r - p * (p - ONE)
    xr := new(big.Int).Sub(
        new(big.Int).Mul(r, priv.X),
        new(big.Int).Mul(
            priv.P,
            new(big.Int).Sub(priv.P, one),
        ),
    )

    // hmxr = [H(m)-xr]
    hmxr := new(big.Int).Sub(m, xr)
    hmxr.Mod(hmxr, new(big.Int).Sub(priv.P, one))

    // k = k^(-1)
    k = k.ModInverse(k, new(big.Int).Sub(priv.P, one))

    // s = [H(m) -xr]k^(-1) mod (p-1)
    s := new(big.Int).Mod(
        new(big.Int).Mul(hmxr, k),
        new(big.Int).Sub(priv.P, one),
    )

    return r, s, nil
}

// Verify hash
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) (bool, error) {
    // verify that 0 < r < p
    signr := new(big.Int).Set(r)
    if signr.Cmp(zero) == -1 {
        return false, errors.New("egdsa: r is smaller than zero")
    } else if signr.Cmp(pub.P) == +1 {
        return false, errors.New("egdsa: r is larger than public key p")
    }

    signs := new(big.Int).Set(s)
    if signs.Cmp(zero) == -1 {
        return false, errors.New("egdsa: s is smaller than zero")
    } else if signs.Cmp(new(big.Int).Sub(pub.P, one)) == +1 {
        return false, errors.New("egdsa: s is larger than public key p")
    }

    // m = m % (p - THREE) + TWO
    m := new(big.Int).SetBytes(hash)
    m.Mod(m, new(big.Int).Sub(pub.P, three))
    m.Add(m, two)

    // ghashm = g^[H(m)] mod p
    ghashm := new(big.Int).Exp(pub.G, m, pub.P)

    // y^r * r*s mod p
    YrRs := new(big.Int).Mod(
        new(big.Int).Mul(
            new(big.Int).Exp(pub.Y, signr, pub.P),
            new(big.Int).Exp(signr, signs, pub.P),
        ),
        pub.P,
    )

    // g^H(m) y^r * r*s mod p
    if ghashm.Cmp(YrRs) == 0 {
        return true, nil // signature is verified
    }

    return false, errors.New("egdsa: signature is not verified")
}

// Gen emit <p,q,g>.
func generatePQZp(random io.Reader, n, probability int) (*big.Int, *big.Int, *big.Int, error) {
    for {
        q, err := rand.Prime(random, n-1)
        if err != nil {
            return nil, nil, nil, err
        }

        t := new(big.Int).Mul(q, two)
        p := new(big.Int).Add(t, one)
        if p.ProbablyPrime(probability) {
            for {
                g, err := rand.Int(random, p)
                if err != nil {
                    return nil, nil, nil, err
                }

                b := new(big.Int).Exp(g, two, p)
                if b.Cmp(one) == 0 {
                    continue
                }

                b = new(big.Int).Exp(g, q, p)
                if b.Cmp(one) == 0 {
                    return p, q, g, nil
                }
            }
        }
    }

    return nil, nil, nil, errors.New("egdsa: generate key fail")
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
