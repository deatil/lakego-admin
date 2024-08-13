package eckcdsa

import (
    "io"
    "hash"
    "errors"
    "math/big"
    "crypto"
    "crypto/subtle"
    "crypto/elliptic"

    "golang.org/x/crypto/cryptobyte"
    "golang.org/x/crypto/cryptobyte/asn1"
)

// see TTAK.KO-12.0015/R3

var (
    ErrParametersNotSetUp = errors.New("go-cryptobin/eckcdsa: parameters not set up before generating key")
    ErrInvalidK           = errors.New("go-cryptobin/eckcdsa: use another K")
    ErrInvalidInteger     = errors.New("go-cryptobin/eckcdsa: invalid integer")
    ErrInvalidASN1        = errors.New("go-cryptobin/eckcdsa: invalid ASN.1")
)

var (
    one = big.NewInt(1)
    two = big.NewInt(2)
)

// SignerOpts contains options for creating and verifying EC-KCDSA signatures.
type SignerOpts struct {
    Hash crypto.Hash
}

// HashFunc returns opts.Hash
func (opts *SignerOpts) HashFunc() crypto.Hash {
    return opts.Hash
}

// ec-kcdsa PublicKey
type PublicKey struct {
    elliptic.Curve

    X *big.Int
    Y *big.Int
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

// Verify asn.1 marshal data
func (pub *PublicKey) Verify(msg, sign []byte, opts crypto.SignerOpts) bool {
    return Verify(pub, opts.HashFunc().New(), msg, sign)
}

// ec-kcdsa PrivateKey
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

// crypto.Signer
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    return Sign(rand, priv, opts.HashFunc().New(), digest)
}

// Generate the paramters
func GenerateKey(c elliptic.Curve, randReader io.Reader) (*PrivateKey, error) {
    d, err := randFieldElement(randReader, c)
    if err != nil {
        return nil, err
    }

    dInv := fermatInverse(d, c.Params().N)

    priv := new(PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = d
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(dInv.Bytes())

    return priv, nil
}

// Sign data returns the ASN.1 encoded signature.
func Sign(rand io.Reader, priv *PrivateKey, h hash.Hash, data []byte) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, h, data)
    if err != nil {
        return nil, err
    }

    return encodeSignature(r.Bytes(), s.Bytes())
}

// Verify verifies the ASN.1 encoded signature, sig, M, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func Verify(pub *PublicKey, h hash.Hash, data, sig []byte) bool {
    r, s, err := parseSignature(sig)
    if err != nil {
        return false
    }

    return VerifyWithRS(
        pub,
        h,
        data,
        new(big.Int).SetBytes(r),
        new(big.Int).SetBytes(s),
    )
}

func encodeSignature(r, s []byte) ([]byte, error) {
    var b cryptobyte.Builder
    b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
        addASN1IntBytes(b, r)
        addASN1IntBytes(b, s)
    })

    return b.Bytes()
}

func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
    for len(bytes) > 0 && bytes[0] == 0 {
        bytes = bytes[1:]
    }

    if len(bytes) == 0 {
        b.SetError(ErrInvalidInteger)
        return
    }

    b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
        if bytes[0]&0x80 != 0 {
            c.AddUint8(0)
        }
        c.AddBytes(bytes)
    })
}

func parseSignature(sig []byte) (r, s []byte, err error) {
    var inner cryptobyte.String

    input := cryptobyte.String(sig)

    if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
        !input.Empty() ||
        !inner.ReadASN1Integer(&r) ||
        !inner.ReadASN1Integer(&s) ||
        !inner.Empty() {
        return nil, nil, ErrInvalidASN1
    }

    return r, s, nil
}

// Sign data
func SignToRS(rand io.Reader, priv *PrivateKey, h hash.Hash, msg []byte) (r, s *big.Int, err error) {
    var k *big.Int

    for {
        k, err = randFieldElement(rand, priv.Curve)
        if err != nil {
            return
        }

        r, s, err = signUsingK(k, priv, h, msg)
        if err == ErrInvalidK {
            continue
        }

        return
    }
}

func signUsingK(k *big.Int, priv *PrivateKey, h hash.Hash, msg []byte) (r, s *big.Int, err error) {
    if priv == nil || priv.Curve == nil || priv.X == nil || priv.Y == nil || priv.D == nil || !priv.Curve.IsOnCurve(priv.X, priv.Y) {
        return nil, nil, ErrParametersNotSetUp
    }

    curve := priv.Curve
    curveParams := curve.Params()
    n := curveParams.N

    w := (n.BitLen() + 7) / 8
    K := (curveParams.BitSize + 7) / 8 // curve size
    Lh := h.Size()
    L := h.BlockSize()
    d := priv.D
    xQ := priv.X
    yQ := priv.Y

    var two_8w *big.Int
    if Lh > w {
        two_8w = big.NewInt(256)
        two_8w.Exp(two_8w, big.NewInt(int64(w)), nil)
    }

    // 2: kG = (x1, y1)
    x1, _ := curve.ScalarBaseMult(k.Bytes())
    x1Bytes := padLeft(x1.Bytes(), K)

    // 3: r ← Hash(x1)
    h.Reset()
    h.Write(x1Bytes)
    rBytes := h.Sum(nil)
    r = new(big.Int).SetBytes(rBytes)
    if Lh > w {
        r = r.Mod(r, two_8w)
    }

    // 4: cQ ← MSB(xQ ‖ yQ, L)
    cQ := append(
        padLeft(xQ.Bytes(), K),
        padLeft(yQ.Bytes(), K)...,
    )
    cQ = padRight(cQ, L)

    // 5: v ← Hash(cQ ‖ M)
    h.Reset()
    h.Write(cQ)
    h.Write(msg)
    vBytes := h.Sum(nil)
    v := new(big.Int).SetBytes(vBytes)
    if Lh > w {
        v = v.Mod(v, two_8w)
    }

    // 6: e ← (r ⊕ v) mod n
    e := new(big.Int)
    e.Mod(e.Xor(r, v), n)

    // 7: t ← d(k - e) mod n
    t := new(big.Int)
    t.Mod(t.Sub(k, e), n)
    t.Mod(t.Mul(d, t), n)

    if t.Sign() <= 0 {
        return nil, nil, ErrInvalidK
    }

    s = t

    return r, s, nil
}

func VerifyWithRS(pub *PublicKey, h hash.Hash, data []byte, r, s *big.Int) bool {
    if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return false
    }
    if r.Sign() <= 0 || s.Sign() <= 0 {
        return false
    }

    curve := pub.Curve
    curveParams := pub.Curve.Params()
    n := curveParams.N

    w := (n.BitLen() + 7) / 8
    K := (curveParams.BitSize + 7) / 8 // curve size
    Lh := h.Size()
    L := h.BlockSize()
    xQ := pub.X
    yQ := pub.Y

    t := s

    var two_8w *big.Int
    if Lh > w {
        two_8w = big.NewInt(256)
        two_8w.Exp(two_8w, big.NewInt(int64(w)), nil)
    }

    if r.Sign() <= 0 {
        return false
    }
    if Lh > w {
        if (r.BitLen()+7)/8 > w {
            return false
        }
    } else {
        if (r.BitLen()+7)/8 > Lh {
            return false
        }
    }
    if t.Sign() <= 0 || t.Cmp(n) >= 0 {
        return false
    }

    // 2: cQ ← MSB(xQ ‖ yQ, L)
    cQ := append(
        padLeft(xQ.Bytes(), K),
        padLeft(yQ.Bytes(), K)...,
    )
    cQ = padRight(cQ, L)

    // 3: v′ ← Hash(cQ ‖ M′)
    h.Reset()
    h.Write(cQ)
    h.Write(data)
    vBytes := h.Sum(nil)
    v := new(big.Int).SetBytes(vBytes)
    if Lh > w {
        v.Mod(v, two_8w)
    }

    // 4: e′ ← (r′ ⊕ v′) mod n
    e := new(big.Int).Xor(r, v)
    e.Mod(e, n)

    // 5: (x2, y2) ← t′Q + e′G
    x21, y21 := curve.ScalarMult(pub.X, pub.Y, t.Bytes())
    x22, y22 := curve.ScalarBaseMult(e.Bytes())
    x2, _ := curve.Add(x21, y21, x22, y22)
    x2Bytes := padLeft(x2.Bytes(), K)

    // 6: Hash(x2′) = r′
    h.Reset()
    h.Write(x2Bytes)
    rBytes := h.Sum(nil)
    r2 := new(big.Int).SetBytes(rBytes)
    if Lh > w {
        r2.Mod(r2, two_8w)
    }

    return r.Cmp(r2) == 0
}

func padLeft(arr []byte, l int) []byte {
    if len(arr) >= l {
        return arr[:l]
    }

    n := make([]byte, l)
    copy(n[l-len(arr):], arr)

    return n
}

func padRight(arr []byte, l int) []byte {
    if len(arr) >= l {
        return arr[:l]
    }

    n := make([]byte, l)
    copy(n, arr)

    return n
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

func XY(D *big.Int, c elliptic.Curve) (X, Y *big.Int) {
    dInv := fermatInverse(D, c.Params().N)
    return c.ScalarBaseMult(dInv.Bytes())
}

func fermatInverse(a, N *big.Int) *big.Int {
    two := big.NewInt(2)
    nMinus2 := new(big.Int).Sub(N, two)
    return new(big.Int).Exp(a, nMinus2, N)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
