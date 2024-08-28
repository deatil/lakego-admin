package ecgdsa

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

var (
    ErrParametersNotSetUp = errors.New("go-cryptobin/ecgdsa: parameters not set up before generating key")
    ErrInvalidASN1        = errors.New("go-cryptobin/ecgdsa: invalid ASN.1")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/ecgdsa: opts must be *SignerOpts")
)

var (
    zero = big.NewInt(0)
)

type Hasher = func() hash.Hash

// SignerOpts contains options for creating and verifying EC-GDSA signatures.
type SignerOpts struct {
    Hash Hasher
}

// HashFunc returns opts.Hash
func (opts *SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// GetHash returns func() hash.Hash
func (opts *SignerOpts) GetHash() Hasher {
    return opts.Hash
}

// ec-gdsa PublicKey
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

// Verify asn.1 marshal data
func (pub *PublicKey) Verify(msg, sign []byte, opts crypto.SignerOpts) (bool, error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return false, ErrInvalidSignerOpts
    }

    return Verify(pub, opt.GetHash(), msg, sign), nil
}

// ec-gdsa PrivateKey
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
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return nil, ErrInvalidSignerOpts
    }

    return Sign(rand, priv, opt.GetHash(), digest)
}

// Generate the PrivateKey
func GenerateKey(random io.Reader, c elliptic.Curve) (*PrivateKey, error) {
    d, err := randFieldElement(random, c)
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

// New a PrivateKey from privatekey data
func NewPrivateKey(curve elliptic.Curve, k []byte) (*PrivateKey, error) {
    d := new(big.Int).SetBytes(k)

    one := new(big.Int).SetInt64(1)

    n := new(big.Int).Sub(curve.Params().N, one)
    if d.Cmp(n) >= 0 {
        return nil, errors.New("cryptobin/ecgdsa: privateKey's D is overflow")
    }

    dInv := fermatInverse(d, curve.Params().N)

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = d
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(dInv.Bytes())

    return priv, nil
}

// 输出私钥明文
// output PrivateKey data
func PrivateKeyTo(key *PrivateKey) []byte {
    privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
    return key.D.FillBytes(privateKey)
}

// 根据公钥明文初始化公钥
// New a PublicKey from publicKey data
func NewPublicKey(curve elliptic.Curve, k []byte) (*PublicKey, error) {
    x, y := elliptic.Unmarshal(curve, k)
    if x == nil || y == nil {
        return nil, errors.New("cryptobin/ecgdsa: incorrect public key")
    }

    pub := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    return pub, nil
}

// 输出公钥明文
// output PublicKey data
func PublicKeyTo(key *PublicKey) []byte {
    return elliptic.Marshal(key.Curve, key.X, key.Y)
}

// Sign data returns the ASN.1 encoded signature.
func Sign(rand io.Reader, priv *PrivateKey, h Hasher, data []byte) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, h, data)
    if err != nil {
        return nil, err
    }

    return encodeSignature(r, s)
}

// Verify verifies the ASN.1 encoded signature, sig, M, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func Verify(pub *PublicKey, h Hasher, data, sig []byte) bool {
    r, s, err := parseSignature(sig)
    if err != nil {
        return false
    }

    return VerifyWithRS(
        pub,
        h,
        data,
        r,
        s,
    )
}

func encodeSignature(r, s *big.Int) ([]byte, error) {
    var b cryptobyte.Builder
    b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
        b.AddASN1BigInt(r)
        b.AddASN1BigInt(s)
    })

    return b.Bytes()
}

func parseSignature(sig []byte) (r, s *big.Int, err error) {
    var inner cryptobyte.String
    input := cryptobyte.String(sig)

    r = new(big.Int)
    s = new(big.Int)

    if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
        !input.Empty() ||
        !inner.ReadASN1Integer(r) ||
        !inner.ReadASN1Integer(s) ||
        !inner.Empty() {
        return nil, nil, ErrInvalidASN1
    }

    return
}

// Sign data returns the Bytes encoded signature.
func SignBytes(rand io.Reader, priv *PrivateKey, h Hasher, data []byte) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, h, data)
    if err != nil {
        return nil, err
    }

    byteLen := (priv.Curve.Params().BitSize + 7) / 8

    sig = make([]byte, 2 * byteLen)

    r.FillBytes(sig[:byteLen])
    s.FillBytes(sig[byteLen:])

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, h Hasher, data, sig []byte) bool {
    byteLen := (pub.Curve.Params().BitSize + 7) / 8

    if len(sig) != 2*byteLen {
        return false
    }

    r := new(big.Int).SetBytes(sig[:byteLen])
    s := new(big.Int).SetBytes(sig[byteLen:])

    return VerifyWithRS(
        pub,
        h,
        data,
        r,
        s,
    )
}

/**
 *| IUF - EC-GDSA signature
 *|
 *|  UF 1. Compute h = H(m). If |h| > bitlen(q), set h to bitlen(q)
 *|	   leftmost (most significant) bits of h
 *|   F 2. Compute e = - OS2I(h) mod q
 *|   F 3. Get a random value k in [0,q]
 *|   F 4. Compute W = (W_x,W_y) = kG
 *|   F 5. Compute r = W_x mod q
 *|   F 6. If r is 0, restart the process at step 4.
 *|   F 7. Compute s = x(kr + e) mod q
 *|   F 8. If s is 0, restart the process at step 4.
 *|   F 9. Return (r,s)
 *
 */
func SignToRS(rand io.Reader, priv *PrivateKey, hashFunc Hasher, msg []byte) (r, s *big.Int, err error) {
    if priv == nil || priv.Curve == nil ||
        priv.X == nil || priv.Y == nil ||
        priv.D == nil || !priv.Curve.IsOnCurve(priv.X, priv.Y) {
        return nil, nil, ErrParametersNotSetUp
    }

    h := hashFunc()

    curve := priv.Curve
    curveParams := curve.Params()
    n := curveParams.N

    w := (n.BitLen() + 7) / 8
    hsize := h.Size()
    d := priv.D

    /* 1. Compute h = H(m) */
    h.Write(msg)
    eBuf := h.Sum(nil)

    rshift := 0
    if hsize > w {
        rshift = (hsize - w) * 8
    }

    e := new(big.Int).SetBytes(eBuf)
    e.Rsh(e, uint(rshift))

    // 2: e = q - (h mod q) (except when h is 0).
    e = e.Mod(e, n)
    e.Mod(e.Neg(e), n)

Retry:
    k, err := randFieldElement(rand, priv.Curve)
    if err != nil {
        return
    }

    // 4: Compute W = kG = (Wx, Wy) */
    x1, _ := curve.ScalarBaseMult(k.Bytes())

    // 5. Compute r = Wx mod q */
    r = new(big.Int)
    r.Mod(x1, n)

    if r.Cmp(zero) == 0 {
        goto Retry
    }

    /* 7. Compute s = x(kr + e) mod q */
    kr := new(big.Int)
    kr.Mod(kr.Mul(k, r), n)

    s = new(big.Int)
    s.Mod(s.Add(kr, e), n)
    s.Mod(s.Mul(d, s), n)

    if r.Cmp(zero) == 0 {
        goto Retry
    }

    return r, s, nil
}

/*
 *| IUF - EC-GDSA verification
 *|
 *| I   1. Reject the signature if r or s is 0.
 *|  UF 2. Compute h = H(m). If |h| > bitlen(q), set h to bitlen(q)
 *|	   leftmost (most significant) bits of h
 *|   F 3. Compute e = OS2I(h) mod q
 *|   F 4. Compute u = ((r^-1)e mod q)
 *|   F 5. Compute v = ((r^-1)s mod q)
 *|   F 6. Compute W' = uG + vY
 *|   F 7. Compute r' = W'_x mod q
 *|   F 8. Accept the signature if and only if r equals r'
 *
 */
func VerifyWithRS(pub *PublicKey, hashFunc Hasher, data []byte, r, s *big.Int) bool {
    if pub == nil || pub.Curve == nil ||
        pub.X == nil || pub.Y == nil ||
        !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return false
    }

    if r.Sign() <= 0 || s.Sign() <= 0 {
        return false
    }

    h := hashFunc()

    curve := pub.Curve
    curveParams := pub.Curve.Params()
    n := curveParams.N

    w := (n.BitLen() + 7) / 8
    hsize := h.Size()

    /* 1. Compute h = H(m) */
    h.Write(data)
    eBuf := h.Sum(nil)

    rshift := 0
    if hsize > w {
        rshift = (hsize - w) * 8
    }

    e := new(big.Int).SetBytes(eBuf)
    e.Rsh(e, uint(rshift))

    /* 3. Compute e by converting h to an integer and reducing it mod q */
    e = e.Mod(e, n)

    /* 4. Compute u = (r^-1)e mod q */
    rinv := new(big.Int).ModInverse(r, n)
    u := new(big.Int).Mul(rinv, e)

    /* 5. Compute v = (r^-1)s mod q */
    v := new(big.Int).Mul(rinv, s)

    /* 6. Compute W' = uG + vY */
    x21, y21 := curve.ScalarMult(pub.X, pub.Y, v.Bytes())
    x22, y22 := curve.ScalarBaseMult(u.Bytes())
    x2, _ := curve.Add(x21, y21, x22, y22)

    /* 7. Compute r' = W'_x mod q */
    rPrime := x2.Mod(x2, n)

    return r.Cmp(rPrime) == 0
}

func XY(D *big.Int, c elliptic.Curve) (X, Y *big.Int) {
    dInv := fermatInverse(D, c.Params().N)
    return c.ScalarBaseMult(dInv.Bytes())
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
