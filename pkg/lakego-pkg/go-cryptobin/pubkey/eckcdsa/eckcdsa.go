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

    "github.com/deatil/go-cryptobin/tool/math"
)

// see TTAK.KO-12.0015/R3

var (
    ErrParametersNotSetUp = errors.New("go-cryptobin/eckcdsa: parameters not set up before generating key")
    ErrInvalidK           = errors.New("go-cryptobin/eckcdsa: use another K")
    ErrInvalidASN1        = errors.New("go-cryptobin/eckcdsa: invalid ASN.1")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/eckcdsa: opts must be *SignerOpts")
)

// hash Func
type Hasher = func() hash.Hash

// SignerOpts contains options for creating and verifying EC-KCDSA signatures.
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

// ec-kcdsa PublicKey
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
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return nil, ErrInvalidSignerOpts
    }

    return Sign(rand, priv, opt.GetHash(), digest)
}

// Generate the paramters
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
        return nil, errors.New("cryptobin/eckcdsa: privateKey's D is overflow")
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
        return nil, errors.New("cryptobin/eckcdsa: incorrect public key")
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

    return VerifyWithRS(pub, h, data, r, s)
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

    hsize := h().Size()
    bitSize := priv.Curve.Params().BitSize
    sigRLen := sigRLen(hsize, bitSize)

    sig = make([]byte, sigLen(hsize, bitSize))

    r.FillBytes(sig[:sigRLen])
    s.FillBytes(sig[sigRLen:])

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, h Hasher, data, sig []byte) bool {
    hsize := h().Size()
    bitSize := pub.Curve.Params().BitSize
    sigRLen := sigRLen(hsize, bitSize)

    if len(sig) != sigLen(hsize, bitSize) {
        return false
    }

    r := new(big.Int).SetBytes(sig[:sigRLen])
    s := new(big.Int).SetBytes(sig[sigRLen:])

    return VerifyWithRS(pub, h, data, r, s)
}

/**
 *| IUF - EC-KCDSA signature
 *|
 *| IUF  1. Compute h = H(z||m)
 *|   F  2. If |H| > bitlen(q), set h to beta' rightmost bits of
 *|         bitstring h (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|         set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
 *|   F  3. Get a random value k in ]0,q[
 *|   F  4. Compute W = (W_x,W_y) = kG
 *|   F  5. Compute r = H(FE2OS(W_x)).
 *|   F  6. If |H| > bitlen(q), set r to beta' rightmost bits of
 *|         bitstring r (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|         set r to I2BS(beta', BS2I(|H|, r) mod 2^beta')
 *|   F  7. Compute e = OS2I(r XOR h) mod q
 *|   F  8. Compute s = x(k - e) mod q
 *|   F  9. if s == 0, restart at step 3.
 *|   F 10. return (r,s)
 *
 */
func SignToRS(random io.Reader, priv *PrivateKey, h Hasher, msg []byte) (r, s *big.Int, err error) {
    var k *big.Int

    for {
        k, err = randFieldElement(random, priv.Curve)
        if err != nil {
            return
        }

        r, s, err = SignUsingK(k, priv, h, msg)
        if err == ErrInvalidK {
            continue
        }

        return
    }
}

// sign with k
func SignUsingK(k *big.Int, priv *PrivateKey, hashFunc Hasher, msg []byte) (r, s *big.Int, err error) {
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
    e := new(big.Int).Xor(r, v)
    e.Mod(e, n)

    // 7: t ← x(k - e) mod n
    t := new(big.Int)
    t.Mod(t.Sub(k, e), n)
    t.Mod(t.Mul(d, t), n)

    if t.Sign() <= 0 {
        return nil, nil, ErrInvalidK
    }

    s = t

    return r, s, nil
}

/**
 *| IUF - EC-KCDSA verification
 *|
 *| I   1. Check the length of r:
 *|         - if |H| > bitlen(q), r must be of length
 *|           beta' = 8 * ceil(bitlen(q) / 8)
 *|         - if |H| <= bitlen(q), r must be of length hsize
 *| I   2. Check that s is in ]0,q[
 *| IUF 3. Compute h = H(z||m)
 *|   F 4. If |H| > bitlen(q), set h to beta' rightmost bits of
 *|        bitstring h (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|        set h to I2BS(beta', BS2I(|H|, h) mod 2^beta')
 *|   F 5. Compute e = OS2I(r XOR h) mod q
 *|   F 6. Compute W' = sY + eG, where Y is the public key
 *|   F 7. Compute r' = h(W'x)
 *|   F 8. If |H| > bitlen(q), set r' to beta' rightmost bits of
 *|        bitstring r' (w/ beta' = 8 * ceil(bitlen(q) / 8)), i.e.
 *|        set r' to I2BS(beta', BS2I(|H|, r') mod 2^beta')
 *|   F 9. Check if r == r'
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
    K := (curveParams.BitSize + 7) / 8 // curve size
    Lh := h.Size()
    L := h.BlockSize()
    xQ := pub.X
    yQ := pub.Y

    t := s

    if Lh > w {
        if (r.BitLen()+7)/8 > w {
            return false
        }
    } else {
        if (r.BitLen()+7)/8 > Lh {
            return false
        }
    }
    if t.Cmp(n) >= 0 {
        return false
    }

    var two_8w *big.Int
    if Lh > w {
        two_8w = big.NewInt(256)
        two_8w.Exp(two_8w, big.NewInt(int64(w)), nil)
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

func sigRLen(hsize, n int) int {
    return math.Min(hsize, byteceil(n))
}

func sigLLen(n int) int {
    return byteceil(n)
}

func sigLen(hsize, n int) int {
    return sigRLen(hsize, n) + sigLLen(n)
}

func byteceil(size int) int {
    return (size + 7) / 8
}
