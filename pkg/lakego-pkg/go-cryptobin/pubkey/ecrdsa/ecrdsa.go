package ecrdsa

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
    ErrParametersNotSetUp = errors.New("go-cryptobin/ecrdsa: parameters not set up before generating key")
    ErrInvalidASN1        = errors.New("go-cryptobin/ecrdsa: invalid ASN.1")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/ecrdsa: opts must be *SignerOpts")
)

var (
    zero = big.NewInt(0)
    one  = new(big.Int).SetInt64(1)
)

type Hasher = func() hash.Hash

// SignerOpts contains options for creating and verifying EC-GDSA signatures.
type SignerOpts struct {
    Hash          Hasher
    UseISO14888_3 bool
}

// HashFunc returns opts.Hash
func (opts *SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// GetHash returns func() hash.Hash
func (opts *SignerOpts) GetHash() Hasher {
    return opts.Hash
}

// GetUseISO14888_3 returns bool
func (opts *SignerOpts) GetUseISO14888_3() bool {
    return opts.UseISO14888_3
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

    return Verify(pub, opt.GetHash(), msg, sign, opt.GetUseISO14888_3()), nil
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

    return Sign(rand, priv, opt.GetHash(), digest, opt.GetUseISO14888_3())
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
        return nil, errors.New("cryptobin/ecrdsa: privateKey's D is overflow")
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = d
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

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
        return nil, errors.New("cryptobin/ecrdsa: incorrect public key")
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
func Sign(rand io.Reader, priv *PrivateKey, h Hasher, data []byte, useISO14888_3 bool) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, h, data, useISO14888_3)
    if err != nil {
        return nil, err
    }

    return encodeSignature(r, s)
}

// Verify verifies the ASN.1 encoded signature, sig, M, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func Verify(pub *PublicKey, h Hasher, data, sig []byte, useISO14888_3 bool) bool {
    r, s, err := parseSignature(sig)
    if err != nil {
        return false
    }

    return VerifyWithRS(pub, h, data, r, s, useISO14888_3)
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
func SignBytes(rand io.Reader, priv *PrivateKey, h Hasher, data []byte, useISO14888_3 bool) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, h, data, useISO14888_3)
    if err != nil {
        return nil, err
    }

    qlen := (priv.Curve.Params().BitSize + 7) / 8

    sig = make([]byte, 2 * qlen)

    r.FillBytes(sig[:qlen])
    s.FillBytes(sig[qlen:])

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, h Hasher, data, sig []byte, useISO14888_3 bool) bool {
    qlen := (pub.Curve.Params().BitSize + 7) / 8

    if len(sig) != 2 * qlen {
        return false
    }

    r := new(big.Int).SetBytes(sig[:qlen])
    s := new(big.Int).SetBytes(sig[qlen:])

    return VerifyWithRS(pub, h, data, r, s, useISO14888_3)
}

/*
 *| IUF - EC-RDSA signature
 *|
 *|  UF	 1. Compute h = H(m)
 *|   F	 2. Get a random value k in ]0,q[
 *|   F	 3. Compute W = (W_x,W_y) = kG
 *|   F	 4. Compute r = W_x mod q
 *|   F	 5. If r is 0, restart the process at step 2.
 *|   F	 6. Compute e = OS2I(h) mod q. If e is 0, set e to 1.
 *|         NOTE: here, ISO/IEC 14888-3 and RFCs differ in the way e treated.
 *|         e = OS2I(h) for ISO/IEC 14888-3, or e = OS2I(reversed(h)) when endianness of h
 *|         is reversed for RFCs.
 *|   F	 7. Compute s = (rx + ke) mod q
 *|   F	 8. If s is 0, restart the process at step 2.
 *|   F 11. Return (r,s)
 *
 */
func SignToRS(rand io.Reader, priv *PrivateKey, hashFunc Hasher, msg []byte, useISO14888_3 bool) (r, s *big.Int, err error) {
    if priv == nil || priv.Curve == nil ||
        priv.X == nil || priv.Y == nil ||
        priv.D == nil || !priv.Curve.IsOnCurve(priv.X, priv.Y) {
        return nil, nil, ErrParametersNotSetUp
    }

    h := hashFunc()

    curve := priv.Curve
    curveParams := curve.Params()
    n := curveParams.N

Retry:
    /* 2. Get a random value k in ]0, q[ ... */
    k, err := randFieldElement(rand, priv.Curve)
    if err != nil {
        return
    }

    /* 3. Compute W = kG = (Wx, Wy) */
    x1, _ := curve.ScalarBaseMult(k.Bytes())

    /* 4. Compute r = Wx mod q */
    r = new(big.Int)
    r.Mod(x1, n)

    /* 5. If r is 0, restart the process at step 2. */
    if r.Cmp(zero) == 0 {
        goto Retry
    }

    /* 6. Compute e = OS2I(h) mod q. If e is 0, set e to 1. */
    h.Write(msg)
    eBuf := h.Sum(nil)

    if useISO14888_3 {
        eBuf = reverse(eBuf)
    }

    e := new(big.Int).SetBytes(eBuf)
    e.Mod(e, n)

    if e.Cmp(zero) == 0 {
        e.Set(one)
    }

    /* Compute s = (rx + ke) mod q */
    rx := new(big.Int)
    rx.Mod(rx.Mul(r, priv.D), n)

    ke := new(big.Int)
    ke.Mod(ke.Mul(k, e), n)

    s = new(big.Int)
    s.Mod(s.Add(rx, ke), n)

    if s.Cmp(zero) == 0 {
        goto Retry
    }

    return r, s, nil
}

/*
 *| IUF - EC-RDSA verification
 *|
 *|  UF 1. Check that r and s are both in ]0,q[
 *|   F 2. Compute h = H(m)
 *|   F 3. Compute e = OS2I(h)^-1 mod q
 *|         NOTE: here, ISO/IEC 14888-3 and RFCs differ in the way e treated.
 *|         e = OS2I(h) for ISO/IEC 14888-3, or e = OS2I(reversed(h)) when endianness of h
 *|         is reversed for RFCs.
 *|   F 4. Compute u = es mod q
 *|   F 5. Compute v = -er mod q
 *|   F 6. Compute W' = uG + vY = (W'_x, W'_y)
 *|   F 7. Compute r' = W'_x mod q
 *|   F 8. Check r and r' are the same
 *
 */
func VerifyWithRS(pub *PublicKey, hashFunc Hasher, data []byte, r, s *big.Int, useISO14888_3 bool) bool {
    if pub == nil || pub.Curve == nil ||
        pub.X == nil || pub.Y == nil ||
        !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return false
    }

    if r.Sign() <= 0 || s.Sign() <= 0 {
        return false
    }

    hasher := hashFunc()

    curve := pub.Curve
    curveParams := pub.Curve.Params()
    n := curveParams.N

    /* 1. Check that r and s are both in ]0,q[ */
    if r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
        return false
    }

    /* 2. Compute h = H(m) */
    hasher.Write(data)
    eBuf := hasher.Sum(nil)

    if useISO14888_3 {
        eBuf = reverse(eBuf)
    }

    /* 3. Compute e = OS2I(h)^-1 mod q */
    h := new(big.Int).SetBytes(eBuf)
    h.Mod(h, n)

    /* If h is equal to 0, set it to 1 */
    if h.Cmp(zero) == 0 {
        h.Set(one)
    }

    e := new(big.Int).ModInverse(h, n)

    /* 4. Compute u = es mod q */
    u := new(big.Int)
    u.Mod(u.Mul(e, s), n)

    /* 5. Compute v = -er mod q
     *
     * Because we only support positive integers, we compute
     * v = -er mod q = q - (er mod q) (except when er is 0).
     * NOTE: we reuse e for er computation to avoid losing
     * a variable.
     */
    v := new(big.Int)
    v.Mod(v.Mul(e, r), n)
    v.Mod(v.Neg(v), n)

    /* 6. Compute W' = uG + vY = (W'_x, W'_y) */
    x21, y21 := curve.ScalarMult(pub.X, pub.Y, v.Bytes())
    x22, y22 := curve.ScalarBaseMult(u.Bytes())
    x2, _ := curve.Add(x21, y21, x22, y22)

    /* 7. Compute r' = W'_x mod q */
    rPrime := new(big.Int)
    rPrime.Mod(x2, n)

    return r.Cmp(rPrime) == 0
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

// Reverse bytes
func reverse(b []byte) []byte {
    d := make([]byte, len(b))
    copy(d, b)

    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
}
