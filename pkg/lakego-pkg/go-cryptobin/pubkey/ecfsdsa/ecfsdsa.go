package ecfsdsa

import (
    "io"
    "hash"
    "bytes"
    "errors"
    "math/big"
    "crypto"
    "crypto/subtle"
    "crypto/elliptic"

    "golang.org/x/crypto/cryptobyte"
    "golang.org/x/crypto/cryptobyte/asn1"

    "github.com/deatil/go-cryptobin/tool/alias"
)

var (
    ErrParametersNotSetUp = errors.New("go-cryptobin/ecfsdsa: parameters not set up before generating key")
    ErrInvalidASN1        = errors.New("go-cryptobin/ecfsdsa: invalid ASN.1")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/ecfsdsa: opts must be *SignerOpts")
)

var (
    zero = big.NewInt(0)
    one  = new(big.Int).SetInt64(1)
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
        return nil, errors.New("go-cryptobin/ecfsdsa: privateKey's D is overflow")
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
        return nil, errors.New("go-cryptobin/ecfsdsa: incorrect public key")
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

    curveParams := priv.Curve.Params()
    p := curveParams.P

    plen := (p.BitLen() + 7) / 8
    qlen := (curveParams.BitSize + 7) / 8

    sig = make([]byte, 2 * plen + qlen)

    r.FillBytes(sig[:2 * plen])
    s.FillBytes(sig[2 * plen:])

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, h Hasher, data, sig []byte) bool {
    curveParams := pub.Curve.Params()
    p := curveParams.P

    plen := (p.BitLen() + 7) / 8
    qlen := (curveParams.BitSize + 7) / 8

    if len(sig) != 2 * plen + qlen {
        return false
    }

    r := new(big.Int).SetBytes(sig[:2 * plen])
    s := new(big.Int).SetBytes(sig[2 * plen:])

    return VerifyWithRS(pub, h, data, r, s)
}

/*
 *| IUF - ECFSDSA signature
 *|
 *| I   1. Get a random value k in ]0,q[
 *| I   2. Compute W = (W_x,W_y) = kG
 *| I   3. Compute r = FE2OS(W_x)||FE2OS(W_y)
 *| I   4. If r is an all zero string, restart the process at step 1.
 *| IUF 5. Compute h = H(r||m)
 *|   F 6. Compute e = OS2I(h) mod q
 *|   F 7. Compute s = (k + ex) mod q
 *|   F 8. If s is 0, restart the process at step 1 (see c. below)
 *|   F 9. Return (r,s)
 *
 * Implementation notes:
 *
 * a) sig is built as the concatenation of r and s. r is encoded on
 *    2*ceil(bitlen(p)) bytes and s on ceil(bitlen(q)) bytes.
 * b) in EC-FSDSA, the public part of the key is not needed per se during
 *    the signature but - as it is needed in other signature algs implemented
 *    in the library - the whole key pair is passed instead of just the
 *    private key.
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
    p := curveParams.P

    plen := (p.BitLen() + 7) / 8

Retry:
    /*  1. Get a random value k in ]0,q[ */
    k, err := randFieldElement(rand, priv.Curve)
    if err != nil {
        return
    }

    /*  2. Compute W = (W_x,W_y) = kG */
    x1, y1 := curve.ScalarBaseMult(k.Bytes())

    /*  3. Compute r = FE2OS(W_x)||FE2OS(W_y) */
    rBytes := make([]byte, 2*plen)
    x1.FillBytes(rBytes[:plen])
    y1.FillBytes(rBytes[plen:])

    /*  4. If r is an all zero string, restart the process at step 1. */
    if alias.ConstantTimeAllZero(rBytes) {
        goto Retry
    }

    r = new(big.Int)
    r.SetBytes(rBytes)

    /*  5. Compute h = H(r||m). */
    h.Write(rBytes)
    h.Write(msg)
    eBuf := h.Sum(nil)

    /*  6. Compute e by converting h to an integer and reducing it mod q */
    e := new(big.Int).SetBytes(eBuf)
    e.Mod(e, n)

    /*  7. Compute s = (k + ex) mod q */
    ex := new(big.Int)
    ex.Mod(ex.Mul(e, priv.D), n)

    s = new(big.Int)
    s.Mod(s.Add(k, ex), n)

    if s.Cmp(zero) == 0 {
        goto Retry
    }

    return r, s, nil
}

/*
 *| IUF - ECFSDSA verification
 *|
 *| I   1. Reject the signature if r is not a valid point on the curve.
 *| I   2. Reject the signature if s is not in ]0,q[
 *| IUF 3. Compute h = H(r||m)
 *|   F 4. Convert h to an integer and then compute e = -h mod q
 *|   F 5. compute W' = sG + eY, where Y is the public key
 *|   F 6. Compute r' = FE2OS(W'_x)||FE2OS(W'_y)
 *|   F 7. Accept the signature if and only if r equals r'
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
    p := curveParams.P

    plen := (p.BitLen() + 7) / 8

    /* Check that s is in ]0,q[ */
    if s.Cmp(n) >= 0 {
        return false
    }

    /*  1. Reject the signature if r is not a valid point on the curve. */
    rBytes := make([]byte, 2*plen)
    r.FillBytes(rBytes)

    rxBuf := rBytes[:plen]
    ryBuf := rBytes[plen:]

    rx := new(big.Int).SetBytes(rxBuf)
    ry := new(big.Int).SetBytes(ryBuf)

    if !pub.Curve.IsOnCurve(rx, ry) {
        return false
    }

    /* 3. Compute h = H(r||m) */
    h.Write(rBytes)
    h.Write(data)
    eBuf := h.Sum(nil)

    /*
     * 4. Convert h to an integer and then compute e = -h mod q
     *
     * Because we only support positive integers, we compute
     * e = q - (h mod q) (except when h is 0).
     */
    e := new(big.Int).SetBytes(eBuf)
    e.Mod(e, n)

    e.Mod(e.Neg(e), n)

    /* 5. compute W' = (W'_x,W'_y) = sG + eY, where Y is the public key */
    x21, y21 := curve.ScalarMult(pub.X, pub.Y, e.Bytes())
    x22, y22 := curve.ScalarBaseMult(s.Bytes())
    x2, y2 := curve.Add(x21, y21, x22, y22)

    /* 7. Accept the signature if and only if r equals r' */
    rPrime := make([]byte, 2*plen)
    x2.FillBytes(rPrime[:plen])
    y2.FillBytes(rPrime[plen:])

    return bytes.Equal(rBytes, rPrime)
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

