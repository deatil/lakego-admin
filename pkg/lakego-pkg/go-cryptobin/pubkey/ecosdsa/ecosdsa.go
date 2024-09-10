package ecosdsa

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
)

var (
    ErrParametersNotSetUp = errors.New("go-cryptobin/ecosdsa: parameters not set up before generating key")
    ErrInvalidASN1        = errors.New("go-cryptobin/ecosdsa: invalid ASN.1")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/ecosdsa: opts must be *SignerOpts")
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
        return nil, errors.New("cryptobin/ecosdsa: privateKey's D is overflow")
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
        return nil, errors.New("cryptobin/ecosdsa: incorrect public key")
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
func SignBytes(rand io.Reader, priv *PrivateKey, hashFunc Hasher, data []byte) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, hashFunc, data)
    if err != nil {
        return nil, err
    }

    h := hashFunc()

    curveParams := priv.Curve.Params()

    rlen := h.Size()
    slen := (curveParams.BitSize + 7) / 8

    sig = make([]byte, rlen + slen)

    r.FillBytes(sig[:rlen])
    s.FillBytes(sig[rlen:])

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, hashFunc Hasher, data, sig []byte) bool {
    h := hashFunc()

    curveParams := pub.Curve.Params()

    rlen := h.Size()
    slen := (curveParams.BitSize + 7) / 8

    if len(sig) != rlen + slen {
        return false
    }

    r := new(big.Int).SetBytes(sig[:rlen])
    s := new(big.Int).SetBytes(sig[rlen:])

    return VerifyWithRS(pub, hashFunc, data, r, s)
}

/*
 * Generic *internal* EC-{,O}SDSA signature functions. There purpose is to
 * allow passing specific hash functions and the random ephemeral
 * key k, so that compliance tests against test vector be made
 * without ugly hack in the code itself.
 *
 * The 'optimized' parameter tells the function if the r value of
 * the signature is computed using only the x ccordinate of the
 * the user's public key (normal version uses both coordinates).
 *
 * Normal:     r = h(Wx || Wy || m)
 * Optimized : r = h(Wx || m)
 *
 *| IUF - ECSDSA/ECOSDSA signature
 *|
 *| I	1. Get a random value k in ]0, q[
 *| I	2. Compute W = kG = (Wx, Wy)
 *| IUF 3. Compute r = H(Wx [|| Wy] || m)
 *|	   - In the normal version (ECSDSA), r = H(Wx || Wy || m).
 *|	   - In the optimized version (ECOSDSA), r = H(Wx || m).
 *|   F 4. Compute e = OS2I(r) mod q
 *|   F 5. if e == 0, restart at step 1.
 *|   F 6. Compute s = (k + ex) mod q.
 *|   F 7. if s == 0, restart at step 1.
 *|   F 8. Return (r, s)
 *
 * In the project, the normal mode is named ECSDSA, the optimized
 * one is ECOSDSA.
 *
 * Implementation note:
 *
 * In ISO-14888-3, the option is provided to the developer to check
 * whether r = 0 and restart the process in that case. Even if
 * unlikely to trigger, that check makes a lot of sense because the
 * verifier expects a non-zero value for r. In the  specification, r
 * is a string (r =  H(Wx [|| Wy] || m)). But r is used in practice
 * - both on the signer and the verifier - after conversion to an
 * integer and reduction mod q. The value resulting from that step
 * is named e (e = OS2I(r) mod q). The check for the case when r = 0
 * should be replaced by a check for e = 0. This is more conservative
 * and what is described above and done below in the implementation.
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
    /* 1. Get a random value k in ]0, q[ */
    k, err := randFieldElement(rand, priv.Curve)
    if err != nil {
        return
    }

    /* 2. Compute W = kG = (Wx, Wy). */
    x1, _ := curve.ScalarBaseMult(k.Bytes())

    /*
     * 3. Compute r = H(Wx [|| Wy] || m)
     *
     *    - In the normal version (ECSDSA), r = h(Wx || Wy || m).
     *    - In the optimized version (ECOSDSA), r = h(Wx || m).
     */
    Wx := make([]byte, plen)
    x1.FillBytes(Wx)

    /* 3. Compute r = H(Wx [|| Wy] || m) */
    h.Write(Wx)
    h.Write(msg)
    eBuf := h.Sum(nil)

    r = new(big.Int)
    r.SetBytes(eBuf)

    /* 4. Compute e = OS2I(r) mod q */
    e := new(big.Int).Set(r)
    e.Mod(e, n)

    if e.Cmp(zero) == 0 {
        goto Retry
    }

    /* 6. Compute s = (k + ex) mod q. */
    ex := new(big.Int)
    ex.Mod(ex.Mul(e, priv.D), n)

    s = new(big.Int)
    s.Mod(s.Add(k, ex), n)

    /* 7. if s == 0, restart at step 1. */
    if s.Cmp(zero) == 0 {
        goto Retry
    }

    return r, s, nil
}

/*
 *| IUF - ECSDSA/ECOSDSA verification
 *|
 *| I   1. if s is not in ]0,q[, reject the signature.
 *| I   2. Compute e = -r mod q
 *| I   3. If e == 0, reject the signature.
 *| I   4. Compute W' = sG + eY
 *| IUF 5. Compute r' = H(W'x [|| W'y] || m)
 *|    - In the normal version (ECSDSA), r' = H(W'x || W'y || m).
 *|    - In the optimized version (ECOSDSA), r' = H(W'x || m).
 *|   F 6. Accept the signature if and only if r and r' are the same
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
    hsize := h.Size()

    /* Check that s is in ]0,q[ */
    if s.Cmp(n) >= 0 {
        return false
    }

    /*
     * 2. Compute e = -r mod q
     *
     * To avoid dealing w/ negative numbers, we simply compute
     * e = -r mod q = q - (r mod q) (except when r is 0).
     */
    rmodq := new(big.Int)
    rmodq.Mod(r, n)

    e := new(big.Int)
    e.Mod(e.Neg(rmodq), n)

    /* 3. If e == 0, reject the signature. */
    if e.Cmp(zero) == 0 {
        return false
    }

    /* 4. Compute W' = sG + eY */
    x21, y21 := curve.ScalarMult(pub.X, pub.Y, e.Bytes())
    x22, y22 := curve.ScalarBaseMult(s.Bytes())
    x2, _ := curve.Add(x21, y21, x22, y22)

    /*
     * 5. Compute r' = H(W'x [|| W'y] || m)
     *
     *    - In the normal version (ECSDSA), r = h(W'x || W'y || m).
     *    - In the optimized version (ECOSDSA), r = h(W'x || m).
     */
    Wx := make([]byte, plen)
    x2.FillBytes(Wx)

    h.Write(Wx)
    h.Write(data)
    rPrime := h.Sum(nil)

    rBytes := make([]byte, hsize)
    r.FillBytes(rBytes)

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

