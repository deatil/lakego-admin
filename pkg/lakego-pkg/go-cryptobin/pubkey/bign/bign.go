package bign

import (
    "io"
    "hash"
    "bytes"
    "errors"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/elliptic"

    "golang.org/x/crypto/cryptobyte"
    "golang.org/x/crypto/cryptobyte/asn1"

    "github.com/deatil/go-cryptobin/hash/belt"
)

/*
 * This is an implementation of the BIGN signature algorithm as
 * described in the STB 34.101.45 standard
 * (http://apmi.bsu.by/assets/files/std/bign-spec29.pdf).
 *
 * The BIGN signature is a variation on the Shnorr signature scheme.
 *
 * An english high-level (less formal) description and rationale can be found
 * in the IETF archive:
 *   https://mailarchive.ietf.org/arch/msg/cfrg/pI92HSRjMBg50NVEz32L5RciVBk/
 *
 * BIGN comes in two flavors: deterministic and non-deterministic. The current
 * file implements the two.
 *
 */

var (
    ErrAdata              = errors.New("go-cryptobin/bign: invalid adata")
    ErrPrivateKey         = errors.New("go-cryptobin/bign: invalid PrivateKey")
    ErrParametersNotSetUp = errors.New("go-cryptobin/bign: parameters not set up before generating key")
    ErrInvalidASN1        = errors.New("go-cryptobin/bign: invalid ASN.1")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/bign: opts must be *SignerOpts")
)

var (
    zero = big.NewInt(0)
    one  = big.NewInt(1)
    two  = big.NewInt(2)
)

type Hasher = func() hash.Hash

// SignerOpts contains options for creating and verifying EC-GDSA signatures.
type SignerOpts struct {
    Hash  Hasher
    Adata []byte
}

// HashFunc returns opts.Hash
func (opts *SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// GetHash returns func() hash.Hash
func (opts *SignerOpts) GetHash() Hasher {
    return opts.Hash
}

// GetAdata returns adata data
func (opts *SignerOpts) GetAdata() []byte {
    return opts.Adata
}

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

// Verify asn.1 marshal data
func (pub *PublicKey) Verify(msg, sign []byte, opts crypto.SignerOpts) (bool, error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return false, ErrInvalidSignerOpts
    }

    return Verify(pub, opt.GetHash(), msg, opt.GetAdata(), sign), nil
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

// crypto.Signer
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return nil, ErrInvalidSignerOpts
    }

    return Sign(rand, priv, opt.GetHash(), digest, opt.GetAdata())
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
        return nil, errors.New("go-cryptobin/bign: privateKey's D is overflow")
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
        return nil, errors.New("go-cryptobin/bign: incorrect public key")
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
func Sign(rand io.Reader, priv *PrivateKey, h Hasher, data []byte, adata []byte) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, h, data, adata)
    if err != nil {
        return nil, err
    }

    return encodeSignature(r, s)
}

// Verify verifies the ASN.1 encoded signature, sig, M, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func Verify(pub *PublicKey, h Hasher, data, adata []byte, sig []byte) bool {
    r, s, err := parseSignature(sig)
    if err != nil {
        return false
    }

    return VerifyWithRS(pub, h, data, adata, r, s)
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
func SignBytes(rand io.Reader, priv *PrivateKey, h Hasher, data []byte, adata []byte) (sig []byte, err error) {
    r, s, err := SignToRS(rand, priv, h, data, adata)
    if err != nil {
        return nil, err
    }

    newHash := h()

    curveParams := priv.Curve.Params()
    qlen := (curveParams.BitSize + 7) / 8
    l := qlen / 2
    hsize := newHash.Size()

    sig = make([]byte, l + qlen)

    rBytes := make([]byte, mathMin(l, hsize))
    r.FillBytes(rBytes)
    copy(sig[:l], rBytes)

    sBytes := make([]byte, qlen)
    s.FillBytes(sBytes)
    copy(sig[l:], sBytes)

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, h Hasher, data, adata []byte, sig []byte) bool {
    curveParams := pub.Curve.Params()
    qlen := (curveParams.BitSize + 7) / 8
    l := qlen / 2

    if len(sig) != l + qlen {
        return false
    }

    r := new(big.Int).SetBytes(sig[:l])
    s := new(big.Int).SetBytes(sig[l:])

    return VerifyWithRS(pub, h, data, adata, r, s)
}

/*
 *| IUF - bign signature
 */
func SignToRS(random io.Reader, priv *PrivateKey, hashFunc Hasher, msg []byte, adata []byte) (r, s *big.Int, err error) {
    if priv == nil || priv.Curve == nil ||
        priv.X == nil || priv.Y == nil ||
        priv.D == nil || !priv.Curve.IsOnCurve(priv.X, priv.Y) {
        return nil, nil, ErrParametersNotSetUp
    }

    newHash := hashFunc()

    curve := priv.Curve
    curveParams := curve.Params()
    n := curveParams.N
    p := curveParams.P

    x := priv.D

    qlen := (curveParams.BitSize + 7) / 8
    plen := (p.BitLen() + 7) / 8
    hsize := newHash.Size()

    l := qlen / 2

    /* Sanity check */
    if x.Cmp(n) >= 0 {
        err = ErrPrivateKey
        return
    }

    if len(adata) == 0 {
        err = ErrAdata
        return
    }

    /* 1. Compute h = H(m) */
    newHash.Write(msg)
    hashBuf := newHash.Sum(nil)

    /* 2. get a random value k in ]0,q[ */
    var k *big.Int

    if random != nil {
        k, err = rand.Int(random, n)
        if err != nil {
            return
        }
    } else {
        k = new(big.Int)
        err = determiniticNonce(k, n, curveParams.BitSize, priv.D, adata, hashBuf)
        if err != nil {
            return
        }
    }

    /* 3. Compute W = (W_x,W_y) = kG */
    kGx, kGy := curve.ScalarBaseMult(k.Bytes())

    /* 4. Compute s0 = <BELT-HASH(OID(H) || <<FE2OS(W_x)> || <FE2OS(W_y)>>2*l || H(X))>l */
    beltHash := belt.New()

    oid, err := GetOidFromAdata(adata)
    if err != nil {
        return
    }

    beltHash.Write(oid)

    FE2OS_W := make([]byte, 2*plen)
    kGx.FillBytes(FE2OS_W[:plen])
    reverse(FE2OS_W[:plen])

    kGy.FillBytes(FE2OS_W[plen:2*plen])
    reverse(FE2OS_W[plen:2*plen])

    /* Only hash the 2*l bytes of FE2OS(W_x) || FE2OS(W_y) */
    beltHash.Write(FE2OS_W[:2*l])

    beltHash.Write(hashBuf)

    hashBelt := beltHash.Sum(nil)

    sig := make([]byte, l)
    copy(sig, hashBelt[:mathMin(l, hsize)])

    r = new(big.Int).SetBytes(sig)

    /* 5. Now compute s1 = (k - H_bar - (s0_bar + 2**l) * d) mod q */
    /* First import H and s0 as numbers modulo q */
    /* Import H */
    reverse(hashBuf)
    h := new(big.Int).SetBytes(hashBuf)
    h.Mod(h, n)

    copy(FE2OS_W[:], sig[:l])
    reverse(FE2OS_W[:l])
    s1 := new(big.Int).SetBytes(FE2OS_W[:l])
    s1.Mod(s1, n)

    /* Compute (s0_bar + 2**l) * d */
    tmp := new(big.Int).Set(one)
    tmp.Lsh(tmp, uint(8*l))
    tmp.Mod(tmp, n)

    s1.Mod(s1.Add(s1, tmp), n)

    s1.Mod(s1.Mul(s1, priv.D), n)
    s1.Mod(s1.Sub(k, s1), n)
    s1.Mod(s1.Sub(s1, h), n)

    s1Bytes := make([]byte, qlen)
    s1.FillBytes(s1Bytes)
    reverse(s1Bytes)

    s = new(big.Int).SetBytes(s1Bytes)

    return r, s, nil
}

/*
 *| IUF - bign verification
 *
 */
func VerifyWithRS(pub *PublicKey, hashFunc Hasher, data []byte, adata []byte, r, s *big.Int) bool {
    if pub == nil || pub.Curve == nil ||
        pub.X == nil || pub.Y == nil ||
        !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return false
    }

    if s.Sign() <= 0 {
        return false
    }

    newHash := hashFunc()

    curve := pub.Curve
    curveParams := pub.Curve.Params()
    n := curveParams.N
    p := curveParams.P

    qlen := (curveParams.BitSize + 7) / 8
    plen := (p.BitLen() + 7) / 8
    hsize := newHash.Size()

    l := qlen / 2

    var tmpw []byte

    tmpw = make([]byte, l)
    r.FillBytes(tmpw)
    reverse(tmpw)
    s0 := new(big.Int).SetBytes(tmpw)

    tmpw = make([]byte, qlen)
    s.FillBytes(tmpw)
    reverse(tmpw)
    s1 := new(big.Int).SetBytes(tmpw)

    /* 1. Reject the signature if s1 >= q */
    if s1.Cmp(n) >= 0 {
        return false
    }

    /* 2. Compute h = H(m) */
    newHash.Write(data)
    hashBuf := newHash.Sum(nil)

    reverse(hashBuf)
    h := new(big.Int).SetBytes(hashBuf)
    h.Mod(h, n)

    reverse(hashBuf)

    /* Compute ((s1_bar + h_bar) mod q) */
    h.Mod(h.Add(h, s1), n)

    /* Compute (s0_bar + 2**l) mod q */
    tmp := new(big.Int).Set(one)
    tmp.Lsh(tmp, uint(8*l))
    tmp.Mod(tmp, n)
    tmp.Mod(tmp.Add(tmp, s0), n)

    /* 3. Compute ((s1_bar + h_bar) mod q) * G + ((s0_bar + 2**l) mod q) * Y. */
    x21, y21 := curve.ScalarMult(pub.X, pub.Y, tmp.Bytes())
    x22, y22 := curve.ScalarBaseMult(h.Bytes())
    x2, y2 := curve.Add(x21, y21, x22, y22)

    /* 6. Compute t = <BELT-HASH(OID(H) || <<FE2OS(W_x)> || <FE2OS(W_y)>>2*l || H(X))>l */
    beltHash := belt.New()

    oid, err := GetOidFromAdata(adata)
    if err != nil {
        return false
    }

    beltHash.Write(oid)

    FE2OS_W := make([]byte, 2*plen)
    x2.FillBytes(FE2OS_W[:plen])
    reverse(FE2OS_W[:plen])

    y2.FillBytes(FE2OS_W[plen:2*plen])
    reverse(FE2OS_W[plen:2*plen])

    /* Only hash the 2*l bytes of FE2OS(W_x) || FE2OS(W_y) */
    beltHash.Write(FE2OS_W[:2*l])

    beltHash.Write(hashBuf)

    hashBelt := beltHash.Sum(nil)

    t := make([]byte, l)
    copy(t, hashBelt[:mathMin(l, hsize)])

    rBytes := make([]byte, mathMin(l, hsize))
    r.FillBytes(rBytes)

    s0Sig := make([]byte, l)
    copy(s0Sig, rBytes)

    return bytes.Equal(t, s0Sig)
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
