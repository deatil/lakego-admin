package bip0340

import (
    "io"
    "hash"
    "errors"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/elliptic"

    "golang.org/x/crypto/cryptobyte"
    "golang.org/x/crypto/cryptobyte/asn1"
)

const BIP0340_AUX       = "BIP0340/aux"
const BIP0340_NONCE     = "BIP0340/nonce"
const BIP0340_CHALLENGE = "BIP0340/challenge"

var (
    ErrPrivateKey         = errors.New("go-cryptobin/bip0340: invalid PrivateKey")
    ErrParametersNotSetUp = errors.New("go-cryptobin/bip0340: parameters not set up before generating key")
    ErrInvalidASN1        = errors.New("go-cryptobin/bip0340: invalid ASN.1")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/bip0340: opts must be *SignerOpts")
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

// Schnorr Signatures for secp256k1
// bip0340 PublicKey
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

// bip0340 PrivateKey
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
        return nil, errors.New("cryptobin/bip0340: privateKey's D is overflow")
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
        return nil, errors.New("cryptobin/bip0340: incorrect public key")
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

    sig = make([]byte, plen + qlen)

    r.FillBytes(sig[:plen])
    s.FillBytes(sig[plen:])

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, h Hasher, data, sig []byte) bool {
    curveParams := pub.Curve.Params()
    p := curveParams.P

    plen := (p.BitLen() + 7) / 8
    qlen := (curveParams.BitSize + 7) / 8

    if len(sig) != plen + qlen {
        return false
    }

    r := new(big.Int).SetBytes(sig[:plen])
    s := new(big.Int).SetBytes(sig[plen:])

    return VerifyWithRS(pub, h, data, r, s)
}

/*
 * BIP0340 signature.
 * NOTE: because of the semi-deterministinc nonce generation
 * process, streaming mode is NOT supported for signing.
 * Hence the following all-in-one signature function.
 */
func SignToRS(random io.Reader, priv *PrivateKey, hashFunc Hasher, msg []byte) (r, s *big.Int, err error) {
    curveParams := priv.Curve.Params()

    qlen := (curveParams.BitSize + 7) / 8

    e := new(big.Int).Set(one)
    e.Lsh(e, 8 * uint(qlen))

    k, err := rand.Int(random, e)
    if err != nil {
        return
    }

    return SignUsingKToRS(k, priv, hashFunc, msg)
}

// sign with k
func SignUsingKToRS(k *big.Int, priv *PrivateKey, hashFunc Hasher, msg []byte) (r, s *big.Int, err error) {
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

    qlen := (curveParams.BitSize + 7) / 8
    plen := (p.BitLen() + 7) / 8
    hsize := h.Size()

    d := new(big.Int).Set(priv.D)

    px, py := curve.ScalarBaseMult(priv.D.Bytes())

    /* Fail if d = 0 or d >= q */
    if d.Cmp(zero) == 0 || d.Cmp(n) >= 0 {
        return nil, nil, ErrPrivateKey
    }

    /* Adjust d depending on public key y */
    bip0340SetScalar(d, n, py)

Retry:
    sig := make([]byte, qlen)
    k.FillBytes(sig)

    bip0340Hash([]byte(BIP0340_AUX), sig, h)

    buff := h.Sum(nil)

    d.FillBytes(sig)

    if qlen > hsize {
        for i := 0; i < hsize; i++ {
            sig[i] ^= buff[i]
        }

        bip0340Hash([]byte(BIP0340_NONCE), sig, h)
    } else {
        for i := 0; i < qlen; i++ {
            buff[i] ^= sig[i]
        }

        bip0340Hash([]byte(BIP0340_NONCE), buff, h)
    }

    sig = make([]byte, plen)
    px.FillBytes(sig)

    h.Write(sig)
    h.Write(msg)
    buff = h.Sum(nil)

    k = new(big.Int).SetBytes(buff)
    k.Mod(k, n)

    if k.Cmp(zero) == 0 {
        goto Retry
    }

    kGx, kGy := curve.ScalarBaseMult(k.Bytes())

    /* Update k depending on the kG y coordinate */
    bip0340SetScalar(k, n, kGy)

    sig = make([]byte, plen)
    kGx.FillBytes(sig)

    bip0340Hash([]byte(BIP0340_CHALLENGE), sig, h)

    /* Export our public key */
    sig = make([]byte, plen)
    px.FillBytes(sig)

    h.Write(sig)
    h.Write(msg)
    buff = h.Sum(nil)

    e := new(big.Int).SetBytes(buff)
    e.Mod(e, n)

    /* Export our r in the signature */
    r = new(big.Int).Set(kGx)

    e.Mod(e.Mul(e, d), n)
    e.Mod(e.Add(k, e), n)

    /* Export our s in the signature */
    s = new(big.Int).Set(e)

    return r, s, nil
}

/*
 * BIP0340 verification functions.
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

    sig := make([]byte, plen)
    r.FillBytes(sig)

    bip0340Hash([]byte(BIP0340_CHALLENGE), sig, h)

    Pubx := make([]byte, plen)
    pub.X.FillBytes(Pubx)

    h.Write(Pubx)
    h.Write(data)
    eBuf := h.Sum(nil)

    e := new(big.Int).SetBytes(eBuf)
    e.Mod(e, n)

    /* compute -e = (q - e) mod q */
    e.Mod(e.Neg(e), n)

    YY := new(big.Int).Set(pub.Y)

    if bigintIsodd(YY) {
        YY.Mod(YY.Neg(YY), p)
    }

    /* Compute sG - eY */
    x21, y21 := curve.ScalarMult(pub.X, YY, e.Bytes())
    x22, y22 := curve.ScalarBaseMult(s.Bytes())
    x2, y2 := curve.Add(x21, y21, x22, y22)

    /* Reject point at infinity */
    if x2.Cmp(zero) == 0 || y2.Cmp(zero) == 0 {
        return false
    }

    /* Reject non even Y coordinate */
    if bigintIsodd(y2) {
        return false
    }

    return r.Cmp(x2) == 0
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
