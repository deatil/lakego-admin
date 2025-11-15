package kg

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

// see doc
// https://eprint.iacr.org/2023/1656

var (
    ErrInvalidCurve       = errors.New("go-cryptobin/kg: invalid curve")
    ErrInvalidK           = errors.New("go-cryptobin/kg: use another K")
    ErrInvalidPrivateKey  = errors.New("go-cryptobin/kg: invalid private key")
    ErrInvalidPublicKey   = errors.New("go-cryptobin/kg: invalid public key")
    ErrInvalidSignature   = errors.New("go-cryptobin/kg: invalid signature")
    ErrInvalidCurvesMatch = errors.New("go-cryptobin/kg: curves miss match")
    ErrSharedKeyIsZero    = errors.New("go-cryptobin/kg: shared key is zero")
    ErrInvalidASN1        = errors.New("go-cryptobin/kg: invalid ASN.1 encoding")
    ErrInvalidSignerOpts  = errors.New("go-cryptobin/kg: opts must be *SignerOpts")
)

var (
    one = big.NewInt(1)
)

type Hasher = func() hash.Hash

// SignerOpts contains options for creating
// and verifying KG signatures.
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

type PublicKey struct {
    elliptic.Curve

    X, Y  *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.X.Cmp(xx.X) == 0 &&
        pub.Y.Cmp(xx.Y) == 0 &&
        pub.Curve == xx.Curve
}

// Verify asn.1 marshal data ans1(r, s)
func (pub *PublicKey) Verify(digest, signature []byte, opts crypto.SignerOpts) bool {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return false
    }

    _, err := VerifyASN1(pub, opt.GetHash(), digest, signature)
    return err == nil
}

type PrivateKey struct {
    PublicKey

    D *big.Int
}

// The KG's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.PublicKey.Equal(&xx.PublicKey) &&
        bigIntEqual(priv.D, xx.D)
}

// sign data and return asn.1 or bytes marshal data, default asn.1
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return nil, ErrInvalidSignerOpts
    }

    return SignASN1(rand, priv, opt.GetHash(), digest)
}

func (priv *PrivateKey) ECDH(pub *PublicKey) ([]byte, error) {
    if pub == nil {
        return nil, ErrInvalidPublicKey
    }

    if priv.Curve != pub.Curve {
        return nil, ErrInvalidCurvesMatch
    }
    if !priv.Curve.IsOnCurve(pub.X, pub.Y) {
        return nil, ErrInvalidPublicKey
    }

    x, y := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

    if x.Sign() == 0 && y.Sign() == 0 {
        return nil, ErrSharedKeyIsZero
    }

    preMasterSecret := make([]byte, (priv.Curve.Params().BitSize + 7) / 8)
    xBytes := x.Bytes()
    copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

    return preMasterSecret, nil
}

// generate a private key
func GenerateKey(rand io.Reader, curve elliptic.Curve) (*PrivateKey, error) {
    if curve == nil {
        return nil, ErrInvalidCurve
    }

    k, err := randFieldElement(rand, curve)
    if err != nil {
        return nil, err
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())

    return priv, nil
}

// New a private key from key data bytes
func NewPrivateKey(curve elliptic.Curve, d []byte) (*PrivateKey, error) {
    k := new(big.Int).SetBytes(d)

    n := new(big.Int).Sub(curve.Params().N, one)
    if k.Cmp(n) >= 0 {
        return nil, errors.New("go-cryptobin/kg: privateKey's D is overflow")
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d)

    return priv, nil
}

// return PrivateKey data
func PrivateKeyTo(key *PrivateKey) []byte {
    privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
    return key.D.FillBytes(privateKey)
}

// New a PublicKey from publicKey data
func NewPublicKey(curve elliptic.Curve, data []byte) (*PublicKey, error) {
    x, y := elliptic.Unmarshal(curve, data)
    if x == nil || y == nil {
        return nil, errors.New("go-cryptobin/kg: incorrect public key")
    }

    pub := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    return pub, nil
}

// return PublicKey data
func PublicKeyTo(key *PublicKey) []byte {
    return elliptic.Marshal(key.Curve, key.X, key.Y)
}

// sign data and return asn.1 marshal data
func SignASN1(rand io.Reader, priv *PrivateKey, hashFunc Hasher, msg []byte) ([]byte, error) {
    if priv == nil {
        return nil, ErrInvalidPrivateKey
    }

    r, s, err := SignToRS(rand, priv, hashFunc, msg)
    if err != nil {
        return nil, err
    }

    return encodeSignature(r, s)
}

// Verify asn.1 marshal data
func VerifyASN1(pub *PublicKey, hashFunc Hasher, msg, signature []byte) (bool, error) {
    if pub == nil {
        return false, ErrInvalidPublicKey
    }

    r, s, err := parseSignature(signature)
    if err != nil {
        return false, ErrInvalidASN1
    }

    return VerifyWithRS(pub, hashFunc, msg, r, s)
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

/*
 * KG signature.
 */
func SignToRS(random io.Reader, priv *PrivateKey, hashFunc Hasher, msg []byte) (r, s *big.Int, err error) {
    var k *big.Int

Retry:
    k, err = randFieldElement(random, priv.Curve)
    if err != nil {
        return nil, nil, err
    }

    r, s, err = SignUsingKToRS(k, priv, hashFunc, msg)
    if err == ErrInvalidK {
        goto Retry
    }

    return
}

/*
 *| IUF - KG signature
 */
func SignUsingKToRS(k *big.Int, priv *PrivateKey, hashFunc Hasher, msg []byte) (r, s *big.Int, err error) {
    if priv == nil {
        return nil, nil, ErrInvalidPrivateKey
    }

    curve := priv.Curve
    N := curve.Params().N

    // digest = h(msg)
    h := hashFunc()
    h.Write(msg)
    digest := h.Sum(nil)

    // Hash message
    hash := formatMessage(digest, (N.BitLen()+7)/8)
    e := new(big.Int).SetBytes(hash)
    e.Mod(e, N)

    // Compute r = (k * G).x mod N
    rx, _ := curve.ScalarBaseMult(k.Bytes())
    r = new(big.Int).Mod(rx, N)

    if r.Sign() == 0 {
        return nil, nil, ErrInvalidK
    }

    // Compute s = k⁻¹ * (hash + r * privKey) mod N
    invK := new(big.Int).ModInverse(k, N)

    // rp = r * privKey
    rp := new(big.Int).Mul(r, priv.D)
    rp.Mod(rp, N)

    // rp = rp + e
    rp.Add(rp, e)
    rp.Mod(rp, N)

    // s = k⁻¹ * (e + r * privKey)
    s = new(big.Int).Mul(invK, rp)
    s.Mod(s, N)

    if s.Sign() == 0 {
        return nil, nil, ErrInvalidK
    }

    return
}

/*
 *| IUF - KG verification
 */
func VerifyWithRS(pub *PublicKey, hashFunc Hasher, msg []byte, r, s *big.Int) (bool, error) {
    if pub == nil {
        return false, ErrInvalidPublicKey
    }

    curve := pub.Curve
    N := curve.Params().N

    if r.Sign() <= 0 || r.Cmp(N) >= 0 {
        return false, ErrInvalidSignature
    }
    if s.Sign() <= 0 || s.Cmp(N) >= 0 {
        return false, ErrInvalidSignature
    }

    if !curve.IsOnCurve(pub.X, pub.Y) {
        return false, ErrInvalidPublicKey
    }

    // digest = h(msg)
    h := hashFunc()
    h.Write(msg)
    digest := h.Sum(nil)

    hash := formatMessage(digest, (N.BitLen()+7)/8)
    e := new(big.Int).SetBytes(hash)
    e.Mod(e, N)

    // Compute w = s⁻¹ mod N
    w := new(big.Int).ModInverse(s, N)
    if w == nil {
        return false, ErrInvalidSignature
    }

    // Compute u1 = e * w mod N
    u1 := new(big.Int).Mul(e, w)
    u1.Mod(u1, N)

    // Compute u2 = r * w mod N
    u2 := new(big.Int).Mul(r, w)
    u2.Mod(u2, N)

    // Compute r' = u1 * G + u2 * Q
    x1, y1 := curve.ScalarBaseMult(u1.Bytes())
    x2, y2 := curve.ScalarMult(pub.X, pub.Y, u2.Bytes())
    x, y := curve.Add(x1, y1, x2, y2)

    if x.Sign() == 0 && y.Sign() == 0 {
        return false, ErrInvalidSignature
    }

    xx := new(big.Int).Mod(x, N)

    if xx.Cmp(r) != 0 {
        return false, ErrInvalidSignature
    }

    return true, nil
}

// format message
func formatMessage(message []byte, size int) []byte {
    mb := new(big.Int)
    for _, b := range message {
        mb.Lsh(mb, 8)
        mb.Add(mb, big.NewInt(int64(b)))
    }

    mbBytes := mb.Bytes()

    result := make([]byte, size)
    if len(mbBytes) > size {
        copy(result, mbBytes[:size])
    } else {
        copy(result[size-len(mbBytes):], mbBytes)
    }

    return result
}

func randFieldElement(rand io.Reader, curve elliptic.Curve) (k *big.Int, err error) {
    N := curve.Params().N
    bitSize := N.BitLen()
    byteSize := (bitSize + 7) / 8

    for {
        bytes := make([]byte, byteSize)
        if _, err = io.ReadFull(rand, bytes); err != nil {
            return nil, err
        }

        if excess := len(bytes)*8 - bitSize; excess > 0 {
            bytes[0] >>= excess
        }

        k = new(big.Int).SetBytes(bytes)
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
