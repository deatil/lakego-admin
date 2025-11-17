package ed521

import (
    "io"
    "errors"
    "strconv"
    "math/big"
    "crypto"
    "crypto/subtle"
    "crypto/elliptic"

    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/cryptobyte"
    "golang.org/x/crypto/cryptobyte/asn1"

    "github.com/deatil/go-cryptobin/elliptic/e521"
)

var (
    ErrInvalidASN1 = errors.New("go-cryptobin/ed521: invalid ASN.1 encoding")
)

var (
    one = big.NewInt(1)
)

const (
    // ContextMaxSize is the maximum length (in bytes) allowed for context.
    ContextMaxSize = 255
    // SeedSize is the size, in bytes, of private key seeds.
    SeedSize = 66
)

// SchemeID is an identifier for each signature scheme.
type SchemeID uint

const (
    ED521 SchemeID = iota
    ED521Ph
)

// Options implements crypto.SignerOpts and augments with parameters
// that are specific to the Ed521 signature schemes.
type Options struct {
    // Hash must be crypto.Hash(0) for both Ed521 and Ed521Ph.
    Hash crypto.Hash

    // Context is an optional domain separation string for signing.
    // Its length must be less or equal than 255 bytes.
    Context string

    // Scheme is an identifier for choosing a signature scheme.
    Scheme SchemeID
}

// HashFunc returns o.Hash.
func (o *Options) HashFunc() crypto.Hash {
    return o.Hash
}

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

    return pub.X.Cmp(xx.X) == 0 &&
        pub.Y.Cmp(xx.Y) == 0 &&
        pub.Curve == xx.Curve
}

// Verify verifies the signature of message for a given public key
func (pub *PublicKey) Verify(message, sig []byte) bool {
    return verify(pub, message, sig, domPrefixPure, "")
}

type PrivateKey struct {
    PublicKey

    D *big.Int
}

// Public returns the public key corresponding to priv.
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

// Sign creates a signature for message
func (priv *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
    var context string
    var scheme SchemeID
    var hash crypto.Hash

    if opts != nil {
        hash = opts.HashFunc()
    }

    if o, ok := opts.(*Options); ok {
        context = o.Context
        scheme = o.Scheme
    }

    switch {
        case scheme == ED521 && hash == crypto.Hash(0):
            if l := len(context); l > ContextMaxSize {
                return nil, errors.New("go-cryptobin/ed521: bad ED521 context length: " + strconv.Itoa(l))
            }

            return sign(priv, message, domPrefixPure, context)
        case scheme == ED521Ph && hash == crypto.Hash(0):
            if l := len(context); l > ContextMaxSize {
                return nil, errors.New("go-cryptobin/ed521: bad ED521ph context length: " + strconv.Itoa(l))
            }

            return sign(priv, message, domPrefixPh, context)
    }

    return nil, errors.New("go-cryptobin/ed521: bad hash algorithm")
}

// GenerateKey returns Ed521 PrivateKey
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
    curve := e521.E521()

    k, err := randFieldElement(rand, curve)
    if err != nil {
        return nil, err
    }

    return newKeyFromSeed(k.Bytes())
}

func newKeyFromSeed(seed []byte) (*PrivateKey, error) {
    if l := len(seed); l > SeedSize {
        panic("go-cryptobin/ed521: bad seed length: " + strconv.Itoa(l))
    }

    curve := e521.E521()

    k := new(big.Int).SetBytes(seed)

    n := new(big.Int).Sub(curve.Params().N, one)
    if k.Cmp(n) >= 0 {
        return nil, errors.New("go-cryptobin/ed521: privateKey's seed is overflow")
    }

    h := make([]byte, 132)
    sha3.ShakeSum256(h, k.Bytes())

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(h[:66])

    return priv, nil
}

// New a private key from key data bytes
func NewPrivateKey(d []byte) (*PrivateKey, error) {
    return newKeyFromSeed(d)
}

// return PrivateKey data
func PrivateKeyTo(key *PrivateKey) []byte {
    privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
    return key.D.FillBytes(privateKey)
}

// New a PublicKey from publicKey data
func NewPublicKey(data []byte) (*PublicKey, error) {
    curve := e521.E521()

    x, y := elliptic.Unmarshal(curve, data)
    if x == nil || y == nil {
        return nil, errors.New("go-cryptobin/ed521: incorrect public key")
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
    return e521.Marshal(key.Curve, key.X, key.Y)
}

// sign data and return marshal plain data
func Sign(rand io.Reader, priv *PrivateKey, msg []byte) ([]byte, error) {
    if priv == nil {
        return nil, errors.New("go-cryptobin/ed521: invalid private key")
    }

    return sign(priv, msg, domPrefixPure, "")
}

// Verify marshaled plain data
func Verify(pub *PublicKey, msg, signature []byte) (bool, error) {
    if pub == nil {
        return false, errors.New("go-cryptobin/ed521: invalid public key")
    }

    return verify(pub, msg, signature, domPrefixPure, ""), nil
}

const (
    // sigEd521 = domPrefix + ctxLen + ctx
    // domPrefixPure for Ed521.
    domPrefixPure = "SigEd521\x00"
    // domPrefixPh for Ed521Ph.
    domPrefixPh = "SigEd521\x01"
)

// sign logic from ed448, message hash used Shake256
func sign(privateKey *PrivateKey, message []byte, domPre, context string) ([]byte, error) {
    var PHM []byte

    if domPre == domPrefixPh {
        hm := make([]byte, 64)
        sha3.ShakeSum256(hm, message)
        PHM = hm[:]
    } else {
        PHM = message
    }

    n := privateKey.Curve.Params().N

    seed := privateKey.D.Bytes()
    publicKey := e521.MarshalCompressed(privateKey.Curve, privateKey.X, privateKey.Y)

    h := make([]byte, 132)
    sha3.ShakeSum256(h, seed)

    s := new(big.Int).SetBytes(h[:66])
    s.Mod(s, n)

    prefix := h[66:]

    mh := sha3.NewShake256()
    mh.Write([]byte(domPre))
    mh.Write([]byte{byte(len(context))})
    mh.Write([]byte(context))
    mh.Write(prefix)
    mh.Write(PHM)
    messageDigest := make([]byte, 132)
    mh.Read(messageDigest)

    r := new(big.Int).SetBytes(messageDigest)
    r.Mod(r, n)

    _, R := privateKey.Curve.ScalarBaseMult(r.Bytes())

    kh := sha3.NewShake256()
    kh.Write([]byte(domPre))
    kh.Write([]byte{byte(len(context))})
    kh.Write([]byte(context))
    kh.Write(R.Bytes())
    kh.Write(publicKey)
    kh.Write(PHM)
    hramDigest := make([]byte, 132)
    kh.Read(hramDigest)

    k := new(big.Int).SetBytes(hramDigest)
    k.Mod(k, n)

    // S := k * s + r
    S := new(big.Int).Mul(k, s)
    S.Add(S, r)
    S.Mod(S, n)

    return encodeSignature(R, S)
}

// VerifyWithOptions reports whether sig is a valid signature of message by
// publicKey.
func VerifyWithOptions(publicKey *PublicKey, message, sig []byte, opts crypto.SignerOpts) error {
    var context string
    var scheme SchemeID
    if o, ok := opts.(*Options); ok {
        context = o.Context
        scheme = o.Scheme
    }

    hash := opts.HashFunc()

    switch {
        case scheme == ED521Ph && hash == crypto.Hash(0): // ED521ph
            if l := len(context); l > ContextMaxSize {
                return errors.New("go-cryptobin/ed521: bad ED521ph context length: " + strconv.Itoa(l))
            }

            if !verify(publicKey, message, sig, domPrefixPh, context) {
                return errors.New("go-cryptobin/ed521: invalid signature")
            }

            return nil
        case scheme == ED521 && hash == crypto.Hash(0): // ED521
            if l := len(context); l > ContextMaxSize {
                return errors.New("go-cryptobin/ed521: bad ED521 context length: " + strconv.Itoa(l))
            }

            if !verify(publicKey, message, sig, domPrefixPure, context) {
                return errors.New("go-cryptobin/ed521: invalid signature")
            }

            return nil
    }

    return errors.New("go-cryptobin/ed521: expected opts.Hash zero (unhashed message, for standard ED521) or SHA3-Shake256 (for ED521ph)")
}

// Verify reports whether sig is a valid signature of message by publicKey.
func verify(publicKey *PublicKey, message, sig []byte, domPre, context string) bool {
    R, S, err := parseSignature(sig)
    if err != nil {
        return false
    }

    var PHM []byte

    if domPre == domPrefixPh {
        h := make([]byte, 64)
        sha3.ShakeSum256(h, message)
        PHM = h[:]
    } else {
        PHM = message
    }

    curve := publicKey.Curve
    n := curve.Params().N

    publicKeyBytes := e521.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y)

    kh := sha3.NewShake256()
    kh.Write([]byte(domPre))
    kh.Write([]byte{byte(len(context))})
    kh.Write([]byte(context))
    kh.Write(R.Bytes())
    kh.Write(publicKeyBytes)
    kh.Write(PHM)
    hramDigest := make([]byte, 132)
    kh.Read(hramDigest)

    k := new(big.Int).SetBytes(hramDigest)
    k.Mod(k, n)

    k.Mod(k.Neg(k), n)

    // r = S - k * pri
    x21, y21 := curve.ScalarMult(publicKey.X, publicKey.Y, k.Bytes())
    x22, y22 := curve.ScalarBaseMult(S.Bytes())
    _, y2 := curve.Add(x21, y21, x22, y22)

    return bigIntEqual(R, y2)
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
        err = ErrInvalidASN1
        return
    }

    return
}

func randFieldElement(rand io.Reader, curve elliptic.Curve) (*big.Int, error) {
    N := curve.Params().N

    byteLen := (N.BitLen() + 7) / 8
    bytes := make([]byte, byteLen)

    for {
        _, err := io.ReadFull(rand, bytes)
        if err != nil {
            return nil, err
        }

        num := new(big.Int).SetBytes(bytes)
        if num.Cmp(N) < 0 {
            return num, nil
        }
    }
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
