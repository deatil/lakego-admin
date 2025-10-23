// Package ed448 implements the Ed448 signature algorithm defined in RFC 8032.
//
// These functions are also compatible with the “Ed448” function defined in RFC 8032.
// However, unlike RFC 8032's formulation, this package's private key representation
// includes a public key suffix to make multiple signing operations
// with the same key more efficient.
// This package refers to the RFC 8032 private key as the “seed”.
package ed448

import (
    "io"
    "bytes"
    "errors"
    "strconv"
    "crypto"
    "crypto/subtle"
    cryptorand "crypto/rand"

    "golang.org/x/crypto/sha3"

    "github.com/deatil/go-cryptobin/elliptic/edwards448"
)

const (
    // ContextMaxSize is the maximum length (in bytes) allowed for context.
    ContextMaxSize = 255
    // PublicKeySize is the size, in bytes, of public keys as used in this package.
    PublicKeySize = 57
    // PrivateKeySize is the size, in bytes, of private keys as used in this package.
    PrivateKeySize = 114
    // SignatureSize is the size, in bytes, of signatures generated and verified by this package.
    SignatureSize = 114
    // SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
    SeedSize = 57
)

// SchemeID is an identifier for each signature scheme.
type SchemeID uint

const (
    ED448 SchemeID = iota
    ED448Ph
)

// Options implements crypto.SignerOpts and augments with parameters
// that are specific to the Ed448 signature schemes.
type Options struct {
    // Hash must be crypto.Hash(0) for both Ed448 and Ed448Ph.
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

// PublicKey is the type of Ed448 public keys.
type PublicKey []byte

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(PublicKey)
    if !ok {
        return false
    }
    return bytes.Equal(pub, xx)
}

// PrivateKey is the type of Ed448 private keys.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
    publicKey := make([]byte, PublicKeySize)
    copy(publicKey, priv[57:])
    return PublicKey(publicKey)
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(PrivateKey)
    if !ok {
        return false
    }

    return subtle.ConstantTimeCompare(priv, xx) == 1
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (priv PrivateKey) Seed() []byte {
    seed := make([]byte, SeedSize)
    copy(seed, priv[:57])
    return seed
}

// Sign signs the given message with priv.
// Ed448 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to
// indicate the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) as the value for opts.
func (priv PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
    var context string
    var scheme SchemeID

    if o, ok := opts.(*Options); ok {
        context = o.Context
        scheme = o.Scheme
    }

    hash := opts.HashFunc()

    switch {
        case scheme == ED448 && hash == crypto.Hash(0):
            if l := len(context); l > ContextMaxSize {
                return nil, errors.New("go-cryptobin/ed448: bad ED448 context length: " + strconv.Itoa(l))
            }

            signature := make([]byte, SignatureSize)
            sign(signature, priv, message, domPrefixPure, context)
            return signature, nil
        case scheme == ED448Ph && hash == crypto.Hash(0):
            if l := len(context); l > ContextMaxSize {
                return nil, errors.New("go-cryptobin/ed448: bad ED448ph context length: " + strconv.Itoa(l))
            }

            signature := make([]byte, SignatureSize)
            sign(signature, priv, message, domPrefixPh, context)
            return signature, nil
    }

    return nil, errors.New("go-cryptobin/ed448: bad hash algorithm")
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
    if rand == nil {
        rand = cryptorand.Reader
    }

    seed := make([]byte, SeedSize)
    if _, err := io.ReadFull(rand, seed); err != nil {
        return nil, nil, err
    }

    privateKey := make([]byte, PrivateKeySize)
    newKeyFromSeed(privateKey, seed)

    publicKey := make([]byte, PublicKeySize)
    copy(publicKey, privateKey[57:])

    return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
    privateKey := make([]byte, PrivateKeySize)
    newKeyFromSeed(privateKey, seed)
    return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
    if l := len(seed); l != SeedSize {
        panic("go-cryptobin/ed448: bad seed length: " + strconv.Itoa(l))
    }

    h := make([]byte, 114)
    sha3.ShakeSum256(h, seed)

    s, err := edwards448.NewScalar().SetBytesWithClamping(h[:57])
    if err != nil {
        panic(err)
    }

    p := new(edwards448.Point).ScalarBaseMult(s)

    copy(privateKey, seed)
    copy(privateKey[57:], p.Bytes())
}

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not [PrivateKeySize].
func Sign(privateKey PrivateKey, message []byte) []byte {
    // Outline the function body so that the returned signature can be
    // stack-allocated.
    signature := make([]byte, SignatureSize)
    sign(signature, privateKey, message, domPrefixPure, "")
    return signature
}

const (
    // sigEd448 = domPrefix + ctxLen + ctx
    // domPrefixPure for Ed448.
    domPrefixPure = "SigEd448\x00"
    // domPrefixPh for Ed448Ph.
    domPrefixPh = "SigEd448\x01"
)

func sign(signature, privateKey, message []byte, domPre, context string) {
    var PHM []byte

    if domPre == domPrefixPh {
        hm := make([]byte, 64)
        sha3.ShakeSum256(hm, message)
        PHM = hm[:]
    } else {
        PHM = message
    }

    seed, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]

    h := make([]byte, 114)
    sha3.ShakeSum256(h, seed)
    s, err := edwards448.NewScalar().SetBytesWithClamping(h[:57])
    if err != nil {
        panic("go-cryptobin/ed448: internal error: setting scalar failed")
    }
    prefix := h[57:]

    mh := sha3.NewShake256()
    mh.Write([]byte(domPre))
    mh.Write([]byte{byte(len(context))})
    mh.Write([]byte(context))
    mh.Write(prefix)
    mh.Write(PHM)
    messageDigest := make([]byte, 114)
    mh.Read(messageDigest)
    r, err := edwards448.NewScalar().SetUniformBytes(messageDigest)
    if err != nil {
        panic("go-cryptobin/ed448: internal error: setting scalar failed")
    }

    R := new(edwards448.Point).ScalarBaseMult(r)

    kh := sha3.NewShake256()
    kh.Write([]byte(domPre))
    kh.Write([]byte{byte(len(context))})
    kh.Write([]byte(context))
    kh.Write(R.Bytes())
    kh.Write(publicKey)
    kh.Write(PHM)
    hramDigest := make([]byte, 114)
    kh.Read(hramDigest)
    k, err := edwards448.NewScalar().SetUniformBytes(hramDigest)
    if err != nil {
        panic("go-cryptobin/ed448: internal error: setting scalar failed")
    }

    S := edwards448.NewScalar().MulAdd(k, s, r)

    sb := S.Bytes()
    copy(signature[:57], R.Bytes())
    copy(signature[57:], sb[:])
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not [PublicKeySize].
func Verify(publicKey PublicKey, message, sig []byte) bool {
    return verify(publicKey, message, sig, domPrefixPure, "")
}

// VerifyWithOptions reports whether sig is a valid signature of message by
// publicKey. A valid signature is indicated by returning a nil error. It will
// panic if len(publicKey) is not [PublicKeySize].
func VerifyWithOptions(publicKey PublicKey, message, sig []byte, opts crypto.SignerOpts) error {
    var context string
    var scheme SchemeID
    if o, ok := opts.(*Options); ok {
        context = o.Context
        scheme = o.Scheme
    }

    hash := opts.HashFunc()

    switch {
        case scheme == ED448Ph && hash == crypto.Hash(0): // ED448ph
            if l := len(context); l > ContextMaxSize {
                return errors.New("go-cryptobin/ed448: bad ED448ph context length: " + strconv.Itoa(l))
            }

            if !verify(publicKey, message, sig, domPrefixPh, context) {
                return errors.New("go-cryptobin/ed448: invalid signature")
            }

            return nil
        case scheme == ED448 && hash == crypto.Hash(0): // ED448
            if l := len(context); l > ContextMaxSize {
                return errors.New("go-cryptobin/ed448: bad ED448 context length: " + strconv.Itoa(l))
            }

            if !verify(publicKey, message, sig, domPrefixPure, context) {
                return errors.New("go-cryptobin/ed448: invalid signature")
            }

            return nil
    }

    return errors.New("go-cryptobin/ed448: expected opts.Hash zero (unhashed message, for standard ED448) or SHA3-Shake256 (for ED448ph)")
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
func verify(publicKey PublicKey, message, sig []byte, domPre, context string) bool {
    if l := len(publicKey); l != PublicKeySize {
        panic("go-cryptobin/ed448: bad public key length: " + strconv.Itoa(l))
    }

    if len(sig) != SignatureSize || sig[113]&0x7F != 0 {
        return false
    }

    A, err := new(edwards448.Point).SetBytes(publicKey)
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

    kh := sha3.NewShake256()
    kh.Write([]byte(domPre))
    kh.Write([]byte{byte(len(context))})
    kh.Write([]byte(context))
    kh.Write(sig[:57])
    kh.Write(publicKey)
    kh.Write(PHM)
    hramDigest := make([]byte, 114)
    kh.Read(hramDigest)
    k, err := edwards448.NewScalar().SetUniformBytes(hramDigest)
    if err != nil {
        panic("go-cryptobin/ed448: internal error: setting scalar failed")
    }

    S, err := edwards448.NewScalar().SetCanonicalBytes(sig[57:])
    if err != nil {
        return false
    }

    minusA := new(edwards448.Point).Negate(A)
    R := new(edwards448.Point).VarTimeDoubleScalarBaseMult(k, minusA, S)
    return bytes.Equal(sig[:57], R.Bytes())
}
