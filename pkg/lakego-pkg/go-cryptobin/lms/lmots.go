package lms

import (
    "io"
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
)

// Signer Opts
type LmotsSignerOpts struct {
    C []byte
}

func (this LmotsSignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// default Signer Opts
var DefaultLmotsSignerOpts = LmotsSignerOpts{}

// A LmotsPrivateKey is used to sign exactly one message.
type LmotsPrivateKey struct {
    LmotsPublicKey
    x     [][]byte
    valid bool
}

// NewLmotsPrivateKey returns a LmotsPrivateKey, seeded by a cryptographically secure
// random number generator.
func NewLmotsPrivateKey(lop ILmotsParam, q uint32, id ID) (*LmotsPrivateKey, error) {
    params := lop.Params()

    seed := make([]byte, params.N)
    _, err := rand.Read(seed)
    if err != nil {
        return nil, err
    }

    return NewLmotsPrivateKeyFromSeed(lop, q, id, seed)
}

// NewLmotsPrivateKeyFromSeed returns a new LmotsPrivateKey, using the algorithm from
// Appendix A of <https://datatracker.ietf.org/doc/html/rfc8554#appendix-A>
func NewLmotsPrivateKeyFromSeed(lop ILmotsParam, q uint32, id ID, seed []byte) (*LmotsPrivateKey, error) {
    params := lop.Params()

    x := make([][]byte, params.P)

    for i := uint64(0); i < params.P; i++ {
        var q_be [4]byte
        var i_be [2]byte

        putu32(q_be[:], q)
        putu16(i_be[:], uint16(i))

        hasher := params.Hash()
        hasher.Write(id[:])
        hasher.Write(q_be[:])
        hasher.Write(i_be[:])
        hasher.Write([]byte{0xff})
        hasher.Write(seed)

        x[i] = hasher.Sum(nil)
    }

    pk := LmotsPrivateKey{
        LmotsPublicKey: LmotsPublicKey{
            typ: lop,
            q:   q,
            id:  id,
        },
        x:     x,
        valid: true,
    }
    pk.LmotsPublicKey.k = pk.computeRoot()

    return &pk, nil
}

// Equal reports whether priv and x have the same value.
func (priv *LmotsPrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*LmotsPrivateKey)
    if !ok {
        return false
    }

    var checkX = func(x1, x2 [][]byte) bool {
        if len(x1) != len(x2) {
            return false
        }

        for i := 0; i < len(x1); i++ {
            if subtle.ConstantTimeCompare(x1[i], x2[i]) != 1 {
                return false
            }
        }

        return true
    }

    return priv.LmotsPublicKey.Equal(&xx.LmotsPublicKey) &&
        checkX(priv.x, xx.x) &&
        priv.valid == xx.valid
}

// Public returns a crypto.PublicKey that validates signatures for this private key.
func (priv *LmotsPrivateKey) Public() crypto.PublicKey {
    return priv.LmotsPublicKey
}

// PublicKey returns a LmotsPublicKey that validates signatures for this private key.
func (priv *LmotsPrivateKey) PublicKey() LmotsPublicKey {
    return priv.LmotsPublicKey
}

// Sign calculates the LM-OTS signature of a chosen message.
func (priv *LmotsPrivateKey) Sign(rng io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    sig, err := priv.SignToSignature(rng, msg, opts)
    if err != nil {
        return nil, err
    }

    return sig.ToBytes()
}

// SignToSignature calculates the LM-OTS signature of a chosen message.
func (priv *LmotsPrivateKey) SignToSignature(rng io.Reader, msg []byte, opts crypto.SignerOpts) (*LmotsSignature, error) {
    if !priv.valid {
        return nil, errors.New("lms: invalid private key")
    }

    var err error
    var be16 [2]byte
    var be32 [4]byte

    params := priv.typ.Params()

    opt := DefaultLmotsSignerOpts
    if o, ok := opts.(LmotsSignerOpts); ok {
        opt = o
    }

    c := opt.C
    if c == nil {
        c = make([]byte, params.N)
        if _, err := rng.Read(c); err != nil {
            return nil, err
        }
    }

    putu32(be32[:], priv.q)

    hasher := params.Hash()
    hasher.Write(priv.id[:])
    hasher.Write(be32[:])
    hasher.Write(D_MESG[:])
    hasher.Write(c)
    hasher.Write(msg)

    q := hasher.Sum(nil)
    expanded, err := Expand(q, priv.typ)
    if err != nil {
        return nil, err
    }

    y := make([][]byte, params.P)

    for i := uint64(0); i < params.P; i++ {
        a := uint64(expanded[i])
        y[i] = make([]byte, len(priv.x[i]))
        copy(y[i], priv.x[i])

        for j := uint64(0); j < a; j++ {
            putu32(be32[:], priv.q)
            putu16(be16[:], uint16(i))

            inner := params.Hash()
            inner.Write(priv.id[:])
            inner.Write(be32[:])
            inner.Write(be16[:])
            inner.Write([]byte{byte(j)})
            inner.Write(y[i])

            y[i] = inner.Sum(nil)
        }
    }

    // mark private key as invalid
    priv.x = nil
    priv.valid = false

    return &LmotsSignature{
        typ: priv.typ,
        c:   c,
        y:   y,
    }, nil
}

func (priv *LmotsPrivateKey) computeRoot() []byte {
    var be16 [2]byte
    var be32 [4]byte
    var tmp []byte

    params := priv.typ.Params()

    putu32(be32[:], priv.q)

    hasher := params.Hash()
    hasher.Write(priv.id[:])
    hasher.Write(be32[:])
    hasher.Write(D_PBLC[:])

    for i := uint64(0); i < params.P; i++ {
        tmp = make([]byte, len(priv.x[i]))
        copy(tmp, priv.x[i])

        for j := uint64(0); j < (uint64(1)<<int(params.W.Window()))-1; j++ {
            putu32(be32[:], priv.q)
            putu16(be16[:], uint16(i))

            inner := params.Hash()
            inner.Write(priv.id[:])
            inner.Write(be32[:])
            inner.Write(be16[:])
            inner.Write([]byte{byte(j)})
            inner.Write(tmp)

            tmp = inner.Sum(nil)
        }

        hasher.Write(tmp)
    }

    root := hasher.Sum(nil)

    return root
}

// A LmotsPublicKey is used to verify exactly one message.
type LmotsPublicKey struct {
    typ ILmotsParam
    q   uint32
    id  ID
    k   []byte
}

// Equal reports whether pub and x have the same value.
func (pub *LmotsPublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*LmotsPublicKey)
    if !ok {
        return false
    }

    return pub.typ.GetType() == xx.typ.GetType() &&
        pub.q == xx.q &&
        subtle.ConstantTimeCompare(pub.id[:], xx.id[:]) == 1 &&
        subtle.ConstantTimeCompare(pub.k, xx.k) == 1
}

// Verify returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *LmotsPublicKey) Verify(msg []byte, sig []byte) bool {
    newSig, err := NewLmotsSignatureFromBytes(sig)
    if err != nil {
        return false
    }

    return pub.VerifyWithSignature(msg, newSig)
}

// VerifyWithSignature returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *LmotsPublicKey) VerifyWithSignature(msg []byte, sig *LmotsSignature) bool {
    // sanity check ots type
    if pub.typ.GetType() != sig.typ.GetType() {
        return false
    }

    // try to recover the public key
    kc, valid := sig.RecoverPublicKey(msg, pub.id, pub.q)

    // this short circuits if valid == false and does the key comparison otherwise
    return valid && subtle.ConstantTimeCompare(pub.k, kc.k) == 1
}

// RecoverPublicKey calculates the public key for a given message.
// This is used in signature verification.
func (sig *LmotsSignature) RecoverPublicKey(msg []byte, id ID, q uint32) (LmotsPublicKey, bool) {
    var be16 [2]byte
    var be32 [4]byte
    var tmp []byte

    params := sig.typ.Params()

    hasher := params.Hash()
    hash_len := hasher.Size()

    // verify length of nonce
    if len(sig.c) != hash_len {
        return LmotsPublicKey{}, false
    }

    // verify length of y and y[i]
    if uint64(len(sig.y)) != params.P {
        return LmotsPublicKey{}, false
    }

    for i := uint64(0); i < params.P; i++ {
        if len(sig.y[i]) != hash_len {
            return LmotsPublicKey{}, false
        }
    }

    putu32(be32[:], q)

    hasher.Write(id[:])
    hasher.Write(be32[:])
    hasher.Write(D_MESG[:])
    hasher.Write(sig.c)
    hasher.Write(msg)

    Q := hasher.Sum(nil)
    expanded, err := Expand(Q, sig.typ)
    if err != nil {
        return LmotsPublicKey{}, false
    }

    hasher.Reset()
    hasher.Write(id[:])
    hasher.Write(be32[:])
    hasher.Write(D_PBLC[:])

    for i := uint64(0); i < params.P; i++ {
        a := uint64(expanded[i])
        tmp = make([]byte, len(sig.y[i]))
        copy(tmp, sig.y[i])

        for j := uint64(a); j < (uint64(1)<<int(params.W.Window()))-1; j++ {
            putu32(be32[:], q)
            putu16(be16[:], uint16(i))

            inner := params.Hash()
            inner.Write(id[:])
            inner.Write(be32[:])
            inner.Write(be16[:])
            inner.Write([]byte{byte(j)})
            inner.Write(tmp)

            tmp = inner.Sum(nil)
        }

        hasher.Write(tmp)
    }

    return LmotsPublicKey{
        typ: sig.typ,
        q:   q,
        id:  id,
        k:   hasher.Sum(nil),
    }, true
}

// Key returns a copy of the public key's k parameter.
// We need this to get the public key as bytes in order to hash
func (pub *LmotsPublicKey) Key() []byte {
    return pub.k[:]
}

// NewLmotsPublicKeyFromBytes returns an LmotsPublicKey that represents b.
// This is the inverse of the ToBytes() method on the LmotsPublicKey object.
func NewLmotsPublicKeyFromBytes(b []byte) (*LmotsPublicKey, error) {
    if len(b) < 4 {
        return nil, errors.New("lms: OTS public key too short")
    }

    // The typecode is bytes 0-3 (4 bytes)
    newType, err := GetLmotsParam(LmotsType(getu32(b[0:4])))
    if err != nil {
        return nil, err
    }

    typecode := newType()

    params := typecode.Params()

    // ensure that the length of the slice is correct
    if uint64(len(b)) < 4+ID_LEN+4+params.N {
        return nil, errors.New("lms: OTS public key too short")
    } else if uint64(len(b)) > 4+ID_LEN+4+params.N {
        return nil, errors.New("lms: OTS public key too long")
    } else {
        // The next ID_LEN bytes are the id
        id := ID(b[4 : 4+ID_LEN])

        // the next 4 bytes is the internal counter q
        q := getu32(b[4+ID_LEN : 8+ID_LEN])

        // The public key, k, is the remaining bytes
        k := b[8+ID_LEN:]

        pub := LmotsPublicKey{
            typ: typecode,
            id:  id,
            q:   q,
            k:   k,
        }

        return &pub, nil
    }
}

// ToBytes() serializes the public key into a byte string for transmission or storage.
func (pub *LmotsPublicKey) ToBytes() []byte {
    var serialized []byte
    var u32_be [4]byte

    // First 4 bytes: typecode
    typecode := pub.typ.GetType()

    // This will never error if we have a valid LmotsPublicKey
    putu32(u32_be[:], uint32(typecode))
    serialized = append(serialized, u32_be[:]...)

    // Next 16 bytes: id
    serialized = append(serialized, pub.id[:]...)

    // Next 4 bytes: q
    putu32(u32_be[:], pub.q)
    serialized = append(serialized, u32_be[:]...)

    // Followed by the public key, k
    serialized = append(serialized, pub.k[:]...)

    return serialized
}

// A LmotsSignature is a signature of one message.
type LmotsSignature struct {
    typ ILmotsParam
    c   []byte
    y   [][]byte
}

// NewLmotsSignatureFromBytes returns an LmotsSignature represented by b.
func NewLmotsSignatureFromBytes(b []byte) (*LmotsSignature, error) {
    if len(b) < 4 {
        return nil, errors.New("lms: No typecode")
    }

    // Typecode is the first 4 bytes
    newType, err := GetLmotsParam(LmotsType(getu32(b[0:4])))
    if err != nil {
        return nil, err
    }

    typecode := newType()

    // Panic if not a valid LM-OTS algorithm:
    params := typecode.Params()

    sigLen := params.SigLength()

    // check the length of the signature
    if uint64(len(b)) < sigLen {
        return nil, errors.New("lms: LMOTS signature too short")
    } else if uint64(len(b)) > sigLen {
        return nil, errors.New("lms: LMOTS signature too long")
    } else {
        // parse the signature
        c := b[4 : 4+int(params.N)]
        cur := uint64(4 + params.N)

        y := make([][]byte, params.P)
        for i := uint64(0); i < params.P; i++ {
            y[i] = b[cur : cur+params.N]
            cur += params.N
        }

        return &LmotsSignature{
            typ: typecode,
            c:   c,
            y:   y,
        }, nil
    }
}

// ToBytes() serializes the LM-OTS signature into a byte string for transmission or storage.
func (sig *LmotsSignature) ToBytes() ([]byte, error) {
    var serialized []byte
    var u32_be [4]byte

    params := sig.typ.Params()

    // First 4 bytes: LMOTS typecode
    typecode := sig.typ.GetType()

    putu32(u32_be[:], uint32(typecode))
    serialized = append(serialized, u32_be[:]...)

    // Next H bytes: nonce C
    serialized = append(serialized, sig.c...)

    // Next P * H bytes: y[0] ... y[p-1]
    for i := uint64(0); i < params.P; i++ {
        serialized = append(serialized, sig.y[i]...)
    }

    return serialized, nil
}

// C returns a bytes for c
func (sig *LmotsSignature) C() []byte {
    return sig.c
}
