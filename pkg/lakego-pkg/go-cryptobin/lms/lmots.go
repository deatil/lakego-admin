package lms

import (
    "io"
    "errors"
    "crypto/rand"
    "crypto/subtle"
    "encoding/binary"
)

// A LmsOtsPrivateKey is used to sign exactly one message.
type LmsOtsPrivateKey struct {
    LmsOtsPublicKey
    x     [][]byte
    valid bool
}

// NewLmsOtsPrivateKey returns a LmsOtsPrivateKey, seeded by a cryptographically secure
// random number generator.
func NewLmsOtsPrivateKey(lop ILmotsParam, q uint32, id ID) (LmsOtsPrivateKey, error) {
    params := lop.Params()

    seed := make([]byte, params.N)
    _, err := rand.Read(seed)
    if err != nil {
        return LmsOtsPrivateKey{}, err
    }

    return NewLmsOtsPrivateKeyFromSeed(lop, q, id, seed)
}

// NewLmsOtsPrivateKeyFromSeed returns a new LmsOtsPrivateKey, using the algorithm from
// Appendix A of <https://datatracker.ietf.org/doc/html/rfc8554#appendix-A>
func NewLmsOtsPrivateKeyFromSeed(lop ILmotsParam, q uint32, id ID, seed []byte) (LmsOtsPrivateKey, error) {
    params := lop.Params()

    x := make([][]byte, params.P)

    for i := uint64(0); i < params.P; i++ {
        var q_be [4]byte
        var i_be [2]byte

        binary.BigEndian.PutUint32(q_be[:], q)
        binary.BigEndian.PutUint16(i_be[:], uint16(i))

        hasher := params.Hash()
        hasher.Write(id[:])
        hasher.Write(q_be[:])
        hasher.Write(i_be[:])
        hasher.Write([]byte{0xff})
        hasher.Write(seed)

        x[i] = hasher.Sum(nil)
    }

    pk := LmsOtsPrivateKey{
        LmsOtsPublicKey: LmsOtsPublicKey{
            typ: lop,
            q:   q,
            id:  id,
        },
        x:     x,
        valid: true,
    }
    pk.LmsOtsPublicKey.k = pk.computeRoot()

    return pk, nil
}

// Public returns an LmsOtsPublicKey that validates signatures for this private key.
func (x *LmsOtsPrivateKey) Public() LmsOtsPublicKey {
    return x.LmsOtsPublicKey
}

// Sign calculates the LM-OTS signature of a chosen message.
func (x *LmsOtsPrivateKey) Sign(rng io.Reader, msg []byte) (LmsOtsSignature, error) {
    params := x.typ.Params()

    c := make([]byte, params.N)
    if _, err := rng.Read(c); err != nil {
        return LmsOtsSignature{}, err
    }

    return x.SignWithData(c, msg)
}

func (x *LmsOtsPrivateKey) SignWithData(c []byte, msg []byte) (LmsOtsSignature, error) {
    if !x.valid {
        return LmsOtsSignature{}, errors.New("Sign(): invalid private key")
    }

    var err error
    var be16 [2]byte
    var be32 [4]byte

    params := x.typ.Params()

    binary.BigEndian.PutUint32(be32[:], x.q)

    hasher := params.Hash()
    hasher.Write(x.id[:])
    hasher.Write(be32[:])
    hasher.Write(D_MESG[:])
    hasher.Write(c)
    hasher.Write(msg)

    q := hasher.Sum(nil)
    expanded, err := Expand(q, x.typ)
    if err != nil {
        return LmsOtsSignature{}, err
    }

    y := make([][]byte, params.P)

    for i := uint64(0); i < params.P; i++ {
        a := uint64(expanded[i])
        y[i] = make([]byte, len(x.x[i]))
        copy(y[i], x.x[i])

        for j := uint64(0); j < a; j++ {
            binary.BigEndian.PutUint32(be32[:], x.q)
            binary.BigEndian.PutUint16(be16[:], uint16(i))

            inner := params.Hash()
            inner.Write(x.id[:])
            inner.Write(be32[:])
            inner.Write(be16[:])
            inner.Write([]byte{byte(j)})
            inner.Write(y[i])

            y[i] = inner.Sum(nil)
        }
    }

    // mark private key as invalid
    x.x = nil
    x.valid = false

    return LmsOtsSignature{
        typ: x.typ,
        c:   c,
        y:   y,
    }, nil
}

func (x *LmsOtsPrivateKey) computeRoot() []byte {
    var be16 [2]byte
    var be32 [4]byte
    var tmp []byte

    params := x.typ.Params()

    binary.BigEndian.PutUint32(be32[:], x.q)

    hasher := params.Hash()
    hasher.Write(x.id[:])
    hasher.Write(be32[:])
    hasher.Write(D_PBLC[:])

    for i := uint64(0); i < params.P; i++ {
        tmp = make([]byte, len(x.x[i]))
        copy(tmp, x.x[i])

        for j := uint64(0); j < (uint64(1)<<int(params.W.Window()))-1; j++ {
            binary.BigEndian.PutUint32(be32[:], x.q)
            binary.BigEndian.PutUint16(be16[:], uint16(i))

            inner := params.Hash()
            inner.Write(x.id[:])
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

// A LmsOtsPublicKey is used to verify exactly one message.
type LmsOtsPublicKey struct {
    typ ILmotsParam
    q   uint32
    id  ID
    k   []byte
}

// Verify returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *LmsOtsPublicKey) Verify(msg []byte, sig LmsOtsSignature) bool {
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
func (sig *LmsOtsSignature) RecoverPublicKey(msg []byte, id ID, q uint32) (LmsOtsPublicKey, bool) {
    var be16 [2]byte
    var be32 [4]byte
    var tmp []byte

    params := sig.typ.Params()

    hasher := params.Hash()
    hash_len := hasher.Size()

    // verify length of nonce
    if len(sig.c) != hash_len {
        return LmsOtsPublicKey{}, false
    }

    // verify length of y and y[i]
    if uint64(len(sig.y)) != params.P {
        return LmsOtsPublicKey{}, false
    }

    for i := uint64(0); i < params.P; i++ {
        if len(sig.y[i]) != hash_len {
            return LmsOtsPublicKey{}, false
        }
    }

    binary.BigEndian.PutUint32(be32[:], q)

    hasher.Write(id[:])
    hasher.Write(be32[:])
    hasher.Write(D_MESG[:])
    hasher.Write(sig.c)
    hasher.Write(msg)

    Q := hasher.Sum(nil)
    expanded, err := Expand(Q, sig.typ)
    if err != nil {
        return LmsOtsPublicKey{}, false
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
            binary.BigEndian.PutUint32(be32[:], q)
            binary.BigEndian.PutUint16(be16[:], uint16(i))

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

    return LmsOtsPublicKey{
        typ: sig.typ,
        q:   q,
        id:  id,
        k:   hasher.Sum(nil),
    }, true
}

// Key returns a copy of the public key's k parameter.
// We need this to get the public key as bytes in order to hash
func (pub *LmsOtsPublicKey) Key() []byte {
    return pub.k[:]
}

// NewLmsOtsPublicKeyFromBytes returns an LmsOtsPublicKey that represents b.
// This is the inverse of the ToBytes() method on the LmsOtsPublicKey object.
func NewLmsOtsPublicKeyFromBytes(b []byte) (LmsOtsPublicKey, error) {
    if len(b) < 4 {
        return LmsOtsPublicKey{}, errors.New("NewLmsOtsPublicKeyFromBytes(): OTS public key too short")
    }

    // The typecode is bytes 0-3 (4 bytes)
    newType, err := GetLmotsParam(LmotsType(binary.BigEndian.Uint32(b[0:4])))
    if err != nil {
        return LmsOtsPublicKey{}, err
    }

    typecode := newType()

    params := typecode.Params()

    // ensure that the length of the slice is correct
    if uint64(len(b)) < 4+ID_LEN+4+params.N {
        return LmsOtsPublicKey{}, errors.New("LmsOtsPublicKeyFromBytes(): OTS public key too short")
    } else if uint64(len(b)) > 4+ID_LEN+4+params.N {
        return LmsOtsPublicKey{}, errors.New("LmsOtsPublicKeyFromBytes(): OTS public key too long")
    } else {
        // The next ID_LEN bytes are the id
        id := ID(b[4 : 4+ID_LEN])

        // the next 4 bytes is the internal counter q
        q := binary.BigEndian.Uint32(b[4+ID_LEN : 8+ID_LEN])

        // The public key, k, is the remaining bytes
        k := b[8+ID_LEN:]

        return LmsOtsPublicKey{
            typ: typecode,
            id:  id,
            q:   q,
            k:   k,
        }, nil
    }
}

// ToBytes() serializes the public key into a byte string for transmission or storage.
func (pub *LmsOtsPublicKey) ToBytes() []byte {
    var serialized []byte
    var u32_be [4]byte

    // First 4 bytes: typecode
    typecode := pub.typ.GetType()

    // This will never error if we have a valid LmsOtsPublicKey
    binary.BigEndian.PutUint32(u32_be[:], uint32(typecode))
    serialized = append(serialized, u32_be[:]...)

    // Next 16 bytes: id
    serialized = append(serialized, pub.id[:]...)

    // Next 4 bytes: q
    binary.BigEndian.PutUint32(u32_be[:], pub.q)
    serialized = append(serialized, u32_be[:]...)

    // Followed by the public key, k
    serialized = append(serialized, pub.k[:]...)

    return serialized
}

// A LmsOtsSignature is a signature of one message.
type LmsOtsSignature struct {
    typ ILmotsParam
    c   []byte
    y   [][]byte
}

// NewLmsOtsSignatureFromBytes returns an LmsOtsSignature represented by b.
func NewLmsOtsSignatureFromBytes(b []byte) (LmsOtsSignature, error) {
    if len(b) < 4 {
        return LmsOtsSignature{}, errors.New("NewLmsOtsSignatureFromBytes(): No typecode")
    }

    // Typecode is the first 4 bytes
    newType, err := GetLmotsParam(LmotsType(binary.BigEndian.Uint32(b[0:4])))
    if err != nil {
        return LmsOtsSignature{}, err
    }

    typecode := newType()

    // Panic if not a valid LM-OTS algorithm:
    params := typecode.Params()

    // check the length of the signature
    if uint64(len(b)) < params.SIG_LEN {
        return LmsOtsSignature{}, errors.New("LmsOtsSignatureFromBytes(): LMOTS signature too short")
    } else if uint64(len(b)) > params.SIG_LEN {
        return LmsOtsSignature{}, errors.New("LmsOtsSignatureFromBytes(): LMOTS signature too long")
    } else {
        // parse the signature
        c := b[4 : 4+int(params.N)]
        cur := uint64(4 + params.N)

        y := make([][]byte, params.P)
        for i := uint64(0); i < params.P; i++ {
            y[i] = b[cur : cur+params.N]
            cur += params.N
        }

        return LmsOtsSignature{
            typ: typecode,
            c:   c,
            y:   y,
        }, nil
    }
}

// ToBytes() serializes the LM-OTS signature into a byte string for transmission or storage.
func (sig *LmsOtsSignature) ToBytes() ([]byte, error) {
    var serialized []byte
    var u32_be [4]byte

    params := sig.typ.Params()

    // First 4 bytes: LMOTS typecode
    typecode := sig.typ.GetType()

    binary.BigEndian.PutUint32(u32_be[:], uint32(typecode))
    serialized = append(serialized, u32_be[:]...)

    // Next H bytes: nonce C
    serialized = append(serialized, sig.c...)

    // Next P * H bytes: y[0] ... y[p-1]
    for i := uint64(0); i < params.P; i++ {
        serialized = append(serialized, sig.y[i]...)
    }

    return serialized, nil
}
