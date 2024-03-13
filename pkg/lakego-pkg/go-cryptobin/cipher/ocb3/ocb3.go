package ocb3

import (
    "fmt"
    "errors"
    "math/bits"
    "crypto/cipher"
    "crypto/subtle"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// Package ocb3 implements the Offset codebook mode (OCB3) cipher
// block mode.
//
// This implementation runs at around 25 cycles per byte for
// messages between 1 KiB and 8 KiB, measured on a 2021 MacBook
// Air M1.
//
// This package is implemented per RFC 7253 and "The Design and
// Evolution of OCB" by Krovetz and Rogaway in the Journal of
// Cryptology (volume 34, issue 4)[0].
//
// OCB3's patents were abandoned in February 2021.
//
// [0]: https://doi.org/10.1007/s00145-021-09399-8
// [1]: https://mailarchive.ietf.org/arch/msg/cfrg/qLTveWOdTJcLn4HP3ev-vrj05Vg/

const (
    // BlockSize is the size in bytes of an OCB3 block.
    BlockSize = 16

    // defaultNonceSize is the size in bytes of an OCB3 nonce.
    defaultNonceSize = 12
    // defaultTagSize is the size in bytes of an OCB3
    // authentication tag.
    defaultTagSize = 16
    // minTagSize is the size in bytes of the smallest
    // allowed OCB3 tag.
    minTagSize = 12
    // maxTagSize is the size in bytes of the largest
    // allowed OCB3 tag.
    maxTagSize = 16
    // maxInputSize is the largest allowed plaintext size,
    // including additional data.
    maxInputSize = (1 << 48) * BlockSize
)

var errOpen = errors.New("ocb3: message authentication failure")

// New creates an OCB3 AEAD from a secure block cipher.
//
// The AEAD uses a 96-bit nonce and 128-bit tag.
//
// Nonces can either be random or a counter. Like many AEAD
// modes, they need not be secret.
//
// Like many AEAD modes, (nonce, key) pairs must never be used to
// encrypt multiple messages (multiple calls to Seal). Doing so
// is catastrophic for both confidentiality and authenticity.
// It cannot be stressed enough: never allow (nonce, key) pairs
// to repeat while encrypting. It is a fatal error.
//
// OCB3's confidentiality and authenticity claims degrade as the
// number of blocks, s, approaches s^2 / 2^128. Therefore, it is
// recommended that each key generate no more than 2^48
// ciphertext blocks (about 4 PB), including associated data.
//
// It is an error if the cipher's block size is not exactly
// BlockSize.
func New(b cipher.Block) (cipher.AEAD, error) {
    return NewWithNonceAndTagSize(b, defaultNonceSize, defaultTagSize)
}

func NewWithNonceSize(block cipher.Block, nonceSize int) (cipher.AEAD, error) {
    return NewWithNonceAndTagSize(block, nonceSize, defaultTagSize)
}

func NewWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error) {
    return NewWithNonceAndTagSize(block, defaultNonceSize, tagSize)
}

func NewWithNonceAndTagSize(b cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
    if tagSize < minTagSize || tagSize > maxTagSize {
        return nil, fmt.Errorf("invalid tag size: %d", tagSize)
    }
    if nonceSize <= 0 {
        return nil, fmt.Errorf("invalid nonce size: %d", nonceSize)
    }
    if b.BlockSize() != BlockSize {
        return nil, fmt.Errorf("invalid block size: %d", b.BlockSize())
    }

    a := &aead{
        b:         b,
        nonceSize: nonceSize,
        tagSize:   tagSize,
    }
    a.setup()

    return a, nil
}

// aead implements cipher.AEAD.
type aead struct {
    // b is the underlying block cipher.
    b cipher.Block
    // nonceSize is the size of the nonce.
    //
    // Will be in [1, 15].
    nonceSize int
    // tagSize is the size of the tag.
    //
    // Will be in [12, 16].
    tagSize int
    // Lstar is the encrypted zero block.
    //
    // Used by setup and updating the offset for partial
    // plaintext blocks.
    Lstar uint128
    // Ldollar is Lstar doubled in GF(2^128).
    //
    // Used by setup and updating the offset when computing the
    // authentication tag.
    Ldollar uint128
    // L is the complete L cache, including L_0.
    L [lsize]uint128
    // buf is a scratch buffer for encipher and decipher.
    buf [BlockSize]byte
}

const (
    // lsize is the size of the key-dependent L buffer. On
    // a 64-bit system, lsize will be 58 and on a 32-bit system
    // lsize will be 26.
    //
    // On a 64-bit system, the maximum plaintext size is 1<<63-1,
    // which is 1<<59-1 blocks and a maximum 58 trailing zeros.
    //
    // On a 32-bit system, the maximum plaintext size is 1<<31-1,
    // which is 1<<27-1 blocks and a maximum 26 trailing zeros.
    lsize = 58 - (64 - uintSize)
    // uintSize is 64 on a 64-bit system and 32 on a 32-bit
    // system.
    uintSize = 32 << (^uint(0) >> 32 & 1)
)

var _ cipher.AEAD = (*aead)(nil)

func (a *aead) NonceSize() int {
    return a.nonceSize
}

func (a *aead) Overhead() int {
    return a.nonceSize + a.tagSize
}

func (a *aead) setup() {
    // L∗ ← E_K(0^128)
    l0, l1 := a.encipher(0, 0)
    a.Lstar = uint128{l0, l1}
    // L ← double(L∗)
    a.Ldollar = double(a.Lstar)
    // L[0] ← double(L$)
    a.L[0] = double(a.Ldollar)
    // for i ← 1, 2, ... do L[i] ← double(L[i−1])
    for i := 1; i < len(a.L); i++ {
        a.L[i] = double(a.L[i-1])
    }
}

func (a *aead) encipher(p0, p1 uint64) (c0, c1 uint64) {
    binary.BigEndian.PutUint64(a.buf[0:8], p0)
    binary.BigEndian.PutUint64(a.buf[8:16], p1)
    a.b.Encrypt(a.buf[:], a.buf[:])
    c0 = binary.BigEndian.Uint64(a.buf[0:8])
    c1 = binary.BigEndian.Uint64(a.buf[8:16])
    return c0, c1
}

func (a *aead) decipher(c0, c1 uint64) (p0, p1 uint64) {
    binary.BigEndian.PutUint64(a.buf[0:8], c0)
    binary.BigEndian.PutUint64(a.buf[8:16], c1)
    a.b.Decrypt(a.buf[:], a.buf[:])
    p0 = binary.BigEndian.Uint64(a.buf[0:8])
    p1 = binary.BigEndian.Uint64(a.buf[8:16])
    return p0, p1
}

func (a *aead) init(nonce []byte) uint128 {
    // Nonce ← [τ mod 128]_7 || 0^120−|N| || 1 || N
    n := make([]byte, 16)
    n[0] = byte((a.tagSize*8)%128) << 1
    copy(n[len(n)-len(nonce):], nonce)
    n[len(n)-len(nonce)-1] |= 1

    // Bottom ← Nonce ∧ 0^122 1^16
    // The bottom 6 bits of the nonce.
    b := n[15] & 0x3f

    // Top ← Nonce ∧ 1^122 0^6
    // All but the top 6 bits of the nonce.
    //
    // Ktop ← E_K(Top)
    k0, k1 := a.encipher(
        binary.BigEndian.Uint64(n[0:8]),
        binary.BigEndian.Uint64(n[8:16])&^0x3f,
    )

    // Stretch ← Ktop || Ktop xor (Ktop << 8)
    s0 := k0
    s1 := k1
    s2 := k0 ^ (k0<<8 | k1>>56)

    // return (Stretch << Bottom)[1..128]
    var off uint128
    off.lo = s0<<b | s1>>(64-b)
    off.hi = s1<<b | s2>>(64-b)
    return off
}

func (a *aead) hash(additionalData []byte) (s0, s1 uint64) {
    // Δ ← 0^128
    var off uint128

    i := uint(1)
    for len(additionalData) >= BlockSize {
        // Δ ← Δ xor L[ntz(i)]
        l := a.L[uint(bits.TrailingZeros(i))%uint(len(a.L))]
        off.lo ^= l.lo
        off.hi ^= l.hi

        // Sum ← Sum xor E_K(A_i xor Δ)
        a0 := binary.BigEndian.Uint64(additionalData[0:8])
        a1 := binary.BigEndian.Uint64(additionalData[8:16])
        h0, h1 := a.encipher(a0^off.lo, a1^off.hi)
        s0 ^= h0
        s1 ^= h1

        additionalData = additionalData[BlockSize:]
        i++
    }

    if len(additionalData) > 0 {
        // Δ ← Δ xor L∗
        off.lo ^= a.Lstar.lo
        off.hi ^= a.Lstar.hi
        // Sum ← Sum xor E_K((A∗ || 1 || 0*) xor Δ)
        q := make([]byte, 16)
        n := copy(q, additionalData)
        q[n] = 1 << 7
        q0 := binary.BigEndian.Uint64(q[0:8])
        q1 := binary.BigEndian.Uint64(q[8:16])
        c0, c1 := a.encipher(q0^off.lo, q1^off.hi)
        s0 ^= c0
        s1 ^= c1
    }
    return s0, s1
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
    if len(nonce) != a.nonceSize {
        panic("ocb3: invalid nonce length")
    }
    if a.tagSize < minTagSize {
        panic("ocb3: invalid tag length")
    }
    if uint64(len(plaintext)) > maxInputSize ||
        maxInputSize-uint64(len(plaintext)) < uint64(len(additionalData)) {
        panic("ocb3: message too large")
    }

    ret, out := alias.SliceForAppend(dst, len(plaintext)+a.tagSize)
    if alias.InexactOverlap(out, plaintext) {
        panic("ocb3: invalid buffer overlap")
    }
    tag := out[len(plaintext):]

    // Checksum ← 0^128
    var ck uint128

    // Δ ← InitK(N)
    off := a.init(nonce[:a.nonceSize:a.nonceSize])

    i := uint(1)
    for len(plaintext) >= BlockSize {
        // Δ ← Δ xor L[ntz(i)]
        l := a.L[uint(bits.TrailingZeros(i))]
        off.lo ^= l.lo
        off.hi ^= l.hi

        // C ← C || E_K(M_i xor Δ) xor Δ
        p0 := binary.BigEndian.Uint64(plaintext[0:8])
        p1 := binary.BigEndian.Uint64(plaintext[8:16])
        c0, c1 := a.encipher(p0^off.lo, p1^off.hi)
        binary.BigEndian.PutUint64(out[0:8], c0^off.lo)
        binary.BigEndian.PutUint64(out[8:16], c1^off.hi)

        // Checksum ← Checksum xor M_i
        ck.lo ^= p0
        ck.hi ^= p1

        plaintext = plaintext[BlockSize:]
        out = out[BlockSize:]
        i++
    }

    if len(plaintext) > 0 {
        // Δ ← Δ xor L∗
        off.lo ^= a.Lstar.lo
        off.hi ^= a.Lstar.hi
        // Pad ← E_K(Δ)
        d0, d1 := a.encipher(off.lo, off.hi)
        pad := make([]byte, 16)
        binary.BigEndian.PutUint64(pad[0:8], d0)
        binary.BigEndian.PutUint64(pad[8:16], d1)
        // C ← C || M∗ xor Pad[1..|M∗|]
        for i, p := range plaintext {
            out[i] = p ^ pad[i]
        }
        // Checksum ← Checksum xor (M∗ || 1 || 0*)
        q := make([]byte, 16)
        n := copy(q, plaintext)
        q[n] = 1 << 7
        q0 := binary.BigEndian.Uint64(q[0:8])
        q1 := binary.BigEndian.Uint64(q[8:16])
        ck.lo ^= q0
        ck.hi ^= q1
    }

    // Δ ← Δ xor L$
    off.lo ^= a.Ldollar.lo
    off.hi ^= a.Ldollar.hi
    // Final ← E_K(Checksum xor Δ)
    f0, f1 := a.encipher(ck.lo^off.lo, ck.hi^off.hi)
    // Auth ← Hash_K(A)
    a0, a1 := a.hash(additionalData)

    // Tag ← Final xor Auth
    t0 := f0 ^ a0
    t1 := f1 ^ a1

    // T ← Tag[1..τ]
    if a.tagSize == defaultTagSize {
        binary.BigEndian.PutUint64(tag[0:8], t0)
        binary.BigEndian.PutUint64(tag[8:16], t1)
    } else {
        writeTag(tag, t0, t1)
    }
    return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
    if len(nonce) != a.nonceSize {
        panic("ocb3: invalid nonce length")
    }
    if a.tagSize < minTagSize {
        panic("ocb3: invalid tag length")
    }

    if len(ciphertext) < a.tagSize {
        return nil, errOpen
    }
    if uint64(len(ciphertext)) > maxInputSize ||
        (maxInputSize+uint64(a.tagSize))-uint64(len(ciphertext)) < uint64(len(additionalData)) {
        panic("ocb3: message too large")
    }

    ret, out := alias.SliceForAppend(dst, len(ciphertext)-a.tagSize)
    if alias.InexactOverlap(out, ciphertext) {
        panic("ocb3: invalid buffer overlap")
    }
    tag := ciphertext[len(ciphertext)-a.tagSize:]
    ciphertext = ciphertext[:len(ciphertext)-a.tagSize]

    // Checksum ← 0^128
    var ck uint128

    // Δ ← InitK(N)
    off := a.init(nonce[:a.nonceSize:a.nonceSize])

    i := uint(1)
    for len(ciphertext) >= BlockSize {
        // Δ ← Δ xor L[ntz(i)]
        l := a.L[uint(bits.TrailingZeros(i))]
        off.lo ^= l.lo
        off.hi ^= l.hi

        // M ← M || D_K(C_i xor Δ) xor Δ
        c0 := binary.BigEndian.Uint64(ciphertext[0:8])
        c1 := binary.BigEndian.Uint64(ciphertext[8:16])
        p0, p1 := a.decipher(c0^off.lo, c1^off.hi)
        p0 ^= off.lo
        p1 ^= off.hi
        binary.BigEndian.PutUint64(out[0:8], p0)
        binary.BigEndian.PutUint64(out[8:16], p1)

        // Checksum ← Checksum xor M_i
        ck.lo ^= p0
        ck.hi ^= p1

        ciphertext = ciphertext[BlockSize:]
        out = out[BlockSize:]
        i++
    }

    if len(ciphertext) > 0 {
        // Δ ← Δ xor L∗
        off.lo ^= a.Lstar.lo
        off.hi ^= a.Lstar.hi
        // Pad ← E_K(Δ)
        d0, d1 := a.encipher(off.lo, off.hi)
        pad := make([]byte, 16)
        binary.BigEndian.PutUint64(pad[0:8], d0)
        binary.BigEndian.PutUint64(pad[8:16], d1)
        // M ← M || C∗ xor Pad[1..|C∗|]
        for i, c := range ciphertext {
            out[i] = c ^ pad[i]
        }
        // Checksum ← Checksum xor (M∗ || 1 || 0*)
        q := make([]byte, 16)
        n := copy(q, out[:len(ciphertext)])
        q[n] = 1 << 7
        q0 := binary.BigEndian.Uint64(q[0:8])
        q1 := binary.BigEndian.Uint64(q[8:16])
        ck.lo ^= q0
        ck.hi ^= q1
    }

    // Δ ← Δ xor L$
    off.lo ^= a.Ldollar.lo
    off.hi ^= a.Ldollar.hi
    // Final ← E_K(Checksum xor Δ)
    f0, f1 := a.encipher(ck.lo^off.lo, ck.hi^off.hi)
    // Auth ← Hash_K(A)
    a0, a1 := a.hash(additionalData)

    // Tag ← Final xor Auth
    t0 := f0 ^ a0
    t1 := f1 ^ a1

    // T ← Tag[1..τ]
    expectedTag := make([]byte, defaultTagSize)
    binary.BigEndian.PutUint64(expectedTag[0:8], t0)
    binary.BigEndian.PutUint64(expectedTag[8:16], t1)

    if subtle.ConstantTimeCompare(expectedTag[:a.tagSize], tag) != 1 {
        for i := range out {
            out[i] = 0
        }
        return nil, errOpen
    }
    return ret, nil
}

// uint128 is a big-endian, 128-bit integer.
type uint128 struct {
    lo, hi uint64
}

func (x uint128) String() string {
    return fmt.Sprintf("%0.16x%0.16x", x.lo, x.hi)
}

// double doubles x in GF(2^128)
//
//    (X << 1) xor (msb(X) · 135)
//
// As double is the only part of OCB3 that depends on secret
// data, care should be taken to ensure that it runs in constant
// time.
func double(x uint128) (z uint128) {
    z.lo = x.lo<<1 | x.hi>>63
    // if x.lo>>63 == 1 {
    //     z.hi ^= 135
    // }
    //
    // The conversion to int64 results in -1 if x.lo's MSB is
    // set. The conversion back to uint64 results in 1<<64-1 if
    // the MSB is set, or 0 otherwise. The bitwise AND operation
    // therefore results in either 135 if the MSB is set or
    // 0 otherwise.
    z.hi = x.hi<<1 ^ uint64((int64(x.lo)>>63))&135
    return z
}

// writeTag writes up to len(tag) bytes of the authentication tag
// (t0, t1) to tag.
//
// writeTag is only used for non-standard tag sizes.
func writeTag(tag []byte, t0, t1 uint64) {
    if len(tag) < minTagSize {
        panic("ocb3: invalid tag length")
    }
    i := 0
    for _, x := range []uint64{t0, t1} {
        for j := 7; j >= 0; j-- {
            if i >= len(tag) {
                break
            }
            tag[i] = byte(x >> (j * 8))
            i++
        }
    }
}
