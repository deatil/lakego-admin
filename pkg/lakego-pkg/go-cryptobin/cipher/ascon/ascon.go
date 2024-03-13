// Package ascon implements the ASCON AEAD cipher.
//
// References:
//
//    [ascon]: https://ascon.iaik.tugraz.at
//
package ascon

import (
    "errors"
    "runtime"
    "strconv"
    "math/bits"
    "crypto/subtle"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

var errOpen = errors.New("cryptobin/ascon: message authentication failed")

const (
    // BlockSize128a is the size in bytes of an ASCON-128a block.
    BlockSize128a = 16
    // BlockSize128 is the size in bytes of an ASCON-128 block.
    BlockSize128 = 8
    // KeySize is the size in bytes of ASCON-128 and ASCON-128a
    // keys.
    KeySize = 16
    // NonceSize is the size in bytes of ASCON-128 and ASCON-128a
    // nonces.
    NonceSize = 16
    // TagSize is the size in bytes of ASCON-128 and ASCON-128a
    // authenticators.
    TagSize = 16
)

type ascon struct {
    k0, k1 uint64
    iv     uint64
}

var _ cipher.AEAD = (*ascon)(nil)

// New128 creates a 128-bit ASCON-128 AEAD.
//
// ASCON-128 provides lower throughput but increased robustness
// against partial or full state recovery compared to ASCON-128a.
//
// Each unique key can encrypt a maximum 2^68 bytes (i.e., 2^64
// plaintext and associated data blocks). Nonces must never be
// reused with the same key. Violating either of these
// constraints compromises the security of the algorithm.
//
// There are no other constraints on the composition of the
// nonce. For example, the nonce can be a counter.
//
// Refer to ASCON's documentation for more information.
func New128(key []byte) (cipher.AEAD, error) {
    if len(key) != KeySize {
        return nil, errors.New("cryptobin/ascon: bad key length")
    }

    return &ascon{
        k0: binary.BigEndian.Uint64(key[0:8]),
        k1: binary.BigEndian.Uint64(key[8:16]),
        iv: iv128,
    }, nil
}

// New128a creates a 128-bit ASCON-128a AEAD.
//
// ASCON-128a provides higher throughput but reduced robustness
// against partial or full state recovery compared to ASCON-128.
//
// Each unique key can encrypt a maximum 2^68 bytes (i.e., 2^64
// plaintext and associated data blocks). Nonces must never be
// reused with the same key. Violating either of these
// constraints compromises the security of the algorithm.
//
// There are no other constraints on the composition of the
// nonce. For example, the nonce can be a counter.
//
// Refer to ASCON's documentation for more information.
func New128a(key []byte) (cipher.AEAD, error) {
    if len(key) != KeySize {
        return nil, errors.New("cryptobin/ascon: bad key length")
    }

    return &ascon{
        k0: binary.BigEndian.Uint64(key[0:8]),
        k1: binary.BigEndian.Uint64(key[8:16]),
        iv: iv128a,
    }, nil
}

func (a *ascon) NonceSize() int {
    return NonceSize
}

func (a *ascon) Overhead() int {
    return TagSize
}

func (a *ascon) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
    if len(nonce) != NonceSize {
        panic("cryptobin/ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
    }

    n0 := binary.BigEndian.Uint64(nonce[0:8])
    n1 := binary.BigEndian.Uint64(nonce[8:16])

    var s state
    s.init(a.iv, a.k0, a.k1, n0, n1)

    if a.iv == iv128a {
        s.additionalData128a(additionalData)
    } else {
        s.additionalData128(additionalData)
    }

    ret, out := alias.SliceForAppend(dst, len(plaintext)+TagSize)
    if alias.InexactOverlap(out, plaintext) {
        panic("cryptobin/ascon: invalid buffer overlap")
    }

    if a.iv == iv128a {
        s.encrypt128a(out[:len(plaintext)], plaintext)
    } else {
        s.encrypt128(out[:len(plaintext)], plaintext)
    }

    if a.iv == iv128a {
        s.finalize128a(a.k0, a.k1)
    } else {
        s.finalize128(a.k0, a.k1)
    }
    s.tag(out[len(out)-TagSize:])

    return ret
}

func (a *ascon) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
    if len(nonce) != NonceSize {
        panic("cryptobin/ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
    }
    if len(ciphertext) < TagSize {
        return nil, errOpen
    }

    tag := ciphertext[len(ciphertext)-TagSize:]
    ciphertext = ciphertext[:len(ciphertext)-TagSize]

    n0 := binary.BigEndian.Uint64(nonce[0:8])
    n1 := binary.BigEndian.Uint64(nonce[8:16])

    var s state
    s.init(a.iv, a.k0, a.k1, n0, n1)

    if a.iv == iv128a {
        s.additionalData128a(additionalData)
    } else {
        s.additionalData128(additionalData)
    }

    ret, out := alias.SliceForAppend(dst, len(ciphertext))
    if alias.InexactOverlap(out, ciphertext) {
        panic("cryptobin/ascon: invalid buffer overlap")
    }

    if a.iv == iv128a {
        s.decrypt128a(out, ciphertext)
    } else {
        s.decrypt128(out, ciphertext)
    }

    if a.iv == iv128a {
        s.finalize128a(a.k0, a.k1)
    } else {
        s.finalize128(a.k0, a.k1)
    }

    expectedTag := make([]byte, TagSize)
    s.tag(expectedTag)

    if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
        for i := range out {
            out[i] = 0
        }
        runtime.KeepAlive(out)
        return nil, errOpen
    }

    return ret, nil
}

const (
    iv128  uint64 = 0x80400c0600000000 // Ascon-128
    iv128a uint64 = 0x80800c0800000000 // Ascon-128a
)

type state struct {
    x0, x1, x2, x3, x4 uint64
}

func (s *state) init(iv, k0, k1, n0, n1 uint64) {
    s.x0 = iv
    s.x1 = k0
    s.x2 = k1
    s.x3 = n0
    s.x4 = n1
    p12(s)
    s.x3 ^= k0
    s.x4 ^= k1
}

func (s *state) finalize128a(k0, k1 uint64) {
    s.x2 ^= k0
    s.x3 ^= k1
    p12(s)
    s.x3 ^= k0
    s.x4 ^= k1
}

func (s *state) additionalData128a(ad []byte) {
    if len(ad) > 0 {
        n := len(ad) &^ (BlockSize128a - 1)
        if n > 0 {
            additionalData128a(s, ad[:n])
            ad = ad[n:]
        }
        if len(ad) >= 8 {
            s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
            s.x1 ^= be64n(ad[8:])
            s.x1 ^= pad(len(ad) - 8)
        } else {
            s.x0 ^= be64n(ad)
            s.x0 ^= pad(len(ad))
        }
        p8(s)
    }
    s.x4 ^= 1
}

func (s *state) encrypt128a(dst, src []byte) {
    n := len(src) &^ (BlockSize128a - 1)
    if n > 0 {
        encryptBlocks128a(s, dst[:n], src[:n])
        src = src[n:]
        dst = dst[n:]
    }
    if len(src) >= 8 {
        s.x0 ^= binary.BigEndian.Uint64(src[0:8])
        s.x1 ^= be64n(src[8:])
        s.x1 ^= pad(len(src) - 8)
        binary.BigEndian.PutUint64(dst[0:8], s.x0)
        put64n(dst[8:], s.x1)
    } else {
        s.x0 ^= be64n(src)
        put64n(dst, s.x0)
        s.x0 ^= pad(len(src))
    }
}

func (s *state) decrypt128a(dst, src []byte) {
    n := len(src) &^ (BlockSize128a - 1)
    if n > 0 {
        decryptBlocks128a(s, dst[:n], src[:n])
        src = src[n:]
        dst = dst[n:]
    }

    if len(src) >= 8 {
        c0 := binary.BigEndian.Uint64(src[0:8])
        c1 := be64n(src[8:])
        binary.BigEndian.PutUint64(dst[0:8], s.x0^c0)
        put64n(dst[8:], s.x1^c1)
        s.x0 = c0
        s.x1 = mask(s.x1, len(src)-8)
        s.x1 |= c1
        s.x1 ^= pad(len(src) - 8)
    } else {
        c0 := be64n(src)
        put64n(dst, s.x0^c0)
        s.x0 = mask(s.x0, len(src))
        s.x0 |= c0
        s.x0 ^= pad(len(src))
    }
}

func (s *state) finalize128(k0, k1 uint64) {
    s.x1 ^= k0
    s.x2 ^= k1
    p12(s)
    s.x3 ^= k0
    s.x4 ^= k1
}

func (s *state) additionalData128(ad []byte) {
    if len(ad) > 0 {
        for len(ad) >= BlockSize128 {
            s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
            p6(s)
            ad = ad[BlockSize128:]
        }
        s.x0 ^= be64n(ad)
        s.x0 ^= pad(len(ad))
        p6(s)
    }
    s.x4 ^= 1
}

func (s *state) encrypt128(dst, src []byte) {
    for len(src) >= BlockSize128 {
        s.x0 ^= binary.BigEndian.Uint64(src[0:8])
        binary.BigEndian.PutUint64(dst[0:8], s.x0)
        p6(s)
        src = src[BlockSize128:]
        dst = dst[BlockSize128:]
    }

    s.x0 ^= be64n(src)
    put64n(dst, s.x0)
    s.x0 ^= pad(len(src))
}

func (s *state) decrypt128(dst, src []byte) {
    for len(src) >= BlockSize128 {
        c := binary.BigEndian.Uint64(src[0:8])
        binary.BigEndian.PutUint64(dst[0:8], s.x0^c)
        s.x0 = c
        p6(s)
        src = src[BlockSize128:]
        dst = dst[BlockSize128:]
    }

    c := be64n(src)
    put64n(dst, s.x0^c)
    s.x0 = mask(s.x0, len(src))
    s.x0 |= c
    s.x0 ^= pad(len(src))
}

func (s *state) tag(dst []byte) {
    binary.BigEndian.PutUint64(dst[0:8], s.x3)
    binary.BigEndian.PutUint64(dst[8:16], s.x4)
}

func pad(n int) uint64 {
    return 0x80 << (56 - 8*n)
}

func rotr(x uint64, n int) uint64 {
    return bits.RotateLeft64(x, -n)
}

func be64n(b []byte) uint64 {
    var x uint64
    for i := len(b) - 1; i >= 0; i-- {
        x |= uint64(b[i]) << (56 - i*8)
    }
    return x
}

func put64n(b []byte, x uint64) {
    for i := len(b) - 1; i >= 0; i-- {
        b[i] = byte(x >> (56 - 8*i))
    }
}

func mask(x uint64, n int) uint64 {
    for i := 0; i < n; i++ {
        x &^= 255 << (56 - 8*i)
    }

    return x
}
