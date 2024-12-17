// Package ascon implements the ASCON AEAD cipher.
package ascon

import (
    "errors"
    "runtime"
    "strconv"
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const (
    iv128  uint64 = 0x80400c0600000000 // Ascon-128
    iv128a uint64 = 0x80800c0800000000 // Ascon-128a
)

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

var errOpen = errors.New("go-cryptobin/ascon: message authentication failed")

type ascon struct {
    k0, k1 uint64
    iv     uint64
}

//
// References:
//
//    [ascon]: https://ascon.iaik.tugraz.at
//

// NewCipher creates a 128-bit ASCON-128 AEAD.
func NewCipher(key []byte) (cipher.AEAD, error) {
    if len(key) != KeySize {
        return nil, errors.New("go-cryptobin/ascon: bad key length")
    }

    return &ascon{
        k0: getu64(key[0:]),
        k1: getu64(key[8:]),
        iv: iv128,
    }, nil
}

// NewCiphera creates a 128-bit ASCON-128a AEAD.
func NewCiphera(key []byte) (cipher.AEAD, error) {
    if len(key) != KeySize {
        return nil, errors.New("go-cryptobin/ascon: bad key length")
    }

    return &ascon{
        k0: getu64(key[0:]),
        k1: getu64(key[8:]),
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
        panic("go-cryptobin/ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
    }

    n0 := getu64(nonce[0:])
    n1 := getu64(nonce[8:])

    var s state
    s.init(a.iv, a.k0, a.k1, n0, n1)

    if a.iv == iv128a {
        s.additionalData128a(additionalData)
    } else {
        s.additionalData128(additionalData)
    }

    ret, out := alias.SliceForAppend(dst, len(plaintext)+TagSize)
    if alias.InexactOverlap(out, plaintext) {
        panic("go-cryptobin/ascon: invalid buffer overlap")
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
        panic("go-cryptobin/ascon: incorrect nonce length: " + strconv.Itoa(len(nonce)))
    }

    if len(ciphertext) < TagSize {
        return nil, errOpen
    }

    tag := ciphertext[len(ciphertext)-TagSize:]
    ciphertext = ciphertext[:len(ciphertext)-TagSize]

    n0 := getu64(nonce[0:])
    n1 := getu64(nonce[8:])

    var s state
    s.init(a.iv, a.k0, a.k1, n0, n1)

    if a.iv == iv128a {
        s.additionalData128a(additionalData)
    } else {
        s.additionalData128(additionalData)
    }

    ret, out := alias.SliceForAppend(dst, len(ciphertext))
    if alias.InexactOverlap(out, ciphertext) {
        panic("go-cryptobin/ascon: invalid buffer overlap")
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
