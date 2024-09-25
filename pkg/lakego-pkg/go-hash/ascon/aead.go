package ascon

import (
    "fmt"
    "errors"
    "crypto/subtle"
)

const (
    NonceSize = 128 / 8
    KeySize   = 128 / 8
    TagSize   = 128 / 8
)

var errDecryptFail = errors.New("ascon: decryption failed")

// AEAD provides an implementation of Ascon-128.
// It implements the crypto/cipher.AEAD interface.
type AEAD struct {
    key [16]byte
}

func NewAEAD(key []byte) (*AEAD, error) {
    a := new(AEAD)
    a.SetKey(key)
    return a, nil
}

// Sets the key to a new value.
// This method is not safe for concurrent use with other methods.
func (a *AEAD) SetKey(key []byte) {
    if len(key) != KeySize {
        panic("ascon: wrong key size")
    }

    copy(a.key[:], key)
}

func (a *AEAD) NonceSize() int {
    return NonceSize
}

func (a *AEAD) Overhead() int  {
    return TagSize
}

// Seal encrypts and authenticates a plaintext
// and appends ciphertext to dst, returning the appended slice.
func (a *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
    if len(nonce) != NonceSize {
        panic(fmt.Sprintf("ascon: bad nonce (len %d)", len(nonce)))
    }

    // Initialize
    // IV || key || nonce
    var s state
    const A, B uint = 12, 6
    s.expandKey(a.key[:], 64, uint8(A), uint8(B), nonce)

    // mix the key in again
    k0 := getu64(a.key[0:])
    k1 := getu64(a.key[8:])
    s[3] ^= k0
    s[4] ^= k1

    // Absorb additionalData
    s.mixAdditionalData(additionalData, B)
    // domain-separation constant
    s[4] ^= 1

    // allocate space
    dstLen := len(dst)
    dst = append(dst, make([]byte, len(plaintext)+TagSize)...)

    // Duplex plaintext/ciphertext
    c := s.encrypt(plaintext, dst[dstLen:], B)

    // mix the key in again
    s[1] ^= k0
    s[2] ^= k1

    // Finalize
    s.rounds(A)

    // Append tag
    t0 := s[3] ^ k0
    t1 := s[4] ^ k1
    putu64(c[0:], t0)
    putu64(c[8:], t1)

    return dst
}

func (a *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
    if len(nonce) != NonceSize {
        panic(fmt.Sprintf("ascon: bad nonce (len %d)", len(nonce)))
    }

    if len(ciphertext) < TagSize {
        return dst, errDecryptFail
    }

    plaintextSize := len(ciphertext) - TagSize
    expectedTag := ciphertext[plaintextSize:]
    ciphertext = ciphertext[0:plaintextSize]

    dstLen := len(dst)
    dst = append(dst, make([]byte, plaintextSize)...)

    // Initialize
    // IV || key || nonce
    var s state
    const A, B uint = 12, 6
    s.expandKey(a.key[:], 64, uint8(A), uint8(B), nonce)

    // mix the key in again
    k0 := getu64(a.key[0:])
    k1 := getu64(a.key[8:])
    s[3] ^= k0
    s[4] ^= k1

    // Absorb additionalData
    s.mixAdditionalData(additionalData, B)
    // domain-separation constant
    s[4] ^= 1

    // Duplex plaintext/ciphertext
    s.decrypt(ciphertext, dst[dstLen:], B)

    // mix the key in again
    s[1] ^= k0
    s[2] ^= k1

    // Finalize
    s.rounds(A)

    // Compute tag
    t0 := s[3] ^ k0
    t1 := s[4] ^ k1
    // Check tag in constant time
    t0 ^= getu64(expectedTag[0:])
    t1 ^= getu64(expectedTag[8:])
    t := uint32(t0>>32) | uint32(t0)
    t |= uint32(t1>>32) | uint32(t1)

    if subtle.ConstantTimeEq(int32(t), 0) == 0 {
        return dst, errDecryptFail
    }

    return dst, nil
}
