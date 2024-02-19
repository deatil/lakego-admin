package ccm

import (
    "math"
    "errors"
    "encoding/binary"
    go_cipher "crypto/cipher"
    go_subtle "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/xor"
    "github.com/deatil/go-cryptobin/tool/alias"
)

const (
    ccmBlockSize         = 16
    ccmTagSize           = 16
    ccmMinimumTagSize    = 4
    ccmStandardNonceSize = 12
)

// ccmAble is an interface implemented by ciphers that have a specific optimized
// implementation of CCM.
type ccmAble interface {
    NewCCM(nonceSize, tagSize int) (go_cipher.AEAD, error)
}

type ccm struct {
    cipher    go_cipher.Block
    nonceSize int
    tagSize   int
}

func (c *ccm) NonceSize() int {
    return c.nonceSize
}

func (c *ccm) Overhead() int {
    return c.tagSize
}

func (c *ccm) MaxLength() int {
    return maxlen(15-c.NonceSize(), c.Overhead())
}

func maxlen(L, tagsize int) int {
    max := (uint64(1) << (8 * L)) - 1
    if m64 := uint64(math.MaxInt64) - uint64(tagsize); L > 8 || max > m64 {
        max = m64 // The maximum lentgh on a 64bit arch
    }
    if max != uint64(int(max)) {
        return math.MaxInt32 - tagsize // We have only 32bit int's
    }
    return int(max)
}

// NewCCM returns the given 128-bit, block cipher wrapped in CCM
// with the standard nonce length.
func NewCCM(cipher go_cipher.Block) (go_cipher.AEAD, error) {
    return NewCCMWithNonceAndTagSize(cipher, ccmStandardNonceSize, ccmTagSize)
}

// NewCCMWithNonceSize returns the given 128-bit, block cipher wrapped in CCM,
// which accepts nonces of the given length. The length must not
// be zero.
func NewCCMWithNonceSize(cipher go_cipher.Block, size int) (go_cipher.AEAD, error) {
    return NewCCMWithNonceAndTagSize(cipher, size, ccmTagSize)
}

// NewCCMWithTagSize returns the given 128-bit, block cipher wrapped in CCM,
// which generates tags with the given length.
//
// Tag sizes between 8 and 16 bytes are allowed.
//
func NewCCMWithTagSize(cipher go_cipher.Block, tagSize int) (go_cipher.AEAD, error) {
    return NewCCMWithNonceAndTagSize(cipher, ccmStandardNonceSize, tagSize)
}

// https://tools.ietf.org/html/rfc3610
func NewCCMWithNonceAndTagSize(cipher go_cipher.Block, nonceSize, tagSize int) (go_cipher.AEAD, error) {
    if tagSize < ccmMinimumTagSize || tagSize > ccmBlockSize || tagSize&1 != 0 {
        return nil, errors.New("cipher: incorrect tag size given to CCM")
    }

    if nonceSize <= 0 {
        return nil, errors.New("cipher: the nonce can't have zero length, or the security of the key will be immediately compromised")
    }

    lenSize := 15 - nonceSize
    if lenSize < 2 || lenSize > 8 {
        return nil, errors.New("cipher: invalid ccm nounce size, should be in [7,13]")
    }

    if cipher, ok := cipher.(ccmAble); ok {
        return cipher.NewCCM(nonceSize, tagSize)
    }

    if cipher.BlockSize() != ccmBlockSize {
        return nil, errors.New("cipher: NewCCM requires 128-bit block cipher")
    }

    c := &ccm{cipher: cipher, nonceSize: nonceSize, tagSize: tagSize}

    return c, nil
}

// https://tools.ietf.org/html/rfc3610
func (c *ccm) deriveCounter(counter *[ccmBlockSize]byte, nonce []byte) {
    counter[0] = byte(14 - c.nonceSize)
    copy(counter[1:], nonce)
}

func (c *ccm) cmac(out, data []byte) {
    for len(data) >= ccmBlockSize {
        xor.XorBytes(out, out, data)
        c.cipher.Encrypt(out, out)
        data = data[ccmBlockSize:]
    }
    if len(data) > 0 {
        var block [ccmBlockSize]byte
        copy(block[:], data)
        xor.XorBytes(out, out, data)
        c.cipher.Encrypt(out, out)
    }
}

// https://tools.ietf.org/html/rfc3610 2.2. Authentication
func (c *ccm) auth(nonce, plaintext, additionalData []byte, tagMask *[ccmBlockSize]byte) []byte {
    var out [ccmTagSize]byte
    if len(additionalData) > 0 {
        out[0] = 1 << 6 // 64*Adata
    }
    out[0] |= byte(c.tagSize-2) << 2 // M' = ((tagSize - 2) / 2)*8
    out[0] |= byte(14 - c.nonceSize) // L'
    binary.BigEndian.PutUint64(out[ccmBlockSize-8:], uint64(len(plaintext)))
    copy(out[1:], nonce)
    // B0
    c.cipher.Encrypt(out[:], out[:])

    var block [ccmBlockSize]byte
    if n := uint64(len(additionalData)); n > 0 {
        // First adata block includes adata length
        i := 2
        if n <= 0xfeff { // l(a) < (2^16 - 2^8)
            binary.BigEndian.PutUint16(block[:i], uint16(n))
        } else {
            block[0] = 0xff
            // If (2^16 - 2^8) <= l(a) < 2^32, then the length field is encoded as
            // six octets consisting of the octets 0xff, 0xfe, and four octets
            // encoding l(a) in most-significant-byte-first order.
            if n < uint64(1<<32) {
                block[1] = 0xfe
                i = 2 + 4
                binary.BigEndian.PutUint32(block[2:i], uint32(n))
            } else {
                block[1] = 0xff
                // If 2^32 <= l(a) < 2^64, then the length field is encoded as ten
                // octets consisting of the octets 0xff, 0xff, and eight octets encoding
                // l(a) in most-significant-byte-first order.
                i = 2 + 8
                binary.BigEndian.PutUint64(block[2:i], uint64(n))
            }
        }
        i = copy(block[i:], additionalData) // first block start with additional data length
        c.cmac(out[:], block[:])
        c.cmac(out[:], additionalData[i:])
    }
    if len(plaintext) > 0 {
        c.cmac(out[:], plaintext)
    }
    xor.XorWords(out[:], out[:], tagMask[:])
    return out[:c.tagSize]
}

func (c *ccm) Seal(dst, nonce, plaintext, data []byte) []byte {
    if len(nonce) != c.nonceSize {
        panic("cryptobin/ccm: incorrect nonce length given to CCM")
    }
    if uint64(len(plaintext)) > uint64(c.MaxLength()) {
        panic("cryptobin/ccm: message too large for CCM")
    }
    ret, out := alias.SliceForAppend(dst, len(plaintext)+c.tagSize)
    if alias.InexactOverlap(out, plaintext) {
        panic("cryptobin/ccm: invalid buffer overlap")
    }

    var counter, tagMask [ccmBlockSize]byte
    c.deriveCounter(&counter, nonce)
    c.cipher.Encrypt(tagMask[:], counter[:])

    counter[len(counter)-1] |= 1
    ctr := go_cipher.NewCTR(c.cipher, counter[:])
    ctr.XORKeyStream(out, plaintext)

    tag := c.auth(nonce, plaintext, data, &tagMask)
    copy(out[len(plaintext):], tag)

    return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (c *ccm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
    if len(nonce) != c.nonceSize {
        panic("cryptobin/ccm: incorrect nonce length given to CCM")
    }
    // Sanity check to prevent the authentication from always succeeding if an implementation
    // leaves tagSize uninitialized, for example.
    if c.tagSize < ccmMinimumTagSize {
        panic("cryptobin/ccm: incorrect CCM tag size")
    }

    if len(ciphertext) < c.tagSize {
        return nil, errOpen
    }

    if len(ciphertext) > c.MaxLength()+c.Overhead() {
        return nil, errOpen
    }

    tag := ciphertext[len(ciphertext)-c.tagSize:]
    ciphertext = ciphertext[:len(ciphertext)-c.tagSize]

    var counter, tagMask [ccmBlockSize]byte
    c.deriveCounter(&counter, nonce)
    c.cipher.Encrypt(tagMask[:], counter[:])

    ret, out := alias.SliceForAppend(dst, len(ciphertext))
    if alias.InexactOverlap(out, ciphertext) {
        panic("cryptobin/ccm: invalid buffer overlap")
    }

    counter[len(counter)-1] |= 1
    ctr := go_cipher.NewCTR(c.cipher, counter[:])
    ctr.XORKeyStream(out, ciphertext)
    expectedTag := c.auth(nonce, out, data, &tagMask)
    if go_subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
        // The AESNI code decrypts and authenticates concurrently, and
        // so overwrites dst in the event of a tag mismatch. That
        // behavior is mimicked here in order to be consistent across
        // platforms.
        for i := range out {
            out[i] = 0
        }
        return nil, errOpen
    }
    return ret, nil
}
