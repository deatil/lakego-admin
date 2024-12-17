package skipjack

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/skipjack: invalid key size " + strconv.Itoa(int(k))
}

// References: http://csrc.nist.gov/groups/ST/toolkit/documents/skipjack/skipjack.pdf
// skipjackCipher is an instance of SKIPJACK encryption with a particular key
type skipjackCipher struct {
    key []byte
}

// NewCipher creates and returns a new cipher.Block implementing the SKIPJACK cipher.
// The key argument must be 10 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 10:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(skipjackCipher)
    c.key = make([]byte, 10)

    copy(c.key[:], key)

    return c, nil
}

// BlockSize returns the SKIPJACK block size
func (c *skipjackCipher) BlockSize() int {
    return BlockSize
}

func (c *skipjackCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/skipjack: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/skipjack: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/skipjack: invalid buffer overlap")
    }

    c.encrypt(dst, src)
}

func (c *skipjackCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/skipjack: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/skipjack: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/skipjack: invalid buffer overlap")
    }

    c.decrypt(dst, src)
}

// Encrypt encrypts src into dst
func (c *skipjackCipher) encrypt(dst, src []byte) {
    w1 := (uint16(src[0]) << 8) + uint16(src[1])
    w2 := (uint16(src[2]) << 8) + uint16(src[3])
    w3 := (uint16(src[4]) << 8) + uint16(src[5])
    w4 := (uint16(src[6]) << 8) + uint16(src[7])

    k := 0

    for t := 0; t < 2; t++ {
        // A
        for i := 0; i < 8; i++ {
            gw1 := g(c.key, k, w1)
            w1, w2, w3, w4 = gw1^w4^(uint16(k)+1), gw1, w2, w3
            k++
        }

        // B
        for i := 0; i < 8; i++ {
            gw1 := g(c.key, k, w1)
            w1, w2, w3, w4 = w4, gw1, w1^w2^uint16(k+1), w3
            k++
        }
    }

    dst[0] = byte(w1 >> 8)
    dst[1] = byte(w1 & 0xff)
    dst[2] = byte(w2 >> 8)
    dst[3] = byte(w2 & 0xff)
    dst[4] = byte(w3 >> 8)
    dst[5] = byte(w3 & 0xff)
    dst[6] = byte(w4 >> 8)
    dst[7] = byte(w4 & 0xff)
}

// Decrypt decrypts src into dst
func (c *skipjackCipher) decrypt(dst, src []byte) {
    w1 := (uint16(src[0]) << 8) + uint16(src[1])
    w2 := (uint16(src[2]) << 8) + uint16(src[3])
    w3 := (uint16(src[4]) << 8) + uint16(src[5])
    w4 := (uint16(src[6]) << 8) + uint16(src[7])

    k := 32

    for t := 0; t < 2; t++ {
        // B^-1
        for i := 0; i < 8; i++ {
            gw2 := ginv(c.key, k-1, w2)
            w1, w2, w3, w4 = gw2, gw2^w3^uint16(k), w4, w1
            k--
        }

        // A^-1
        for i := 0; i < 8; i++ {
            w1, w2, w3, w4 = ginv(c.key, k-1, w2), w3, w4, w1^w2^uint16(k)
            k--
        }
    }

    dst[0] = byte(w1 >> 8)
    dst[1] = byte(w1 & 0xff)
    dst[2] = byte(w2 >> 8)
    dst[3] = byte(w2 & 0xff)
    dst[4] = byte(w3 >> 8)
    dst[5] = byte(w3 & 0xff)
    dst[6] = byte(w4 >> 8)
    dst[7] = byte(w4 & 0xff)
}

// via: http://packetstormsecurity.org/files/20573/skipjack.c
var ftable = []byte{
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
}

func g(key []byte, k int, w uint16) uint16 {
    g1 := byte((w >> 8) & 0xff)
    g2 := byte(w & 0xff)

    g3 := ftable[g2^key[(4*k+0)%10]] ^ g1
    g4 := ftable[g3^key[(4*k+1)%10]] ^ g2
    g5 := ftable[g4^key[(4*k+2)%10]] ^ g3
    g6 := ftable[g5^key[(4*k+3)%10]] ^ g4

    return (uint16(g5) << 8) + uint16(g6)
}

func ginv(key []byte, k int, w uint16) uint16 {
    g5 := byte((w >> 8) & 0xff)
    g6 := byte(w & 0xff)

    g4 := ftable[g5^key[(4*k+3)%10]] ^ g6
    g3 := ftable[g4^key[(4*k+2)%10]] ^ g5
    g2 := ftable[g3^key[(4*k+1)%10]] ^ g4
    g1 := ftable[g2^key[(4*k+0)%10]] ^ g3

    return (uint16(g1) << 8) + uint16(g2)
}
