package threefish

import (
    "crypto/cipher"
)

const (
    // Size of a 1024-bit block in bytes
    BlockSize1024 = 128

    // Number of 64-bit words per 1024-bit block
    numWords1024 = BlockSize1024 / 8

    // Number of rounds when using a 1024-bit cipher
    numRounds1024 = 80
)

type cipher1024 struct {
    t  [(tweakSize / 8) + 1]uint64
    ks [(numRounds1024 / 4) + 1][numWords1024]uint64
}

// NewCipher1024 creates a new Threefish cipher with a block size of 1024 bits.
// The key argument must be 64 bytes and the tweak argument must be 16 bytes.
func NewCipher1024(key, tweak []byte) (cipher.Block, error) {
    // Length check the provided key
    if len(key) != BlockSize1024 {
        return nil, KeySizeError(BlockSize1024)
    }

    c := new(cipher1024)
    err := c.expandKey(key, tweak)
    if err != nil {
        return nil, err
    }

    return c, nil
}

// BlockSize returns the block size of a 1024-bit cipher.
func (c *cipher1024) BlockSize() int {
    return BlockSize1024
}

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher1024) Encrypt(dst, src []byte) {
    in := bytesToUint64s(src)

    var i int

    // Perform encryption rounds
    for d := 0; d < numRounds1024; d += 8 {
        // Add round key
        for i = 0; i < 16; i++ {
            in[i] += c.ks[d/4][i]
        }

        // Four rounds of mix and permute
        g1024(in, 24, 13, 8, 47, 8, 17, 22, 37)
        g1024(in, 38, 19, 10, 55, 49, 18, 23, 52)
        g1024(in, 33, 4, 51, 13, 34, 41, 59, 17)
        g1024(in, 5, 20, 48, 41, 47, 28, 16, 25)

        // Add round key
        for i = 0; i < 16; i++ {
            in[i] += c.ks[(d/4)+1][i]
        }

        // Four rounds of mix and permute
        g1024(in, 41, 9, 37, 31, 12, 47, 44, 30)
        g1024(in, 16, 34, 56, 51, 4, 53, 42, 41)
        g1024(in, 31, 44, 47, 46, 19, 42, 44, 25)
        g1024(in, 9, 48, 35, 52, 23, 31, 37, 20)
    }

    // Add the final round key
    for i = 0; i < 16; i++ {
        in[i] += c.ks[numRounds1024/4][i]
    }

    // Store the ciphertext in destination
    ct := uint64sToBytes(in)
    copy(dst, ct)
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher1024) Decrypt(dst, src []byte) {
    ct := bytesToUint64s(src)

    var i int

    // Subtract the final round key
    for i = 0; i < 16; i++ {
        ct[i] -= c.ks[numRounds1024/4][i]
    }

    // Perform decryption rounds
    for d := numRounds1024 - 1; d >= 0; d -= 8 {
        // Four rounds of permute and unmix
        d1024(ct, 20, 37, 31, 23, 52, 35, 48, 9)
        d1024(ct, 25, 44, 42, 19, 46, 47, 44, 31)
        d1024(ct, 41, 42, 53, 4, 51, 56, 34, 16)
        d1024(ct, 30, 44, 47, 12, 31, 37, 9, 41)

        // Subtract round key
        for i = 0; i < 16; i++ {
            ct[i] -= c.ks[d/4][i]
        }

        // Four rounds of permute and unmix
        d1024(ct, 25, 16, 28, 47, 41, 48, 20, 5)
        d1024(ct, 17, 59, 41, 34, 13, 51, 4, 33)
        d1024(ct, 52, 23, 18, 49, 55, 10, 19, 38)
        d1024(ct, 37, 22, 17, 8, 47, 8, 13, 24)

        // Subtract round key
        for i = 0; i < 16; i++ {
            ct[i] -= c.ks[(d/4)-1][i]
        }
    }

    // Store decrypted value in destination
    pt := uint64sToBytes(ct)
    copy(dst, pt)
}

func (c *cipher1024) expandKey(key, tweak []byte) error {
    // Load and extend the tweak value
    if err := calculateTweak(&c.t, tweak); err != nil {
        return err
    }

    // Load and extend the key
    k := new([numWords1024 + 1]uint64)
    k[numWords1024] = c240
    for i := 0; i < numWords1024; i++ {
        k[i] = GETU64(key[i*8 : (i+1)*8])
        k[numWords1024] ^= k[i]
    }

    // Calculate the key schedule
    for s := 0; s <= numRounds1024/4; s++ {
        for i := 0; i < numWords1024; i++ {
            c.ks[s][i] = k[(s+i)%(numWords1024+1)]
            switch i {
                case numWords1024 - 3:
                    c.ks[s][i] += c.t[s%3]
                case numWords1024 - 2:
                    c.ks[s][i] += c.t[(s+1)%3]
                case numWords1024 - 1:
                    c.ks[s][i] += uint64(s)
            }
        }
    }

    return nil
}

func g1024(in []uint64, a, b, c, d, e, f, g, h int) {
    n := []int{a, b, c, d, e, f, g, h}
    for i := 0; i < 16; i += 2 {
        in[i] += in[i+1]
        in[i+1] = rotl64(in[i+1], n[i/2]) ^ in[i]
    }

    in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
        in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]
}

func d1024(ct []uint64, a, b, c, d, e, f, g, h int) {
    ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
        ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]

    n := []int{h, g, f, e, d, c, b, a}
    for i := 15; i > 0; i -= 2 {
        ct[i] = rotr64(ct[i] ^ ct[i-1], n[i/2])
        ct[i-1] -= ct[i]
    }
}
