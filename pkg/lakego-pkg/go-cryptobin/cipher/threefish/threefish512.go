package threefish

import (
    "crypto/cipher"
)

const (
    // Size of a 512-bit block in bytes
    BlockSize512 = 64

    // Number of 64-bit words per 512-bit block
    numWords512 = BlockSize512 / 8

    // Number of rounds when using a 512-bit cipher
    numRounds512 = 72
)

type cipher512 struct {
    t  [(tweakSize / 8) + 1]uint64
    ks [(numRounds512 / 4) + 1][numWords512]uint64
}

// NewCipher512 creates a new Threefish cipher with a block size of 512 bits.
// The key argument must be 64 bytes and the tweak argument must be 16 bytes.
func NewCipher512(key, tweak []byte) (cipher.Block, error) {
    // Length check the provided key
    if len(key) != BlockSize512 {
        return nil, KeySizeError(BlockSize512)
    }

    c := new(cipher512)
    err := c.expandKey(key, tweak)
    if err != nil {
        return nil, err
    }

    return c, nil
}

// BlockSize returns the block size of a 512-bit cipher.
func (c *cipher512) BlockSize() int {
    return BlockSize512
}

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher512) Encrypt(dst, src []byte) {
    // Load the input
    in := bytesToUint64s(src)

    var i int

    // Perform encryption rounds
    for d := 0; d < numRounds512; d += 8 {
        // Add round key
        for i = 0; i < 8; i++ {
            in[i] += c.ks[d/4][i]
        }

        // Four rounds of mix and permute
        g512(in, 46, 36, 19, 37)
        g512(in, 33, 27, 14, 42)
        g512(in, 17, 49, 36, 39)
        g512(in, 44, 9, 54, 56)

        // Add round key
        for i = 0; i < 8; i++ {
            in[i] += c.ks[(d/4)+1][i]
        }

        // Four rounds of mix and permute
        g512(in, 39, 30, 34, 24)
        g512(in, 13, 50, 10, 17)
        g512(in, 25, 29, 39, 43)
        g512(in, 8, 35, 56, 22)
    }

    // Add the final round key
    for i = 0; i < 8; i++ {
        in[i] += c.ks[numRounds512/4][i]
    }

    // Store the ciphertext in destination
    ct := uint64sToBytes(in)
    copy(dst, ct)
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher512) Decrypt(dst, src []byte) {
    ct := bytesToUint64s(src)

    var i int

    // Subtract the final round key
    for i = 0; i < 8; i++ {
        ct[i] -= c.ks[numRounds512/4][i]
    }

    // Perform decryption rounds
    for d := numRounds512 - 1; d >= 0; d -= 8 {
        // Four rounds of permute and unmix
        d512(ct, 22, 56, 35, 8)
        d512(ct, 43, 39, 29, 25)
        d512(ct, 17, 10, 50, 13)
        d512(ct, 24, 34, 30, 39)

        // Subtract round key
        for i = 0; i < 8; i++ {
            ct[i] -= c.ks[d/4][i]
        }

        // Four rounds of permute and unmix
        d512(ct, 56, 54, 9, 44)
        d512(ct, 39, 36, 49, 17)
        d512(ct, 42, 14, 27, 33)
        d512(ct, 37, 19, 36, 46)

        // Subtract round key
        for i = 0; i < 8; i++ {
            ct[i] -= c.ks[(d/4)-1][i]
        }
    }

    // Store decrypted value in destination
    pt := uint64sToBytes(ct)
    copy(dst, pt)
}

func (c *cipher512) expandKey(key, tweak []byte) error {
    // Load and extend the tweak value
    if err := calculateTweak(&c.t, tweak); err != nil {
        return err
    }

    // Load and extend the key
    k := new([numWords512 + 1]uint64)
    k[numWords512] = c240
    for i := 0; i < numWords512; i++ {
        k[i] = GETU64(key[i*8 : (i+1)*8])
        k[numWords512] ^= k[i]
    }

    // Calculate the key schedule
    for s := 0; s <= numRounds512/4; s++ {
        for i := 0; i < numWords512; i++ {
            c.ks[s][i] = k[(s+i)%(numWords512+1)]
            switch i {
                case numWords512 - 3:
                    c.ks[s][i] += c.t[s%3]
                case numWords512 - 2:
                    c.ks[s][i] += c.t[(s+1)%3]
                case numWords512 - 1:
                    c.ks[s][i] += uint64(s)
            }
        }
    }

    return nil
}

func g512(in []uint64, a, b, c, d int) {
    in[0] += in[1]
    in[1] = rotl64(in[1], a) ^ in[0]
    in[2] += in[3]
    in[3] = rotl64(in[3], b) ^ in[2]
    in[4] += in[5]
    in[5] = rotl64(in[5], c) ^ in[4]
    in[6] += in[7]
    in[7] = rotl64(in[7], d) ^ in[6]
    in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]
}

func d512(ct []uint64, a, b, c, d int) {
    ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
    ct[7] = rotr64(ct[7] ^ ct[6], a)
    ct[6] -= ct[7]
    ct[5] = rotr64(ct[5] ^ ct[4], b)
    ct[4] -= ct[5]
    ct[3] = rotr64(ct[3] ^ ct[2], c)
    ct[2] -= ct[3]
    ct[1] = rotr64(ct[1] ^ ct[0], d)
    ct[0] -= ct[1]
}
