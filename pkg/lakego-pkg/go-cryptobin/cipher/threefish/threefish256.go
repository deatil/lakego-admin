package threefish

import (
    "crypto/cipher"
)

const (
    // Size of a 256-bit block in bytes
    BlockSize256 = 32

    // Number of 64-bit words per 256-bit block
    numWords256 = BlockSize256 / 8

    // Number of rounds when using a 256-bit cipher
    numRounds256 = 72
)

type cipher256 struct {
    t  [(tweakSize / 8) + 1]uint64
    ks [(numRounds256 / 4) + 1][numWords256]uint64
}

// NewCipher256 creates a new Threefish cipher with a block size of 256 bits.
// The key argument must be 32 bytes and the tweak argument must be 16 bytes.
func NewCipher256(key, tweak []byte) (cipher.Block, error) {
    // Length check the provided key
    if len(key) != BlockSize256 {
        return nil, KeySizeError(BlockSize256)
    }

    c := new(cipher256)
    err := c.expandKey(key, tweak)
    if err != nil {
        return nil, err
    }

    return c, nil
}

// BlockSize returns the block size of a 256-bit cipher.
func (c *cipher256) BlockSize() int {
    return BlockSize256
}

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher256) Encrypt(dst, src []byte) {
    in := bytesToUint64s(src)

    var i int

    // Perform encryption rounds
    for d := 0; d < numRounds256; d += 8 {
        // Add round key
        for i = 0; i < 4; i++ {
            in[i] += c.ks[d/4][i]
        }

        // Four rounds of mix and permute
        g256(in, 14, 16)
        g256(in, 52, 57)
        g256(in, 23, 40)
        g256(in, 5, 37)

        // Add round key
        for i = 0; i < 4; i++ {
            in[i] += c.ks[(d/4)+1][i]
        }

        // Four rounds of mix and permute
        g256(in, 25, 33)
        g256(in, 46, 12)
        g256(in, 58, 22)
        g256(in, 32, 32)
    }

    // Add the final round key
    for i = 0; i < 4; i++ {
        in[i] += c.ks[numRounds256/4][i]
    }

    ct := uint64sToBytes(in)
    copy(dst, ct)
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher256) Decrypt(dst, src []byte) {
    ct := bytesToUint64s(src)

    var i int

    // Subtract the final round key
    for i = 0; i < 4; i++ {
        ct[i] -= c.ks[numRounds256/4][i]
    }

    // Perform decryption rounds
    for d := numRounds256 - 1; d >= 0; d -= 8 {
        // Four rounds of permute and unmix
        d256(ct, 32, 32)
        d256(ct, 22, 58)
        d256(ct, 12, 46)
        d256(ct, 33, 25)

        // Subtract round key
        for i = 0; i < 4; i++ {
            ct[i] -= c.ks[d/4][i]
        }

        // Four rounds of permute and unmix
        d256(ct, 37, 5)
        d256(ct, 40, 23)
        d256(ct, 57, 52)
        d256(ct, 16, 14)

        // Subtract round key
        for i = 0; i < 4; i++ {
            ct[i] -= c.ks[(d/4)-1][i]
        }
    }

    // Store decrypted value in destination
    pt := uint64sToBytes(ct)
    copy(dst, pt)
}

func (c *cipher256) expandKey(key, tweak []byte) error {
    // Load and extend the tweak value
    if err := calculateTweak(&c.t, tweak); err != nil {
        return err
    }

    // Load and extend key
    k := new([numWords256 + 1]uint64)
    k[numWords256] = c240
    for i := 0; i < numWords256; i++ {
        k[i] = GETU64(key[i*8 : (i+1)*8])
        k[numWords256] ^= k[i]
    }

    // Calculate the key schedule
    for s := 0; s <= numRounds256/4; s++ {
        for i := 0; i < numWords256; i++ {
            c.ks[s][i] = k[(s+i)%(numWords256+1)]
            switch i {
                case numWords256 - 3:
                    c.ks[s][i] += c.t[s%3]
                case numWords256 - 2:
                    c.ks[s][i] += c.t[(s+1)%3]
                case numWords256 - 1:
                    c.ks[s][i] += uint64(s)
            }
        }
    }

    return nil
}

func g256(in []uint64, a, b int) {
    n := []int{a, b}
    for i := 0; i < 4; i += 2 {
        in[i] += in[i+1]
        in[i+1] = rotl64(in[i+1], n[i/2]) ^ in[i]
    }

    in[1], in[3] = in[3], in[1]
}

func d256(ct []uint64, a, b int) {
    ct[1], ct[3] = ct[3], ct[1]

    n := []int{b, a}
    for i := 3; i > 0; i -= 2 {
        ct[i] = rotr64(ct[i] ^ ct[i-1], n[i/2])
        ct[i-1] -= ct[i]
    }
}
