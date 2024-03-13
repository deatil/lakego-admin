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

// New256 creates a new Threefish cipher with a block size of 256 bits.
// The key argument must be 32 bytes and the tweak argument must be 16 bytes.
func New256(key, tweak []byte) (cipher.Block, error) {
    // Length check the provided key
    if len(key) != BlockSize256 {
        return nil, KeySizeError(BlockSize256)
    }

    c := new(cipher256)

    // Load and extend the tweak value
    if err := calculateTweak(&c.t, tweak); err != nil {
        return nil, err
    }

    // Load and extend key
    k := new([numWords256 + 1]uint64)
    k[numWords256] = c240
    for i := 0; i < numWords256; i++ {
        k[i] = loadWord(key[i*8 : (i+1)*8])
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

    return c, nil
}

// BlockSize returns the block size of a 256-bit cipher.
func (c *cipher256) BlockSize() int {
    return BlockSize256
}

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher256) Encrypt(dst, src []byte) {
    // Load the input
    in := new([numWords256]uint64)
    in[0] = loadWord(src[0:8])
    in[1] = loadWord(src[8:16])
    in[2] = loadWord(src[16:24])
    in[3] = loadWord(src[24:32])

    // Perform encryption rounds
    for d := 0; d < numRounds256; d += 8 {
        // Add round key
        in[0] += c.ks[d/4][0]
        in[1] += c.ks[d/4][1]
        in[2] += c.ks[d/4][2]
        in[3] += c.ks[d/4][3]

        // Four rounds of mix and permute
        in[0] += in[1]
        in[1] = ((in[1] << 14) | (in[1] >> (64 - 14))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 16) | (in[3] >> (64 - 16))) ^ in[2]
        in[1], in[3] = in[3], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 52) | (in[1] >> (64 - 52))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 57) | (in[3] >> (64 - 57))) ^ in[2]
        in[1], in[3] = in[3], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 23) | (in[1] >> (64 - 23))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 40) | (in[3] >> (64 - 40))) ^ in[2]
        in[1], in[3] = in[3], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 5) | (in[1] >> (64 - 5))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 37) | (in[3] >> (64 - 37))) ^ in[2]
        in[1], in[3] = in[3], in[1]

        // Add round key
        in[0] += c.ks[(d/4)+1][0]
        in[1] += c.ks[(d/4)+1][1]
        in[2] += c.ks[(d/4)+1][2]
        in[3] += c.ks[(d/4)+1][3]

        // Four rounds of mix and permute
        in[0] += in[1]
        in[1] = ((in[1] << 25) | (in[1] >> (64 - 25))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 33) | (in[3] >> (64 - 33))) ^ in[2]
        in[1], in[3] = in[3], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 46) | (in[1] >> (64 - 46))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 12) | (in[3] >> (64 - 12))) ^ in[2]
        in[1], in[3] = in[3], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 58) | (in[1] >> (64 - 58))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 22) | (in[3] >> (64 - 22))) ^ in[2]
        in[1], in[3] = in[3], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 32) | (in[1] >> (64 - 32))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 32) | (in[3] >> (64 - 32))) ^ in[2]
        in[1], in[3] = in[3], in[1]
    }

    // Add the final round key
    in[0] += c.ks[numRounds256/4][0]
    in[1] += c.ks[numRounds256/4][1]
    in[2] += c.ks[numRounds256/4][2]
    in[3] += c.ks[numRounds256/4][3]

    // Store ciphertext in destination
    storeWord(dst[0:8], in[0])
    storeWord(dst[8:16], in[1])
    storeWord(dst[16:24], in[2])
    storeWord(dst[24:32], in[3])
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher256) Decrypt(dst, src []byte) {
    // Load the ciphertext
    ct := new([numWords256]uint64)
    ct[0] = loadWord(src[0:8])
    ct[1] = loadWord(src[8:16])
    ct[2] = loadWord(src[16:24])
    ct[3] = loadWord(src[24:32])

    // Subtract the final round key
    ct[0] -= c.ks[numRounds256/4][0]
    ct[1] -= c.ks[numRounds256/4][1]
    ct[2] -= c.ks[numRounds256/4][2]
    ct[3] -= c.ks[numRounds256/4][3]

    // Perform decryption rounds
    for d := numRounds256 - 1; d >= 0; d -= 8 {
        // Four rounds of permute and unmix
        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 32)) | ((ct[3] ^ ct[2]) >> 32)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 32)) | ((ct[1] ^ ct[0]) >> 32)
        ct[0] -= ct[1]

        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 22)) | ((ct[3] ^ ct[2]) >> 22)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 58)) | ((ct[1] ^ ct[0]) >> 58)
        ct[0] -= ct[1]

        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 12)) | ((ct[3] ^ ct[2]) >> 12)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 46)) | ((ct[1] ^ ct[0]) >> 46)
        ct[0] -= ct[1]

        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 33)) | ((ct[3] ^ ct[2]) >> 33)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 25)) | ((ct[1] ^ ct[0]) >> 25)
        ct[0] -= ct[1]

        // Subtract round key
        ct[0] -= c.ks[d/4][0]
        ct[1] -= c.ks[d/4][1]
        ct[2] -= c.ks[d/4][2]
        ct[3] -= c.ks[d/4][3]

        // Four rounds of permute and unmix
        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 37)) | ((ct[3] ^ ct[2]) >> 37)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 5)) | ((ct[1] ^ ct[0]) >> 5)
        ct[0] -= ct[1]

        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 40)) | ((ct[3] ^ ct[2]) >> 40)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 23)) | ((ct[1] ^ ct[0]) >> 23)
        ct[0] -= ct[1]

        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 57)) | ((ct[3] ^ ct[2]) >> 57)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 52)) | ((ct[1] ^ ct[0]) >> 52)
        ct[0] -= ct[1]

        ct[1], ct[3] = ct[3], ct[1]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 16)) | ((ct[3] ^ ct[2]) >> 16)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 14)) | ((ct[1] ^ ct[0]) >> 14)
        ct[0] -= ct[1]

        // Subtract round key
        ct[0] -= c.ks[(d/4)-1][0]
        ct[1] -= c.ks[(d/4)-1][1]
        ct[2] -= c.ks[(d/4)-1][2]
        ct[3] -= c.ks[(d/4)-1][3]
    }

    // Store decrypted value in destination
    storeWord(dst[0:8], ct[0])
    storeWord(dst[8:16], ct[1])
    storeWord(dst[16:24], ct[2])
    storeWord(dst[24:32], ct[3])
}
