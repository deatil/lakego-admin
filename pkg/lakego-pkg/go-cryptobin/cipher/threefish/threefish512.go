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

// New512 creates a new Threefish cipher with a block size of 512 bits.
// The key argument must be 64 bytes and the tweak argument must be 16 bytes.
func New512(key, tweak []byte) (cipher.Block, error) {
    // Length check the provided key
    if len(key) != BlockSize512 {
        return nil, KeySizeError(BlockSize512)
    }

    c := new(cipher512)

    // Load and extend the tweak value
    if err := calculateTweak(&c.t, tweak); err != nil {
        return nil, err
    }

    // Load and extend the key
    k := new([numWords512 + 1]uint64)
    k[numWords512] = c240
    for i := 0; i < numWords512; i++ {
        k[i] = loadWord(key[i*8 : (i+1)*8])
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

    return c, nil
}

// BlockSize returns the block size of a 512-bit cipher.
func (c *cipher512) BlockSize() int {
    return BlockSize512
}

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher512) Encrypt(dst, src []byte) {
    // Load the input
    in := new([numWords512]uint64)
    in[0] = loadWord(src[0:8])
    in[1] = loadWord(src[8:16])
    in[2] = loadWord(src[16:24])
    in[3] = loadWord(src[24:32])
    in[4] = loadWord(src[32:40])
    in[5] = loadWord(src[40:48])
    in[6] = loadWord(src[48:56])
    in[7] = loadWord(src[56:64])

    // Perform encryption rounds
    for d := 0; d < numRounds512; d += 8 {
        // Add round key
        in[0] += c.ks[d/4][0]
        in[1] += c.ks[d/4][1]
        in[2] += c.ks[d/4][2]
        in[3] += c.ks[d/4][3]
        in[4] += c.ks[d/4][4]
        in[5] += c.ks[d/4][5]
        in[6] += c.ks[d/4][6]
        in[7] += c.ks[d/4][7]

        // Four rounds of mix and permute
        in[0] += in[1]
        in[1] = ((in[1] << 46) | (in[1] >> (64 - 46))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 36) | (in[3] >> (64 - 36))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 19) | (in[5] >> (64 - 19))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 37) | (in[7] >> (64 - 37))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]

        in[0] += in[1]
        in[1] = ((in[1] << 33) | (in[1] >> (64 - 33))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 27) | (in[3] >> (64 - 27))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 14) | (in[5] >> (64 - 14))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 42) | (in[7] >> (64 - 42))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]

        in[0] += in[1]
        in[1] = ((in[1] << 17) | (in[1] >> (64 - 17))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 49) | (in[3] >> (64 - 49))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 36) | (in[5] >> (64 - 36))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 39) | (in[7] >> (64 - 39))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]

        in[0] += in[1]
        in[1] = ((in[1] << 44) | (in[1] >> (64 - 44))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 9) | (in[3] >> (64 - 9))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 54) | (in[5] >> (64 - 54))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 56) | (in[7] >> (64 - 56))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]

        // Add round key
        in[0] += c.ks[(d/4)+1][0]
        in[1] += c.ks[(d/4)+1][1]
        in[2] += c.ks[(d/4)+1][2]
        in[3] += c.ks[(d/4)+1][3]
        in[4] += c.ks[(d/4)+1][4]
        in[5] += c.ks[(d/4)+1][5]
        in[6] += c.ks[(d/4)+1][6]
        in[7] += c.ks[(d/4)+1][7]

        // Four rounds of mix and permute
        in[0] += in[1]
        in[1] = ((in[1] << 39) | (in[1] >> (64 - 39))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 30) | (in[3] >> (64 - 30))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 34) | (in[5] >> (64 - 34))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 24) | (in[7] >> (64 - 24))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]

        in[0] += in[1]
        in[1] = ((in[1] << 13) | (in[1] >> (64 - 13))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 50) | (in[3] >> (64 - 50))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 10) | (in[5] >> (64 - 10))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 17) | (in[7] >> (64 - 17))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]

        in[0] += in[1]
        in[1] = ((in[1] << 25) | (in[1] >> (64 - 25))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 29) | (in[3] >> (64 - 29))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 39) | (in[5] >> (64 - 39))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 43) | (in[7] >> (64 - 43))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]

        in[0] += in[1]
        in[1] = ((in[1] << 8) | (in[1] >> (64 - 8))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 35) | (in[3] >> (64 - 35))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 56) | (in[5] >> (64 - 56))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 22) | (in[7] >> (64 - 22))) ^ in[6]
        in[0], in[2], in[3], in[4], in[6], in[7] = in[2], in[4], in[7], in[6], in[0], in[3]
    }

    // Add the final round key
    in[0] += c.ks[numRounds512/4][0]
    in[1] += c.ks[numRounds512/4][1]
    in[2] += c.ks[numRounds512/4][2]
    in[3] += c.ks[numRounds512/4][3]
    in[4] += c.ks[numRounds512/4][4]
    in[5] += c.ks[numRounds512/4][5]
    in[6] += c.ks[numRounds512/4][6]
    in[7] += c.ks[numRounds512/4][7]

    // Store the ciphertext in destination
    storeWord(dst[0:8], in[0])
    storeWord(dst[8:16], in[1])
    storeWord(dst[16:24], in[2])
    storeWord(dst[24:32], in[3])
    storeWord(dst[32:40], in[4])
    storeWord(dst[40:48], in[5])
    storeWord(dst[48:56], in[6])
    storeWord(dst[56:64], in[7])
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher512) Decrypt(dst, src []byte) {
    // Load the ciphertext
    ct := new([numWords512]uint64)
    ct[0] = loadWord(src[0:8])
    ct[1] = loadWord(src[8:16])
    ct[2] = loadWord(src[16:24])
    ct[3] = loadWord(src[24:32])
    ct[4] = loadWord(src[32:40])
    ct[5] = loadWord(src[40:48])
    ct[6] = loadWord(src[48:56])
    ct[7] = loadWord(src[56:64])

    // Subtract the final round key
    ct[0] -= c.ks[numRounds512/4][0]
    ct[1] -= c.ks[numRounds512/4][1]
    ct[2] -= c.ks[numRounds512/4][2]
    ct[3] -= c.ks[numRounds512/4][3]
    ct[4] -= c.ks[numRounds512/4][4]
    ct[5] -= c.ks[numRounds512/4][5]
    ct[6] -= c.ks[numRounds512/4][6]
    ct[7] -= c.ks[numRounds512/4][7]

    // Perform decryption rounds
    for d := numRounds512 - 1; d >= 0; d -= 8 {
        // Four rounds of permute and unmix
        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 22)) | ((ct[7] ^ ct[6]) >> 22)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 56)) | ((ct[5] ^ ct[4]) >> 56)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 35)) | ((ct[3] ^ ct[2]) >> 35)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 8)) | ((ct[1] ^ ct[0]) >> 8)
        ct[0] -= ct[1]

        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 43)) | ((ct[7] ^ ct[6]) >> 43)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 39)) | ((ct[5] ^ ct[4]) >> 39)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 29)) | ((ct[3] ^ ct[2]) >> 29)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 25)) | ((ct[1] ^ ct[0]) >> 25)
        ct[0] -= ct[1]

        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 17)) | ((ct[7] ^ ct[6]) >> 17)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 10)) | ((ct[5] ^ ct[4]) >> 10)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 50)) | ((ct[3] ^ ct[2]) >> 50)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 13)) | ((ct[1] ^ ct[0]) >> 13)
        ct[0] -= ct[1]

        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 24)) | ((ct[7] ^ ct[6]) >> 24)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 34)) | ((ct[5] ^ ct[4]) >> 34)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 30)) | ((ct[3] ^ ct[2]) >> 30)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 39)) | ((ct[1] ^ ct[0]) >> 39)
        ct[0] -= ct[1]

        // Subtract round key
        ct[0] -= c.ks[d/4][0]
        ct[1] -= c.ks[d/4][1]
        ct[2] -= c.ks[d/4][2]
        ct[3] -= c.ks[d/4][3]
        ct[4] -= c.ks[d/4][4]
        ct[5] -= c.ks[d/4][5]
        ct[6] -= c.ks[d/4][6]
        ct[7] -= c.ks[d/4][7]

        // Four rounds of permute and unmix
        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 56)) | ((ct[7] ^ ct[6]) >> 56)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 54)) | ((ct[5] ^ ct[4]) >> 54)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 9)) | ((ct[3] ^ ct[2]) >> 9)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 44)) | ((ct[1] ^ ct[0]) >> 44)
        ct[0] -= ct[1]

        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 39)) | ((ct[7] ^ ct[6]) >> 39)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 36)) | ((ct[5] ^ ct[4]) >> 36)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 49)) | ((ct[3] ^ ct[2]) >> 49)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 17)) | ((ct[1] ^ ct[0]) >> 17)
        ct[0] -= ct[1]

        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 42)) | ((ct[7] ^ ct[6]) >> 42)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 14)) | ((ct[5] ^ ct[4]) >> 14)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 27)) | ((ct[3] ^ ct[2]) >> 27)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 33)) | ((ct[1] ^ ct[0]) >> 33)
        ct[0] -= ct[1]

        ct[0], ct[2], ct[3], ct[4], ct[6], ct[7] = ct[6], ct[0], ct[7], ct[2], ct[4], ct[3]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 37)) | ((ct[7] ^ ct[6]) >> 37)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 19)) | ((ct[5] ^ ct[4]) >> 19)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 36)) | ((ct[3] ^ ct[2]) >> 36)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 46)) | ((ct[1] ^ ct[0]) >> 46)
        ct[0] -= ct[1]

        // Subtract round key
        ct[0] -= c.ks[(d/4)-1][0]
        ct[1] -= c.ks[(d/4)-1][1]
        ct[2] -= c.ks[(d/4)-1][2]
        ct[3] -= c.ks[(d/4)-1][3]
        ct[4] -= c.ks[(d/4)-1][4]
        ct[5] -= c.ks[(d/4)-1][5]
        ct[6] -= c.ks[(d/4)-1][6]
        ct[7] -= c.ks[(d/4)-1][7]
    }

    // Store decrypted value in destination
    storeWord(dst[0:8], ct[0])
    storeWord(dst[8:16], ct[1])
    storeWord(dst[16:24], ct[2])
    storeWord(dst[24:32], ct[3])
    storeWord(dst[32:40], ct[4])
    storeWord(dst[40:48], ct[5])
    storeWord(dst[48:56], ct[6])
    storeWord(dst[56:64], ct[7])
}
