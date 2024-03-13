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

// New1024 creates a new Threefish cipher with a block size of 1024 bits.
// The key argument must be 64 bytes and the tweak argument must be 16 bytes.
func New1024(key, tweak []byte) (cipher.Block, error) {
    // Length check the provided key
    if len(key) != BlockSize1024 {
        return nil, KeySizeError(BlockSize1024)
    }

    c := new(cipher1024)

    // Load and extend the tweak value
    if err := calculateTweak(&c.t, tweak); err != nil {
        return nil, err
    }

    // Load and extend the key
    k := new([numWords1024 + 1]uint64)
    k[numWords1024] = c240
    for i := 0; i < numWords1024; i++ {
        k[i] = loadWord(key[i*8 : (i+1)*8])
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

    return c, nil
}

// BlockSize returns the block size of a 1024-bit cipher.
func (c *cipher1024) BlockSize() int {
    return BlockSize1024
}

// Encrypt loads plaintext from src, encrypts it, and stores it in dst.
func (c *cipher1024) Encrypt(dst, src []byte) {
    // Load the input
    in := new([numWords1024]uint64)
    in[0] = loadWord(src[0:8])
    in[1] = loadWord(src[8:16])
    in[2] = loadWord(src[16:24])
    in[3] = loadWord(src[24:32])
    in[4] = loadWord(src[32:40])
    in[5] = loadWord(src[40:48])
    in[6] = loadWord(src[48:56])
    in[7] = loadWord(src[56:64])
    in[8] = loadWord(src[64:72])
    in[9] = loadWord(src[72:80])
    in[10] = loadWord(src[80:88])
    in[11] = loadWord(src[88:96])
    in[12] = loadWord(src[96:104])
    in[13] = loadWord(src[104:112])
    in[14] = loadWord(src[112:120])
    in[15] = loadWord(src[120:128])

    // Perform encryption rounds
    for d := 0; d < numRounds1024; d += 8 {
        // Add round key
        in[0] += c.ks[d/4][0]
        in[1] += c.ks[d/4][1]
        in[2] += c.ks[d/4][2]
        in[3] += c.ks[d/4][3]
        in[4] += c.ks[d/4][4]
        in[5] += c.ks[d/4][5]
        in[6] += c.ks[d/4][6]
        in[7] += c.ks[d/4][7]
        in[8] += c.ks[d/4][8]
        in[9] += c.ks[d/4][9]
        in[10] += c.ks[d/4][10]
        in[11] += c.ks[d/4][11]
        in[12] += c.ks[d/4][12]
        in[13] += c.ks[d/4][13]
        in[14] += c.ks[d/4][14]
        in[15] += c.ks[d/4][15]

        // Four rounds of mix and permute
        in[0] += in[1]
        in[1] = ((in[1] << 24) | (in[1] >> (64 - 24))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 13) | (in[3] >> (64 - 13))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 8) | (in[5] >> (64 - 8))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 47) | (in[7] >> (64 - 47))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 8) | (in[9] >> (64 - 8))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 17) | (in[11] >> (64 - 17))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 22) | (in[13] >> (64 - 22))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 37) | (in[15] >> (64 - 37))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 38) | (in[1] >> (64 - 38))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 19) | (in[3] >> (64 - 19))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 10) | (in[5] >> (64 - 10))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 55) | (in[7] >> (64 - 55))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 49) | (in[9] >> (64 - 49))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 18) | (in[11] >> (64 - 18))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 23) | (in[13] >> (64 - 23))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 52) | (in[15] >> (64 - 52))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 33) | (in[1] >> (64 - 33))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 4) | (in[3] >> (64 - 4))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 51) | (in[5] >> (64 - 51))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 13) | (in[7] >> (64 - 13))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 34) | (in[9] >> (64 - 34))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 41) | (in[11] >> (64 - 41))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 59) | (in[13] >> (64 - 59))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 17) | (in[15] >> (64 - 17))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 5) | (in[1] >> (64 - 5))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 20) | (in[3] >> (64 - 20))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 48) | (in[5] >> (64 - 48))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 41) | (in[7] >> (64 - 41))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 47) | (in[9] >> (64 - 47))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 28) | (in[11] >> (64 - 28))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 16) | (in[13] >> (64 - 16))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 25) | (in[15] >> (64 - 25))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]

        // Add round key
        in[0] += c.ks[(d/4)+1][0]
        in[1] += c.ks[(d/4)+1][1]
        in[2] += c.ks[(d/4)+1][2]
        in[3] += c.ks[(d/4)+1][3]
        in[4] += c.ks[(d/4)+1][4]
        in[5] += c.ks[(d/4)+1][5]
        in[6] += c.ks[(d/4)+1][6]
        in[7] += c.ks[(d/4)+1][7]
        in[8] += c.ks[(d/4)+1][8]
        in[9] += c.ks[(d/4)+1][9]
        in[10] += c.ks[(d/4)+1][10]
        in[11] += c.ks[(d/4)+1][11]
        in[12] += c.ks[(d/4)+1][12]
        in[13] += c.ks[(d/4)+1][13]
        in[14] += c.ks[(d/4)+1][14]
        in[15] += c.ks[(d/4)+1][15]

        // Four rounds of mix and permute
        in[0] += in[1]
        in[1] = ((in[1] << 41) | (in[1] >> (64 - 41))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 9) | (in[3] >> (64 - 9))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 37) | (in[5] >> (64 - 37))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 31) | (in[7] >> (64 - 31))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 12) | (in[9] >> (64 - 12))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 47) | (in[11] >> (64 - 47))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 44) | (in[13] >> (64 - 44))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 30) | (in[15] >> (64 - 30))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 16) | (in[1] >> (64 - 16))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 34) | (in[3] >> (64 - 34))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 56) | (in[5] >> (64 - 56))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 51) | (in[7] >> (64 - 51))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 4) | (in[9] >> (64 - 4))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 53) | (in[11] >> (64 - 53))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 42) | (in[13] >> (64 - 42))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 41) | (in[15] >> (64 - 41))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 31) | (in[1] >> (64 - 31))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 44) | (in[3] >> (64 - 44))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 47) | (in[5] >> (64 - 47))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 46) | (in[7] >> (64 - 46))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 19) | (in[9] >> (64 - 19))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 42) | (in[11] >> (64 - 42))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 44) | (in[13] >> (64 - 44))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 25) | (in[15] >> (64 - 25))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]

        in[0] += in[1]
        in[1] = ((in[1] << 9) | (in[1] >> (64 - 9))) ^ in[0]
        in[2] += in[3]
        in[3] = ((in[3] << 48) | (in[3] >> (64 - 48))) ^ in[2]
        in[4] += in[5]
        in[5] = ((in[5] << 35) | (in[5] >> (64 - 35))) ^ in[4]
        in[6] += in[7]
        in[7] = ((in[7] << 52) | (in[7] >> (64 - 52))) ^ in[6]
        in[8] += in[9]
        in[9] = ((in[9] << 23) | (in[9] >> (64 - 23))) ^ in[8]
        in[10] += in[11]
        in[11] = ((in[11] << 31) | (in[11] >> (64 - 31))) ^ in[10]
        in[12] += in[13]
        in[13] = ((in[13] << 37) | (in[13] >> (64 - 37))) ^ in[12]
        in[14] += in[15]
        in[15] = ((in[15] << 20) | (in[15] >> (64 - 20))) ^ in[14]
        in[1], in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15] =
            in[9], in[13], in[6], in[11], in[4], in[15], in[10], in[7], in[12], in[3], in[14], in[5], in[8], in[1]
    }

    // Add the final round key
    in[0] += c.ks[numRounds1024/4][0]
    in[1] += c.ks[numRounds1024/4][1]
    in[2] += c.ks[numRounds1024/4][2]
    in[3] += c.ks[numRounds1024/4][3]
    in[4] += c.ks[numRounds1024/4][4]
    in[5] += c.ks[numRounds1024/4][5]
    in[6] += c.ks[numRounds1024/4][6]
    in[7] += c.ks[numRounds1024/4][7]
    in[8] += c.ks[numRounds1024/4][8]
    in[9] += c.ks[numRounds1024/4][9]
    in[10] += c.ks[numRounds1024/4][10]
    in[11] += c.ks[numRounds1024/4][11]
    in[12] += c.ks[numRounds1024/4][12]
    in[13] += c.ks[numRounds1024/4][13]
    in[14] += c.ks[numRounds1024/4][14]
    in[15] += c.ks[numRounds1024/4][15]

    // Store the ciphertext in destination
    storeWord(dst[0:8], in[0])
    storeWord(dst[8:16], in[1])
    storeWord(dst[16:24], in[2])
    storeWord(dst[24:32], in[3])
    storeWord(dst[32:40], in[4])
    storeWord(dst[40:48], in[5])
    storeWord(dst[48:56], in[6])
    storeWord(dst[56:64], in[7])
    storeWord(dst[64:72], in[8])
    storeWord(dst[72:80], in[9])
    storeWord(dst[80:88], in[10])
    storeWord(dst[88:96], in[11])
    storeWord(dst[96:104], in[12])
    storeWord(dst[104:112], in[13])
    storeWord(dst[112:120], in[14])
    storeWord(dst[120:128], in[15])
}

// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
func (c *cipher1024) Decrypt(dst, src []byte) {
    // Load the ciphertext
    ct := new([numWords1024]uint64)
    ct[0] = loadWord(src[0:8])
    ct[1] = loadWord(src[8:16])
    ct[2] = loadWord(src[16:24])
    ct[3] = loadWord(src[24:32])
    ct[4] = loadWord(src[32:40])
    ct[5] = loadWord(src[40:48])
    ct[6] = loadWord(src[48:56])
    ct[7] = loadWord(src[56:64])
    ct[8] = loadWord(src[64:72])
    ct[9] = loadWord(src[72:80])
    ct[10] = loadWord(src[80:88])
    ct[11] = loadWord(src[88:96])
    ct[12] = loadWord(src[96:104])
    ct[13] = loadWord(src[104:112])
    ct[14] = loadWord(src[112:120])
    ct[15] = loadWord(src[120:128])

    // Subtract the final round key
    ct[0] -= c.ks[numRounds1024/4][0]
    ct[1] -= c.ks[numRounds1024/4][1]
    ct[2] -= c.ks[numRounds1024/4][2]
    ct[3] -= c.ks[numRounds1024/4][3]
    ct[4] -= c.ks[numRounds1024/4][4]
    ct[5] -= c.ks[numRounds1024/4][5]
    ct[6] -= c.ks[numRounds1024/4][6]
    ct[7] -= c.ks[numRounds1024/4][7]
    ct[8] -= c.ks[numRounds1024/4][8]
    ct[9] -= c.ks[numRounds1024/4][9]
    ct[10] -= c.ks[numRounds1024/4][10]
    ct[11] -= c.ks[numRounds1024/4][11]
    ct[12] -= c.ks[numRounds1024/4][12]
    ct[13] -= c.ks[numRounds1024/4][13]
    ct[14] -= c.ks[numRounds1024/4][14]
    ct[15] -= c.ks[numRounds1024/4][15]

    // Perform decryption rounds
    for d := numRounds1024 - 1; d >= 0; d -= 8 {
        // Four rounds of permute and unmix
        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 20)) | ((ct[15] ^ ct[14]) >> 20)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 37)) | ((ct[13] ^ ct[12]) >> 37)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 31)) | ((ct[11] ^ ct[10]) >> 31)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 23)) | ((ct[9] ^ ct[8]) >> 23)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 52)) | ((ct[7] ^ ct[6]) >> 52)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 35)) | ((ct[5] ^ ct[4]) >> 35)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 48)) | ((ct[3] ^ ct[2]) >> 48)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 9)) | ((ct[1] ^ ct[0]) >> 9)
        ct[0] -= ct[1]

        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 25)) | ((ct[15] ^ ct[14]) >> 25)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 44)) | ((ct[13] ^ ct[12]) >> 44)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 42)) | ((ct[11] ^ ct[10]) >> 42)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 19)) | ((ct[9] ^ ct[8]) >> 19)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 46)) | ((ct[7] ^ ct[6]) >> 46)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 47)) | ((ct[5] ^ ct[4]) >> 47)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 44)) | ((ct[3] ^ ct[2]) >> 44)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 31)) | ((ct[1] ^ ct[0]) >> 31)
        ct[0] -= ct[1]

        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 41)) | ((ct[15] ^ ct[14]) >> 41)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 42)) | ((ct[13] ^ ct[12]) >> 42)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 53)) | ((ct[11] ^ ct[10]) >> 53)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 4)) | ((ct[9] ^ ct[8]) >> 4)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 51)) | ((ct[7] ^ ct[6]) >> 51)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 56)) | ((ct[5] ^ ct[4]) >> 56)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 34)) | ((ct[3] ^ ct[2]) >> 34)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 16)) | ((ct[1] ^ ct[0]) >> 16)
        ct[0] -= ct[1]

        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 30)) | ((ct[15] ^ ct[14]) >> 30)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 44)) | ((ct[13] ^ ct[12]) >> 44)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 47)) | ((ct[11] ^ ct[10]) >> 47)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 12)) | ((ct[9] ^ ct[8]) >> 12)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 31)) | ((ct[7] ^ ct[6]) >> 31)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 37)) | ((ct[5] ^ ct[4]) >> 37)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 9)) | ((ct[3] ^ ct[2]) >> 9)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 41)) | ((ct[1] ^ ct[0]) >> 41)
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
        ct[8] -= c.ks[d/4][8]
        ct[9] -= c.ks[d/4][9]
        ct[10] -= c.ks[d/4][10]
        ct[11] -= c.ks[d/4][11]
        ct[12] -= c.ks[d/4][12]
        ct[13] -= c.ks[d/4][13]
        ct[14] -= c.ks[d/4][14]
        ct[15] -= c.ks[d/4][15]

        // Four rounds of permute and unmix
        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 25)) | ((ct[15] ^ ct[14]) >> 25)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 16)) | ((ct[13] ^ ct[12]) >> 16)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 28)) | ((ct[11] ^ ct[10]) >> 28)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 47)) | ((ct[9] ^ ct[8]) >> 47)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 41)) | ((ct[7] ^ ct[6]) >> 41)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 48)) | ((ct[5] ^ ct[4]) >> 48)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 20)) | ((ct[3] ^ ct[2]) >> 20)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 5)) | ((ct[1] ^ ct[0]) >> 5)
        ct[0] -= ct[1]

        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 17)) | ((ct[15] ^ ct[14]) >> 17)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 59)) | ((ct[13] ^ ct[12]) >> 59)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 41)) | ((ct[11] ^ ct[10]) >> 41)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 34)) | ((ct[9] ^ ct[8]) >> 34)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 13)) | ((ct[7] ^ ct[6]) >> 13)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 51)) | ((ct[5] ^ ct[4]) >> 51)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 4)) | ((ct[3] ^ ct[2]) >> 4)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 33)) | ((ct[1] ^ ct[0]) >> 33)
        ct[0] -= ct[1]

        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 52)) | ((ct[15] ^ ct[14]) >> 52)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 23)) | ((ct[13] ^ ct[12]) >> 23)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 18)) | ((ct[11] ^ ct[10]) >> 18)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 49)) | ((ct[9] ^ ct[8]) >> 49)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 55)) | ((ct[7] ^ ct[6]) >> 55)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 10)) | ((ct[5] ^ ct[4]) >> 10)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 19)) | ((ct[3] ^ ct[2]) >> 19)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 38)) | ((ct[1] ^ ct[0]) >> 38)
        ct[0] -= ct[1]

        ct[1], ct[3], ct[4], ct[5], ct[6], ct[7], ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15] =
            ct[15], ct[11], ct[6], ct[13], ct[4], ct[9], ct[14], ct[1], ct[8], ct[5], ct[10], ct[3], ct[12], ct[7]
        ct[15] = ((ct[15] ^ ct[14]) << (64 - 37)) | ((ct[15] ^ ct[14]) >> 37)
        ct[14] -= ct[15]
        ct[13] = ((ct[13] ^ ct[12]) << (64 - 22)) | ((ct[13] ^ ct[12]) >> 22)
        ct[12] -= ct[13]
        ct[11] = ((ct[11] ^ ct[10]) << (64 - 17)) | ((ct[11] ^ ct[10]) >> 17)
        ct[10] -= ct[11]
        ct[9] = ((ct[9] ^ ct[8]) << (64 - 8)) | ((ct[9] ^ ct[8]) >> 8)
        ct[8] -= ct[9]
        ct[7] = ((ct[7] ^ ct[6]) << (64 - 47)) | ((ct[7] ^ ct[6]) >> 47)
        ct[6] -= ct[7]
        ct[5] = ((ct[5] ^ ct[4]) << (64 - 8)) | ((ct[5] ^ ct[4]) >> 8)
        ct[4] -= ct[5]
        ct[3] = ((ct[3] ^ ct[2]) << (64 - 13)) | ((ct[3] ^ ct[2]) >> 13)
        ct[2] -= ct[3]
        ct[1] = ((ct[1] ^ ct[0]) << (64 - 24)) | ((ct[1] ^ ct[0]) >> 24)
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
        ct[8] -= c.ks[(d/4)-1][8]
        ct[9] -= c.ks[(d/4)-1][9]
        ct[10] -= c.ks[(d/4)-1][10]
        ct[11] -= c.ks[(d/4)-1][11]
        ct[12] -= c.ks[(d/4)-1][12]
        ct[13] -= c.ks[(d/4)-1][13]
        ct[14] -= c.ks[(d/4)-1][14]
        ct[15] -= c.ks[(d/4)-1][15]
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
    storeWord(dst[64:72], ct[8])
    storeWord(dst[72:80], ct[9])
    storeWord(dst[80:88], ct[10])
    storeWord(dst[88:96], ct[11])
    storeWord(dst[96:104], ct[12])
    storeWord(dst[104:112], ct[13])
    storeWord(dst[112:120], ct[14])
    storeWord(dst[120:128], ct[15])
}
