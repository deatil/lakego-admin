package skein512

import (
    "crypto/cipher"
)

// BlockSize is the block size of Skein-512 in bytes.
const BlockSize = 64

type skein512Cipher struct {
    k [8]uint64
    t [2]uint64

    x  [64]byte
    nx int

    counter uint64
}

// NewCipher returns a cipher.Stream for encrypting a message with the given key
// and nonce. The same key-nonce combination must not be used to encrypt more
// than one message. There are no limits on the length of key or nonce.
func NewCipher(key []byte, nonce []byte) cipher.Stream {
    c := new(skein512Cipher)
    c.expandKey(key, nonce)

    return c
}

// XORKeyStream XORs each byte in the given slice with the next byte from the
// hash output. Dst and src may point to the same memory.
func (cip *skein512Cipher) XORKeyStream(dst, src []byte) {
    left := BlockSize - cip.nx

    if len(src) < left {
        for i, v := range src {
            dst[i] = v ^ cip.x[cip.nx]
            cip.nx++
        }
        return
    }

    for i, b := range cip.x[cip.nx:] {
        dst[i] = src[i] ^ b
    }
    dst = dst[left:]
    src = src[left:]
    cip.nextBlock()

    for len(src) >= BlockSize {
        for i, v := range src[:BlockSize] {
            dst[i] = v ^ cip.x[i]
        }
        dst = dst[BlockSize:]
        src = src[BlockSize:]
        cip.nextBlock()
    }
    if len(src) > 0 {
        for i, v := range src {
            dst[i] = v ^ cip.x[i]
            cip.nx++
        }
    }
}

func (cip *skein512Cipher) expandKey(key []byte, nonce []byte) {
    // Key argument comes before configuration.
    cip.addArg(keyArg, key)
    // Configuration.
    cip.addConfig(streamOutLen * 8)

    if nonce != nil {
        cip.addArg(nonceArg, nonce)
    }

    // Init tweak to first message block.
    cip.t[0] = 0
    cip.t[1] = messageArg<<56 | firstBlockFlag

    cip.nx = BlockSize
}

func (cip *skein512Cipher) hashLastBlock() {
    // Pad buffer with zeros.
    for i := cip.nx; i < len(cip.x); i++ {
        cip.x[i] = 0
    }
    // Set last block flag.
    cip.t[1] |= lastBlockFlag
    // Process last block.
    cip.hashBlock(cip.x[:], uint64(cip.nx))
    cip.nx = 0
}

func (cip *skein512Cipher) outputBlock(dst *[64]byte, counter uint64) {
    var u [8]uint64
    u[0] = counter

    block(&cip.k, outTweak, &u, &u)

    for i, v := range u {
        dst[i*8+0] = byte(v)
        dst[i*8+1] = byte(v >> 8)
        dst[i*8+2] = byte(v >> 16)
        dst[i*8+3] = byte(v >> 24)
        dst[i*8+4] = byte(v >> 32)
        dst[i*8+5] = byte(v >> 40)
        dst[i*8+6] = byte(v >> 48)
        dst[i*8+7] = byte(v >> 56)
    }
}

func (cip *skein512Cipher) update(b []byte) {
    left := 64 - cip.nx
    if len(b) > left {
        // Process leftovers.
        copy(cip.x[cip.nx:], b[:left])
        b = b[left:]
        cip.hashBlock(cip.x[:], 64)
        cip.nx = 0
    }

    // Process full blocks except for the last one.
    for len(b) > 64 {
        cip.hashBlock(b, 64)
        b = b[64:]
    }

    // Save leftovers.
    cip.nx += copy(cip.x[cip.nx:], b)
}

func (cip *skein512Cipher) hashBlock(b []byte, unpaddedLen uint64) {
    var u [8]uint64

    // Update block counter.
    cip.t[0] += unpaddedLen

    u[0] = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
        uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
    u[1] = uint64(b[8]) | uint64(b[9])<<8 | uint64(b[10])<<16 | uint64(b[11])<<24 |
        uint64(b[12])<<32 | uint64(b[13])<<40 | uint64(b[14])<<48 | uint64(b[15])<<56
    u[2] = uint64(b[16]) | uint64(b[17])<<8 | uint64(b[18])<<16 | uint64(b[19])<<24 |
        uint64(b[20])<<32 | uint64(b[21])<<40 | uint64(b[22])<<48 | uint64(b[23])<<56
    u[3] = uint64(b[24]) | uint64(b[25])<<8 | uint64(b[26])<<16 | uint64(b[27])<<24 |
        uint64(b[28])<<32 | uint64(b[29])<<40 | uint64(b[30])<<48 | uint64(b[31])<<56
    u[4] = uint64(b[32]) | uint64(b[33])<<8 | uint64(b[34])<<16 | uint64(b[35])<<24 |
        uint64(b[36])<<32 | uint64(b[37])<<40 | uint64(b[38])<<48 | uint64(b[39])<<56
    u[5] = uint64(b[40]) | uint64(b[41])<<8 | uint64(b[42])<<16 | uint64(b[43])<<24 |
        uint64(b[44])<<32 | uint64(b[45])<<40 | uint64(b[46])<<48 | uint64(b[47])<<56
    u[6] = uint64(b[48]) | uint64(b[49])<<8 | uint64(b[50])<<16 | uint64(b[51])<<24 |
        uint64(b[52])<<32 | uint64(b[53])<<40 | uint64(b[54])<<48 | uint64(b[55])<<56
    u[7] = uint64(b[56]) | uint64(b[57])<<8 | uint64(b[58])<<16 | uint64(b[59])<<24 |
        uint64(b[60])<<32 | uint64(b[61])<<40 | uint64(b[62])<<48 | uint64(b[63])<<56

    block(&cip.k, cip.t, &cip.k, &u)

    // Clear first block flag.
    cip.t[1] &^= firstBlockFlag
}

// nextBlock puts the next hash output block into the internal buffer.
func (cip *skein512Cipher) nextBlock() {
    cip.outputBlock(&cip.x, cip.counter)
    cip.counter++ // increment counter
    cip.nx = 0
}

// addArg adds Skein argument into the hash state.
func (cip *skein512Cipher) addArg(argType uint64, arg []byte) {
    cip.t[0] = 0
    cip.t[1] = argType<<56 | firstBlockFlag
    cip.update(arg)
    cip.hashLastBlock()
}

// addConfig adds configuration block into the hash state.
func (cip *skein512Cipher) addConfig(outBits uint64) {
    var c [32]byte
    copy(c[:], schemaId)

    c[8] = byte(outBits)
    c[9] = byte(outBits >> 8)
    c[10] = byte(outBits >> 16)
    c[11] = byte(outBits >> 24)
    c[12] = byte(outBits >> 32)
    c[13] = byte(outBits >> 40)
    c[14] = byte(outBits >> 48)
    c[15] = byte(outBits >> 56)

    cip.addArg(configArg, c[:])
}
