package jh

import (
    "unsafe"
)

// The size of an JH checksum in bytes.
const Size = 32

// The blocksize of JH in bytes.
const BlockSize = 64

// For memset
var zeroBuf64Byte [64]byte

type digest struct {
    s   [64]byte
    x   [8][2]uint64
    nx  uint64
    len uint64
}

func newDigest() *digest {
    d := new(digest)
    d.Reset()

    return d
}

func (d *digest) Reset() {
    d.len = 0
    d.nx = 0
    d.x = jh256H0
}

func (d *digest) Size() int {
    return Size
}

func (d *digest) BlockSize() int {
    return BlockSize
}

// hash each 512-bit message block, except the last partial block
func (d *digest) Write(data []byte) (n int, err error) {
    var index uint64 = 0

    plen := uint64(len(data)) * 8
    d.len += plen

    if d.nx > 0 && d.nx+plen < 512 {
        if plen&7 == 0 {
            copy(d.s[d.nx>>3:], data[:64-(d.nx>>3)])
        } else {
            copy(d.s[d.nx>>3:], data[:64-(d.nx>>3)+1])
        }
        d.nx += plen
        plen = 0
    }

    if d.nx > 0 && d.nx + plen >= 512 {
        copy(d.s[d.nx>>3:], data[:64-(d.nx>>3)])

        index = 64 - (d.nx >> 3)
        plen -= 512 - d.nx

        d.f8()
        d.nx = 0
    }

    for plen >= 512 {
        copy(d.s[:], data[index:index+64])

        d.f8()
        index += 64
        plen -= 512
    }

    if plen > 0 {
        if plen&7 == 0 {
            copy(d.s[:((plen&0x1ff)>>3)], data[index:])
        } else {
            copy(d.s[:((plen&0x1ff)>>3)+1], data[index:])
        }

        d.nx = plen
    }

    return len(data), nil
}

// Sum pads the message, process the padded block(s), truncate the hash value H to obtain the message digest
func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest) checkSum() *[Size]byte {
    var i uint64

    if d.len&0x1ff == 0 {
        d.s = zeroBuf64Byte
        d.s[0] = 0x80

        PUTU64BE(d.s[56:], d.len)

        d.f8()
    } else {
        // set the rest of the bytes in the buffer to 0
        if d.nx&7 == 0 {
            for i = (d.len & 0x1ff) >> 3; i < 64; i++ {
                d.s[i] = 0
            }
        } else {
            for i = ((d.len & 0x1ff) >> 3) + 1; i < 64; i++ {
                d.s[i] = 0
            }
        }

        // pad and process the partial block when plen is not multiple of 512 bits, then hash the padded blocks
        d.s[(d.len&0x1ff)>>3] |= 1 << (7 - (d.len & 7))

        d.f8()
        d.s = zeroBuf64Byte

        PUTU64BE(d.s[56:], d.len)

        d.f8()
    }

    return (*[32]byte)(unsafe.Pointer(&d.x[6][0]))
}

// The compression function F8.
func (d *digest) f8() {
    var i uint64

    for i = 0; i < 8; i++ {
        d.x[i>>1][i&1] ^= GETU64(d.s[8*i:])
    }

    d.e8()

    for i = 0; i < 8; i++ {
        d.x[(8+i)>>1][(8+i)&1] ^= GETU64(d.s[8*i:])
    }
}

// The bijective function E8, in bitslice form.
func (d *digest) e8() {
    var i, roundnumber, temp0 uint64

    for roundnumber = 0; roundnumber < 42; roundnumber += 7 {
        // round 7*roundnumber+0: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i], e8BitsliceRoundconstant[roundnumber+0][i], e8BitsliceRoundconstant[roundnumber+0][i+2])
            L(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i])
            SWAP1(&d.x[1][i])
            SWAP1(&d.x[3][i])
            SWAP1(&d.x[5][i])
            SWAP1(&d.x[7][i])
        }

        // round 7*roundnumber+1: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i], e8BitsliceRoundconstant[roundnumber+1][i], e8BitsliceRoundconstant[roundnumber+1][i+2])
            L(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i])
            SWAP2(&d.x[1][i])
            SWAP2(&d.x[3][i])
            SWAP2(&d.x[5][i])
            SWAP2(&d.x[7][i])
        }

        // round 7*roundnumber+2: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i], e8BitsliceRoundconstant[roundnumber+2][i], e8BitsliceRoundconstant[roundnumber+2][i+2])
            L(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i])
            SWAP4(&d.x[1][i])
            SWAP4(&d.x[3][i])
            SWAP4(&d.x[5][i])
            SWAP4(&d.x[7][i])
        }

        // round 7*roundnumber+3: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i], e8BitsliceRoundconstant[roundnumber+3][i], e8BitsliceRoundconstant[roundnumber+3][i+2])
            L(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i])
            SWAP8(&d.x[1][i])
            SWAP8(&d.x[3][i])
            SWAP8(&d.x[5][i])
            SWAP8(&d.x[7][i])
        }

        // round 7*roundnumber+4: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i], e8BitsliceRoundconstant[roundnumber+4][i], e8BitsliceRoundconstant[roundnumber+4][i+2])
            L(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i])
            SWAP16(&d.x[1][i])
            SWAP16(&d.x[3][i])
            SWAP16(&d.x[5][i])
            SWAP16(&d.x[7][i])
        }

        // round 7*roundnumber+5: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i], e8BitsliceRoundconstant[roundnumber+5][i], e8BitsliceRoundconstant[roundnumber+5][i+2])
            L(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i])
            SWAP32(&d.x[1][i])
            SWAP32(&d.x[3][i])
            SWAP32(&d.x[5][i])
            SWAP32(&d.x[7][i])
        }

        // round 7*roundnumber+6: Sbox and MDS layers
        for i = 0; i < 2; i++ {
            SS(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i], e8BitsliceRoundconstant[roundnumber+6][i], e8BitsliceRoundconstant[roundnumber+6][i+2])
            L(&d.x[0][i], &d.x[2][i], &d.x[4][i], &d.x[6][i], &d.x[1][i], &d.x[3][i], &d.x[5][i], &d.x[7][i])
        }

        // round 7*roundnumber+6: swapping layer
        for i = 1; i < 8; i = i + 2 {
            temp0 = d.x[i][0]
            d.x[i][0] = d.x[i][1]
            d.x[i][1] = temp0
        }
    }
}
