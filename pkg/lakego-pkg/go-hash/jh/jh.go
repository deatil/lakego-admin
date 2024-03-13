// Package jh implements JH-256 algorithm.
package jh

import (
    "hash"
    "unsafe"
    "encoding/binary"
)

// The size of an jh checksum in bytes.
const Size = 32

// The blocksize of jh in bytes.
const BlockSize = 64

func Sum(data []byte) (sum [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

// For memset
var zeroBuf64Byte [64]byte

type digest struct {
    hashbitlen       int          // the message digest size
    databitlen       uint64       // the message size in bits
    datasizeInBuffer uint64       // the size of the message remained in buffer; assumed to be multiple of 8bits except for the last partial block at the end of the message
    x                [8][2]uint64 // the 1024-bit state, ( x[i][0] || x[i][1] ) is the ith row of the state in the pseudocod
    buffer           [64]byte     // the 512-bit message block to be hashed
}

func New() hash.Hash {
    return &digest{
        hashbitlen: 256,
        x: jh256H0,
    }
}

func (s *digest) Reset() {
    s.hashbitlen = 256
    s.databitlen = 0
    s.datasizeInBuffer = 0
    s.x = jh256H0
}

func (s *digest) Size() int {
    return Size
}

func (s *digest) BlockSize() int {
    return BlockSize
}

// hash each 512-bit message block, except the last partial block
func (s *digest) Write(data []byte) (n int, err error) {
    index := uint64(0) // the starting address of the data to be compressed
    databitlen := uint64(len(data)) * 8
    s.databitlen += databitlen

    // if there is remaining data in the buffer, fill it to a full message block first
    // we assume that the size of the data in the buffer is the multiple of 8 bits if it is not at the end of a message

    // There is data in the buffer, but the incoming data is insufficient for a full block
    if s.datasizeInBuffer > 0 && s.datasizeInBuffer+databitlen < 512 {
        if databitlen&7 == 0 {
            copy(s.buffer[s.datasizeInBuffer>>3:], data[:64-(s.datasizeInBuffer>>3)])
        } else {
            copy(s.buffer[s.datasizeInBuffer>>3:], data[:64-(s.datasizeInBuffer>>3)+1])
        }
        s.datasizeInBuffer += databitlen
        databitlen = 0
    }

    // There is data in the buffer, and the incoming data is sufficient for a full block
    if s.datasizeInBuffer > 0 && s.datasizeInBuffer+databitlen >= 512 {
        copy(s.buffer[s.datasizeInBuffer>>3:], data[:64-(s.datasizeInBuffer>>3)])
        index = 64 - (s.datasizeInBuffer >> 3)
        databitlen -= 512 - s.datasizeInBuffer
        s.f8()
        s.datasizeInBuffer = 0
    }

    // hash the remaining full message blocks
    for databitlen >= 512 {
        copy(s.buffer[:], data[index:index+64])
        s.f8()
        index += 64
        databitlen -= 512
    }

    // store the partial block into buffer, assume that -- if part of the last byte is not part of the message, then that part consists of bits*/
    if databitlen > 0 {
        if databitlen&7 == 0 {
            copy(s.buffer[:((databitlen&0x1ff)>>3)], data[index:])
        } else {
            copy(s.buffer[:((databitlen&0x1ff)>>3)+1], data[index:])
        }
        s.datasizeInBuffer = databitlen
    }

    return len(data), nil
}

// Sum pads the message, process the padded block(s), truncate the hash value H to obtain the message digest
func (s *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *s
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (s *digest) checkSum() *[Size]byte {
    var i uint64

    if s.databitlen&0x1ff == 0 {
        // pad the message when databitlen is multiple of 512 bits, then process the padded block
        s.buffer = zeroBuf64Byte
        s.buffer[0] = 0x80
        s.buffer[63] = uint8(s.databitlen)
        s.buffer[62] = uint8(s.databitlen >> 8)
        s.buffer[61] = uint8(s.databitlen >> 16)
        s.buffer[60] = uint8(s.databitlen >> 24)
        s.buffer[59] = uint8(s.databitlen >> 32)
        s.buffer[58] = uint8(s.databitlen >> 40)
        s.buffer[57] = uint8(s.databitlen >> 48)
        s.buffer[56] = uint8(s.databitlen >> 56)
        s.f8()
    } else {
        // set the rest of the bytes in the buffer to 0
        if s.datasizeInBuffer&7 == 0 {
            for i = (s.databitlen & 0x1ff) >> 3; i < 64; i++ {
                s.buffer[i] = 0
            }
        } else {
            for i = ((s.databitlen & 0x1ff) >> 3) + 1; i < 64; i++ {
                s.buffer[i] = 0
            }
        }

        // pad and process the partial block when databitlen is not multiple of 512 bits, then hash the padded blocks
        s.buffer[(s.databitlen&0x1ff)>>3] |= 1 << (7 - (s.databitlen & 7))

        s.f8()
        s.buffer = zeroBuf64Byte
        s.buffer[63] = uint8(s.databitlen)
        s.buffer[62] = uint8(s.databitlen >> 8)
        s.buffer[61] = uint8(s.databitlen >> 16)
        s.buffer[60] = uint8(s.databitlen >> 24)
        s.buffer[59] = uint8(s.databitlen >> 32)
        s.buffer[58] = uint8(s.databitlen >> 40)
        s.buffer[57] = uint8(s.databitlen >> 48)
        s.buffer[56] = uint8(s.databitlen >> 56)
        s.f8()
    }

    return (*[32]byte)(unsafe.Pointer(&s.x[6][0]))
}

// The compression function F8.
func (s *digest) f8() {
    var i uint64

    // xor the 512-bit message with the fist half of the 1024-bit hash state
    for i = 0; i < 8; i++ {
        s.x[i>>1][i&1] ^= binary.LittleEndian.Uint64(s.buffer[8*i:])
    }

    // the bijective function E8
    s.e8()

    // xor the 512-bit message with the second half of the 1024-bit hash state
    for i = 0; i < 8; i++ {
        s.x[(8+i)>>1][(8+i)&1] ^= binary.LittleEndian.Uint64(s.buffer[8*i:])
    }
}

// The bijective function E8, in bitslice form.
func (s *digest) e8() {
    var i, roundnumber, temp0 uint64

    for roundnumber = 0; roundnumber < 42; roundnumber += 7 {
        // round 7*roundnumber+0: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i], e8BitsliceRoundconstant[roundnumber+0][i], e8BitsliceRoundconstant[roundnumber+0][i+2])
            L(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i])
            SWAP1(&s.x[1][i])
            SWAP1(&s.x[3][i])
            SWAP1(&s.x[5][i])
            SWAP1(&s.x[7][i])
        }

        // round 7*roundnumber+1: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i], e8BitsliceRoundconstant[roundnumber+1][i], e8BitsliceRoundconstant[roundnumber+1][i+2])
            L(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i])
            SWAP2(&s.x[1][i])
            SWAP2(&s.x[3][i])
            SWAP2(&s.x[5][i])
            SWAP2(&s.x[7][i])
        }

        // round 7*roundnumber+2: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i], e8BitsliceRoundconstant[roundnumber+2][i], e8BitsliceRoundconstant[roundnumber+2][i+2])
            L(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i])
            SWAP4(&s.x[1][i])
            SWAP4(&s.x[3][i])
            SWAP4(&s.x[5][i])
            SWAP4(&s.x[7][i])
        }

        // round 7*roundnumber+3: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i], e8BitsliceRoundconstant[roundnumber+3][i], e8BitsliceRoundconstant[roundnumber+3][i+2])
            L(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i])
            SWAP8(&s.x[1][i])
            SWAP8(&s.x[3][i])
            SWAP8(&s.x[5][i])
            SWAP8(&s.x[7][i])
        }

        // round 7*roundnumber+4: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i], e8BitsliceRoundconstant[roundnumber+4][i], e8BitsliceRoundconstant[roundnumber+4][i+2])
            L(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i])
            SWAP16(&s.x[1][i])
            SWAP16(&s.x[3][i])
            SWAP16(&s.x[5][i])
            SWAP16(&s.x[7][i])
        }

        // round 7*roundnumber+5: Sbox, MDS and Swapping layers
        for i = 0; i < 2; i++ {
            SS(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i], e8BitsliceRoundconstant[roundnumber+5][i], e8BitsliceRoundconstant[roundnumber+5][i+2])
            L(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i])
            SWAP32(&s.x[1][i])
            SWAP32(&s.x[3][i])
            SWAP32(&s.x[5][i])
            SWAP32(&s.x[7][i])
        }

        // round 7*roundnumber+6: Sbox and MDS layers
        for i = 0; i < 2; i++ {
            SS(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i], e8BitsliceRoundconstant[roundnumber+6][i], e8BitsliceRoundconstant[roundnumber+6][i+2])
            L(&s.x[0][i], &s.x[2][i], &s.x[4][i], &s.x[6][i], &s.x[1][i], &s.x[3][i], &s.x[5][i], &s.x[7][i])
        }

        // round 7*roundnumber+6: swapping layer
        for i = 1; i < 8; i = i + 2 {
            temp0 = s.x[i][0]
            s.x[i][0] = s.x[i][1]
            s.x[i][1] = temp0
        }
    }
}
