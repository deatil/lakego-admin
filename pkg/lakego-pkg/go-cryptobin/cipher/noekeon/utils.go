package noekeon

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint32(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint32(b[j:])
        }
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        if littleEndian {
            binary.LittleEndian.PutUint32(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint32(dst[j:], w[i])
        }
    }

    return dst
}

func bytesToUint32(inp []byte) (blk uint32) {
    if littleEndian {
        blk = binary.LittleEndian.Uint32(inp[0:])
    } else {
        blk = binary.BigEndian.Uint32(inp[0:])
    }

    return
}

func uint32ToBytes(blk uint32) [4]byte {
    var sav [4]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk)
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk)
    }

    return sav
}

func ROLc(x uint32, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func RORc(x uint32, n uint32) uint32 {
    return ROLc(x, 32 - n);
}

var RC = []uint32{
   0x00000080, 0x0000001b, 0x00000036, 0x0000006c,
   0x000000d8, 0x000000ab, 0x0000004d, 0x0000009a,
   0x0000002f, 0x0000005e, 0x000000bc, 0x00000063,
   0x000000c6, 0x00000097, 0x00000035, 0x0000006a,
   0x000000d4,
}

func kTHETA(a, b, c, d *uint32) {
    var temp uint32

    temp = (*a) ^ (*c)
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8)

    (*b) ^= temp
    (*d) ^= temp

    temp = (*b) ^ (*d)
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8)

    (*a) ^= temp
    (*c) ^= temp
}

func THETA(k []uint32, a, b, c, d *uint32) {
    var temp uint32

    temp = (*a) ^ (*c)
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8)

    (*b) ^= temp ^ k[1]
    (*d) ^= temp ^ k[3]

    temp = (*b) ^ (*d)
    temp = temp ^ ROLc(temp, 8) ^ RORc(temp, 8)

    (*a) ^= temp ^ k[0]
    (*c) ^= temp ^ k[2]
}

func GAMMA(a, b, c, d *uint32) {
    (*b) ^= ^((*d) | (*c))
    (*a) ^= (*c) & (*b)

    (*d), (*a) = (*a), (*d)

    (*c) ^= (*a) ^ (*b) ^ (*d)
    (*b) ^= ^((*d) | (*c))
    (*a) ^= (*c) & (*b)
}

func PI1(a, b, c, d *uint32) {
    (*b) = ROLc((*b), 1)
    (*c) = ROLc((*c), 5)
    (*d) = ROLc((*d), 2)
}

func PI2(a, b, c, d *uint32) {
    (*b) = RORc((*b), 1)
    (*c) = RORc((*c), 5)
    (*d) = RORc((*d), 2)
}
