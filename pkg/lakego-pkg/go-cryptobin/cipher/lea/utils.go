package lea

import (
    "math/bits"
    "encoding/binary"
)

func rotl32(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotr32(x, n uint32) uint32 {
    return rotl32(x, 32 - n);
}

// Endianness option
const littleEndian bool = true

func bytesToUint32s(inp []byte) [4]uint32 {
    var blk [4]uint32

    if littleEndian {
        blk[0] = binary.LittleEndian.Uint32(inp[0:])
        blk[1] = binary.LittleEndian.Uint32(inp[4:])
        blk[2] = binary.LittleEndian.Uint32(inp[8:])
        blk[3] = binary.LittleEndian.Uint32(inp[12:])
    } else {
        blk[0] = binary.BigEndian.Uint32(inp[0:])
        blk[1] = binary.BigEndian.Uint32(inp[4:])
        blk[2] = binary.BigEndian.Uint32(inp[8:])
        blk[3] = binary.BigEndian.Uint32(inp[12:])
    }

    return blk
}

func Uint32sToBytes(blk [4]uint32) [16]byte {
    var sav [16]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk[0])
        binary.LittleEndian.PutUint32(sav[4:], blk[1])
        binary.LittleEndian.PutUint32(sav[8:], blk[2])
        binary.LittleEndian.PutUint32(sav[12:], blk[3])
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk[0])
        binary.BigEndian.PutUint32(sav[4:], blk[1])
        binary.BigEndian.PutUint32(sav[8:], blk[2])
        binary.BigEndian.PutUint32(sav[12:], blk[3])
    }

    return sav
}

func bytesToUint32(inp []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(inp[0:])
    } else {
        return binary.BigEndian.Uint32(inp[0:])
    }
}

func Uint32ToBytes(inp uint32) [4]byte {
    var sav [4]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], inp)
    } else {
        binary.BigEndian.PutUint32(sav[0:], inp)
    }

    return sav
}
