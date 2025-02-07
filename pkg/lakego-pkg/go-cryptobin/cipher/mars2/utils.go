package mars2

import (
    "math/bits"
    "encoding/binary"
)

func bytesToUint32s(inp []byte) [4]uint32 {
    var blk [4]uint32

    blk[0] = binary.LittleEndian.Uint32(inp[0:])
    blk[1] = binary.LittleEndian.Uint32(inp[4:])
    blk[2] = binary.LittleEndian.Uint32(inp[8:])
    blk[3] = binary.LittleEndian.Uint32(inp[12:])

    return blk
}

func uint32sToBytes(blk [4]uint32) [16]byte {
    var sav [16]byte

    binary.LittleEndian.PutUint32(sav[0:], blk[0])
    binary.LittleEndian.PutUint32(sav[4:], blk[1])
    binary.LittleEndian.PutUint32(sav[8:], blk[2])
    binary.LittleEndian.PutUint32(sav[12:], blk[3])

    return sav
}

func keyToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.LittleEndian.Uint32(b[j:])
    }

    return dst
}

func rotl(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotr(x, n uint32) uint32 {
    return rotl(x, 32 - n);
}
