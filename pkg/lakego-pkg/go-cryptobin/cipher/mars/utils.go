package mars

import (
    "encoding/binary"
)

// u4byte = uint32
// u1byte = byte

func rotr(x, n uint32) uint32 {
    return (x >> n) | (x << (32 - n))
}

func rotl(x, n uint32) uint32 {
    return (x << n) | (x >> (32 - n))
}

func bswap(x uint32) uint32 {
    return (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00)
}

func io_swap(x uint32) uint32 {
    return bswap(x)
}

func bytesToUint32s(inp []byte) [4]uint32 {
    var blk [4]uint32

    blk[0] = binary.BigEndian.Uint32(inp[0:])
    blk[1] = binary.BigEndian.Uint32(inp[4:])
    blk[2] = binary.BigEndian.Uint32(inp[8:])
    blk[3] = binary.BigEndian.Uint32(inp[12:])

    return blk
}

func Uint32sToBytes(blk [4]uint32) [16]byte {
    var sav [16]byte

    binary.BigEndian.PutUint32(sav[0:], blk[0])
    binary.BigEndian.PutUint32(sav[4:], blk[1])
    binary.BigEndian.PutUint32(sav[8:], blk[2])
    binary.BigEndian.PutUint32(sav[12:], blk[3])

    return sav
}
