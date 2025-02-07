package wake

import (
    "encoding/binary"
)

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

func bytesToUint32(inp []byte) (blk uint32) {
    blk = binary.BigEndian.Uint32(inp[0:])

    return
}

func uint32ToBytes(blk uint32) [4]byte {
    var sav [4]byte

    binary.BigEndian.PutUint32(sav[0:], blk)

    return sav
}
