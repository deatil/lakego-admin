package kasumi

import (
    "encoding/binary"
)

func bytesToUint32(inp []byte) (blk uint32) {
    blk = binary.BigEndian.Uint32(inp[0:])

    return
}

func uint32ToBytes(blk uint32) []byte {
    var sav [4]byte

    binary.BigEndian.PutUint32(sav[0:], blk)

    return sav[:]
}

func ROL16(a, b uint16) uint16 {
    return (a << b) | (a >> (16 - b))
}
