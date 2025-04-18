package present

import (
    "math/bits"
    "encoding/binary"
)

func bytesToUint64(inp []byte) (blk uint64) {
    blk = binary.BigEndian.Uint64(inp[0:])

    return
}

func uint64ToBytes(blk uint64) []byte {
    var sav [8]byte

    binary.BigEndian.PutUint64(sav[0:], blk)

    return sav[:]
}

func bytesToUint64s(b []byte) []uint64 {
    size := len(b) / 8
    dst := make([]uint64, size)

    for i := 0; i < size; i++ {
        j := i * 8

        dst[i] = binary.BigEndian.Uint64(b[j:])
    }

    return dst
}

func uint64sToBytes(w []uint64) []byte {
    size := len(w) * 8
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 8

        binary.BigEndian.PutUint64(dst[j:], w[i])
    }

    return dst
}

func ROL64(x, n uint64) uint64 {
    return bits.RotateLeft64(x, int(n))
}
