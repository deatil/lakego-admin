package panama

import (
    "math/bits"
    "encoding/binary"
)

func ROTL32(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

/* tau, rotate  word 'a' to the left by rol_bits bit positions */
func tau(a, rol_bits uint32) uint32 {
    return ROTL32(a, rol_bits)
}

// Endianness option
const littleEndian bool = false

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

func keymatToBytes(wkeymat [8]uint32) (bytes [32]byte) {
    var key [4]uint32

    copy(key[0:], wkeymat[0:4])
    b1 := Uint32sToBytes(key)
    copy(bytes[0:], b1[:])

    copy(key[0:], wkeymat[4:8])
    b2 := Uint32sToBytes(key)
    copy(bytes[16:], b2[:])

    return
}
