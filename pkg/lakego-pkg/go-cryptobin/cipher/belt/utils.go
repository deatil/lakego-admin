package belt

import (
    "math/bits"
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
}

func rotatel32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func rotater32(x uint32, n int) uint32 {
    return rotatel32(x, 32 - n)
}

func ROTL_BELT(x uint32, n int) uint32 {
    return rotater32(x, n)
}

func GET_BYTE(x uint32, a int) byte {
    return byte((x >> a) & 0xff)
}

func PUT_BYTE(x uint32, a int) uint32 {
    return x << a
}

func SB(x uint32, a int) uint32 {
    return PUT_BYTE(uint32(S[GET_BYTE(x, a)]), a)
}

func G(x uint32, r int) uint32 {
    return ROTL_BELT(SB(x, 24) | SB(x, 16) | SB(x, 8) | SB(x, 0), r)
}
