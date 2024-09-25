package ascon

import (
    "math/bits"
    "encoding/binary"
)

func getu64(b []byte) uint64 {
    return binary.BigEndian.Uint64(b)
}

func putu64(b []byte, x uint64) {
    binary.BigEndian.PutUint64(b, x)
}

func appendu64(b []byte, x uint64) []byte {
    return append(b, byte(x>>56), byte(x>>48), byte(x>>40), byte(x>>32), byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}

func rotl(a uint64, n int) uint64 {
    return bits.RotateLeft64(a, n)
}
