package anubis

import (
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
}

func getu32Bytes(a uint32) []byte {
    var out [4]byte
    putu32(out[:], a)

    return out[:]
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.BigEndian.Uint32(b[j:])
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        binary.BigEndian.PutUint32(dst[j:], w[i])
    }

    return dst
}

func uint32sToByteArray(w []uint32) (out [][]byte) {
    for _, v := range w {
        out = append(out, getu32Bytes(v))
    }

    return
}
