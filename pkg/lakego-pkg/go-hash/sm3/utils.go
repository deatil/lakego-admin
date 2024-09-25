package sm3

import (
    "math/bits"
    "encoding/binary"
)

func GETU32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func PUTU32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
}

func ROTL(x uint32, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func P0(x uint32) uint32 {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17)
}

func P1(x uint32) uint32 {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23)
}

func FF00(x, y, z uint32) uint32 {
    return x ^ y ^ z
}

func FF16(x, y, z uint32) uint32 {
    return (x & y) | (x & z) | (y & z)
}

func GG00(x, y, z uint32) uint32 {
    return x ^ y ^ z
}

func GG16(x, y, z uint32) uint32 {
    return ((y ^ z) & x) ^ z
}

func GenT() []uint32 {
    init1 := 0x79CC4519
    init2 := 0x7A879D8A

    var T = make([]uint32, 0)
    for j := 0; j < 16; j++ {
        Tj := (init1 << uint32(j)) | (init1 >> (32 - uint32(j)))

        T = append(T, uint32(Tj))
    }

    for j := 16; j < 64; j++ {
        n := j % 32
        Tj := (init2 << uint32(n)) | (init2 >> (32 - uint32(n)))

        T = append(T, uint32(Tj))
    }

    // fmt.Printf("0x%08X, ", Tj)

    return T
}
