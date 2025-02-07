package md6

import (
    "encoding/binary"
)

func GETU32(ptr []byte) uint32 {
    return binary.BigEndian.Uint32(ptr)
}

func PUTU32(ptr []byte, a uint32) {
    binary.BigEndian.PutUint32(ptr, a)
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

func tmax(a, b int) int {
    if a > b {
        return a
    }

    return b
}

func tmin(a, b int) int {
    if a < b {
        return a
    }

    return b
}

func xor(x, y []uint32) []uint32 {
    return []uint32{x[0] ^ y[0], x[1] ^ y[1]}
}

func and(x, y []uint32) []uint32 {
    return []uint32{x[0] & y[0], x[1] & y[1]}
}

func shl(x []uint32, n int) []uint32 {
    a := x[0] | 0x0
    b := x[1] | 0x0

    if n >= 32 {
        return []uint32{
            b << (n - 32),
            0x0,
        }
    }

    return []uint32{
        a << n | b >> (32 - n),
        b << n,
    }
}

func shr(x []uint32, n int) []uint32 {
    a := x[0] | 0x0
    b := x[1] | 0x0

    if n >= 32 {
        return []uint32{
            0x0,
            a >> (n - 32),
        }
    }

    return []uint32{
        a >> n,
        a << (32 - n) | b >> n,
    }
}

func toWord(input []byte) [][]uint32 {
    var i int
    var output [][]uint32

    length := len(input)

    for i = 0; i < length; i += 8 {
        output = append(output, []uint32{
            GETU32(input[i + 0:]),
            GETU32(input[i + 4:]),
        })
    }

    return output
}

func fromWord(input [][]uint32) []byte {
    var i int
    var output []byte

    length := len(input)

    for i = 0; i < length; i++ {
        output = append(output, uint32sToBytes(input[i])...)
    }

    return output
}

func crop(size int, hash []byte, right bool) []byte {
    length := (size + 7) / 8
    remain := size % 8

    if right {
        hash = hash[len(hash) - length:]
    } else {
        hash = hash[:length]
    }

    if remain > 0 {
        hash[length - 1] &= (0xFF << (8 - remain)) & 0xFF
    }

    return hash
}
