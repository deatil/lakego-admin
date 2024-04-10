package sm4

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func getu32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func putu32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
    }
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint32(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint32(b[j:])
        }
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        if littleEndian {
            binary.LittleEndian.PutUint32(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint32(dst[j:], w[i])
        }
    }

    return dst
}

func rotl(a uint32, n int) uint32 {
    return bits.RotateLeft32(a, n)
}

func tau(b uint32) uint32 {
    var in  [4]byte
    var out [4]byte

    putu32(in[:], b)

    out[0] = sbox[in[0]]
    out[1] = sbox[in[1]]
    out[2] = sbox[in[2]]
    out[3] = sbox[in[3]]

    return getu32(out[:])
}

// L
func l(b uint32) uint32 {
    return b ^
           rotl(b,  2) ^
           rotl(b, 10) ^
           rotl(b, 18) ^
           rotl(b, 24)
}

// L2
func lAp(b uint32) uint32 {
    return b ^ rotl(b, 13) ^ rotl(b, 23)
}

// T
func tSlow(X uint32) uint32 {
    // L linear transform
    return l(tau(X))
}

// t(X) equal tSlow(X)
// t(X) run fast
func t(X uint32) uint32 {
    var in [4]byte
    putu32(in[:], X)

    return sbox_t0[in[0]] ^
           sbox_t1[in[1]] ^
           sbox_t2[in[2]] ^
           sbox_t3[in[3]]
}

// T'
func keySub(X uint32) uint32 {
    return lAp(tau(X))
}
