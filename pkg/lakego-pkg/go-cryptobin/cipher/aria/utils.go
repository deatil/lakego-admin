package aria

import (
    "crypto/subtle"
    "encoding/binary"
)

func keyToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.BigEndian.Uint32(b[j:])
    }

    return dst
}

func bytesToUint32s(inp []byte) []uint32 {
    blk := make([]uint32, 4)

    blk[0] = binary.BigEndian.Uint32(inp[0:])
    blk[1] = binary.BigEndian.Uint32(inp[4:])
    blk[2] = binary.BigEndian.Uint32(inp[8:])
    blk[3] = binary.BigEndian.Uint32(inp[12:])

    return blk
}

func uint32sToBytes(blk []uint32) []byte {
    sav := make([]byte, 16)

    binary.BigEndian.PutUint32(sav[0:], blk[0])
    binary.BigEndian.PutUint32(sav[4:], blk[1])
    binary.BigEndian.PutUint32(sav[8:], blk[2])
    binary.BigEndian.PutUint32(sav[12:], blk[3])

    return sav
}

func copyBytes(xk []uint32, x [16]byte) {
    xx := bytesToUint32s(x[:])
    copy(xk, xx)
}

func toBytes(u []uint32) (r [16]byte) {
    rr := uint32sToBytes(u)
    copy(r[:], rr)

    return
}

// Round Function Fo
func roundOdd(d, rk [16]byte) [16]byte {
    return diffuse(substitute1(xor(d, rk)))
}

// Round Function Fe
func roundEven(d, rk [16]byte) [16]byte {
    return diffuse(substitute2(xor(d, rk)))
}

// Substitution Layer SL1
func substitute1(x [16]byte) (y [16]byte) {
    var i uint
    for i = 0; i < 16; i++ {
        switch i%4 {
            case 0:
                y[i] = sb1[x[i]]
            case 1:
                y[i] = sb2[x[i]]
            case 2:
                y[i] = sb3[x[i]]
            case 3:
                y[i] = sb4[x[i]]
        }
    }

    return
}

// Substitution Layer SL2
func substitute2(x [16]byte) (y [16]byte) {
    var i uint
    for i = 0; i < 16; i++ {
        switch i%4 {
            case 0:
                y[i] = sb3[x[i]]
            case 1:
                y[i] = sb4[x[i]]
            case 2:
                y[i] = sb1[x[i]]
            case 3:
                y[i] = sb2[x[i]]
        }
    }

    return
}

// Diffuse Layer A
func diffuse(x [16]byte) (y [16]byte) {
    y[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14]
    y[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15]
    y[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15]
    y[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14]
    y[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15]
    y[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15]
    y[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13]
    y[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13]
    y[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15]
    y[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14]
    y[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15]
    y[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14]
    y[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12]
    y[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13]
    y[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14]
    y[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15]
    return
}

func xor(a, b [16]byte) (r [16]byte) {
    subtle.XORBytes(r[:], a[:], b[:])
    return
}

func lrot(x [16]byte, n uint) (y [16]byte) {
    q, r := n/8, n%8
    s := 8 - r

    var i uint
    for i = 0; i < 15; i++ {
        y[i] = x[(q+i)%16]<<r | x[(q+i+1)%16]>>s
    }

    y[15] = x[(q+15)%16]<<r | x[q%16]>>s
    return
}

func rrot(x [16]byte, n uint) (y [16]byte) {
    q, r := n/8%16, n%8
    s := 8 - r

    var i uint
    for i = 0; i < 16; i++ {
        y[i] = x[((i+16)-q)%16]>>r | x[((i+15)-q)%16]<<s
    }

    return
}
