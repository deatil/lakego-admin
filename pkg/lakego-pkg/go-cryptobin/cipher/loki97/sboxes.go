package loki97

const S1_GEN = 0x2911 // 10513
const S1_SIZE = 0x2000 // 8192

const S2_GEN = 0xAA7 // 2727
const S2_SIZE = 0x800 // 2048

func generationS1Box() [S1_SIZE]byte {
    var S1 [S1_SIZE]byte

    var S1_MASK uint32 = S1_SIZE - 1;

    var i uint32
    var b uint32

    for i = 0; i < S1_SIZE; i++ {
        b = i ^ S1_MASK
        S1[i] = exp3(b, S1_GEN, S1_SIZE)
    }

    return S1
}

func generationS2Box() [S2_SIZE]byte {
    var S2 [S2_SIZE]byte

    var S2_MASK uint32 = S2_SIZE - 1;

    var i uint32
    var b uint32

    for i = 0; i < S2_SIZE; i++ {
        b = i ^ S2_MASK;
        S2[i] = exp3(b, S2_GEN, S2_SIZE);
    }

    return S2
}

func exp3(b, g, n uint32) byte {
    if b == 0 {
        return 0
    }

    var r uint32 = b     // r = b ** 1
    b = mult(r, b, g, n) // r = b ** 2
    r = mult(r, b, g, n) // r = b ** 3

    return byte(r)
}

func mult(a, b, g, n uint32) uint32 {
    var p uint32 = 0

    for b != 0 {
        if (b & 0x01) != 0 {
            p ^= a
        }

        a <<= 1
        if a >= n {
            a ^= g
        }

        b >>= 1
    }

    return p
}
