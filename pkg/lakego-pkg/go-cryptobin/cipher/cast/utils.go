package cast

import (
    "math/bits"
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

func bytesToUint32s(inp []byte) [4]uint32 {
    var blk [4]uint32

    blk[0] = binary.BigEndian.Uint32(inp[0:])
    blk[1] = binary.BigEndian.Uint32(inp[4:])
    blk[2] = binary.BigEndian.Uint32(inp[8:])
    blk[3] = binary.BigEndian.Uint32(inp[12:])

    return blk
}

func uint32sToBytes(blk [4]uint32) [16]byte {
    var sav [16]byte

    binary.BigEndian.PutUint32(sav[0:], blk[0])
    binary.BigEndian.PutUint32(sav[4:], blk[1])
    binary.BigEndian.PutUint32(sav[8:], blk[2])
    binary.BigEndian.PutUint32(sav[12:], blk[3])

    return sav
}

func rotatel32(x uint32, n byte) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotater32(x uint32, n byte) uint32 {
    return rotatel32(x, 32 - n);
}

func f1(D uint32, kr byte, km uint32) uint32 {
    I := rotatel32(km + D, kr)
    return ((S[0][byte(I >> 24)] ^ S[1][byte(I >> 16)]) - S[2][byte(I >> 8)]) + S[3][byte(I)]
}

func f2(D uint32, kr byte, km uint32) uint32 {
    I := rotatel32(km ^ D, kr)
    return ((S[0][byte(I >> 24)] - S[1][byte(I >> 16)]) + S[2][byte(I >> 8)]) ^ S[3][byte(I)]
}

func f3(D uint32, kr byte, km uint32) uint32 {
    I := rotatel32(km - D, kr)
    return ((S[0][byte(I >> 24)] + S[1][byte(I >> 16)]) ^ S[2][byte(I >> 8)]) - S[3][byte(I)]
}

func ks(i int, key *[8]uint32, km []uint32, kr []byte) {
    for j := 0; j < 2; j++ {
        key[6] ^= f1(key[7], tr[i*2+j][0], tm[i*2+j][0])
        key[5] ^= f2(key[6], tr[i*2+j][1], tm[i*2+j][1])
        key[4] ^= f3(key[5], tr[i*2+j][2], tm[i*2+j][2])
        key[3] ^= f1(key[4], tr[i*2+j][3], tm[i*2+j][3])
        key[2] ^= f2(key[3], tr[i*2+j][4], tm[i*2+j][4])
        key[1] ^= f3(key[2], tr[i*2+j][5], tm[i*2+j][5])
        key[0] ^= f1(key[1], tr[i*2+j][6], tm[i*2+j][6])
        key[7] ^= f2(key[0], tr[i*2+j][7], tm[i*2+j][7])
    }

    kr[i*4+0] = byte(key[0] & 0x1f)
    kr[i*4+1] = byte(key[2] & 0x1f)
    kr[i*4+2] = byte(key[4] & 0x1f)
    kr[i*4+3] = byte(key[6] & 0x1f)

    km[i*4+0] = key[7]
    km[i*4+1] = key[5]
    km[i*4+2] = key[3]
    km[i*4+3] = key[1]
}

func keyInit(key [8]uint32, km []uint32, kr []byte) {
    for i := 0; i < 12; i++ {
        ks(i, &key, km, kr)
    }
}
