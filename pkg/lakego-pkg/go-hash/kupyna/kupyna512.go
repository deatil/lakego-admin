package kupyna

import (
    "hash"
)

// The size of an kupyna512 checksum in bytes.
const Size512 = 64

// The blocksize of kupyna512 in bytes.
const BlockSize512 = 128

// digest512 represents the partial evaluation of a checksum.
type digest512 struct {
    s   [16]uint64
    x   [BlockSize512]byte
    nx  int
    len uint64
}

// New512 returns a new hash.Hash computing the Kupyna512 checksum
func New512() hash.Hash {
    d := new(digest512)
    d.Reset()

    return d
}

func (d *digest512) Reset() {
    // h
    d.s = [16]uint64{}
    // m
    d.x = [BlockSize512]byte{}
    d.nx = 0
    d.len = 0

    s1 := [8]byte{}
    s1[0] = 128

    d.s[0] = GETU64(s1[:])
}

func (d *digest512) Size() int {
    return Size512
}

func (d *digest512) BlockSize() int {
    return BlockSize512
}

func (d *digest512) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)
    if d.nx > 0 {
        n := copy(d.x[d.nx:], p)
        d.nx += n
        if d.nx == BlockSize512 {
            d.block(d.x[:])
            d.nx = 0
        }

        p = p[n:]
    }

    for ; len(p) >= BlockSize512; p = p[BlockSize512:] {
        d.block(p)
        d.nx = 0
    }

    if len(p) > 0 {
        d.nx = copy(d.x[:], p)
    }

    return
}

func (d *digest512) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest512) checkSum() []byte {
    d.x[d.nx] = 0x80
    d.nx++

    tmp := make([]byte, BlockSize512)

    if d.nx > 116 {
        copy(d.x[d.nx:], tmp)

        d.block(d.x[:])
        d.nx = 0
    }

    copy(d.x[d.nx:], tmp)

    PUTU64(d.x[116:], d.len * 8)
    d.block(d.x[:])

    d.outputTransform()

    ss := uint64sToBytes(d.s[:])
    return ss[64:]
}

func (d *digest512) G(x [16]uint64, y *[16]uint64) {
    y[0]  = T0[byte(x[0])]  ^ T1[byte(x[15] >> 8)] ^ T2[byte(x[14] >> 16)] ^ T3[byte(x[13] >> 24)] ^ T4[byte(x[12] >> 32)] ^ T5[byte(x[11] >> 40)] ^ T6[byte(x[10] >> 48)] ^ T7[byte(x[5] >> 56)]
    y[1]  = T0[byte(x[1])]  ^ T1[byte(x[0] >> 8)]  ^ T2[byte(x[15] >> 16)] ^ T3[byte(x[14] >> 24)] ^ T4[byte(x[13] >> 32)] ^ T5[byte(x[12] >> 40)] ^ T6[byte(x[11] >> 48)] ^ T7[byte(x[6] >> 56)]
    y[2]  = T0[byte(x[2])]  ^ T1[byte(x[1] >> 8)]  ^ T2[byte(x[0] >> 16)]  ^ T3[byte(x[15] >> 24)] ^ T4[byte(x[14] >> 32)] ^ T5[byte(x[13] >> 40)] ^ T6[byte(x[12] >> 48)] ^ T7[byte(x[7] >> 56)]
    y[3]  = T0[byte(x[3])]  ^ T1[byte(x[2] >> 8)]  ^ T2[byte(x[1] >> 16)]  ^ T3[byte(x[0] >> 24)]  ^ T4[byte(x[15] >> 32)] ^ T5[byte(x[14] >> 40)] ^ T6[byte(x[13] >> 48)] ^ T7[byte(x[8] >> 56)]
    y[4]  = T0[byte(x[4])]  ^ T1[byte(x[3] >> 8)]  ^ T2[byte(x[2] >> 16)]  ^ T3[byte(x[1] >> 24)]  ^ T4[byte(x[0] >> 32)]  ^ T5[byte(x[15] >> 40)] ^ T6[byte(x[14] >> 48)] ^ T7[byte(x[9] >> 56)]
    y[5]  = T0[byte(x[5])]  ^ T1[byte(x[4] >> 8)]  ^ T2[byte(x[3] >> 16)]  ^ T3[byte(x[2] >> 24)]  ^ T4[byte(x[1] >> 32)]  ^ T5[byte(x[0] >> 40)]  ^ T6[byte(x[15] >> 48)] ^ T7[byte(x[10] >> 56)]
    y[6]  = T0[byte(x[6])]  ^ T1[byte(x[5] >> 8)]  ^ T2[byte(x[4] >> 16)]  ^ T3[byte(x[3] >> 24)]  ^ T4[byte(x[2] >> 32)]  ^ T5[byte(x[1] >> 40)]  ^ T6[byte(x[0] >> 48)]  ^ T7[byte(x[11] >> 56)]
    y[7]  = T0[byte(x[7])]  ^ T1[byte(x[6] >> 8)]  ^ T2[byte(x[5] >> 16)]  ^ T3[byte(x[4] >> 24)]  ^ T4[byte(x[3] >> 32)]  ^ T5[byte(x[2] >> 40)]  ^ T6[byte(x[1] >> 48)]  ^ T7[byte(x[12] >> 56)]
    y[8]  = T0[byte(x[8])]  ^ T1[byte(x[7] >> 8)]  ^ T2[byte(x[6] >> 16)]  ^ T3[byte(x[5] >> 24)]  ^ T4[byte(x[4] >> 32)]  ^ T5[byte(x[3] >> 40)]  ^ T6[byte(x[2] >> 48)]  ^ T7[byte(x[13] >> 56)]
    y[9]  = T0[byte(x[9])]  ^ T1[byte(x[8] >> 8)]  ^ T2[byte(x[7] >> 16)]  ^ T3[byte(x[6] >> 24)]  ^ T4[byte(x[5] >> 32)]  ^ T5[byte(x[4] >> 40)]  ^ T6[byte(x[3] >> 48)]  ^ T7[byte(x[14] >> 56)]
    y[10] = T0[byte(x[10])] ^ T1[byte(x[9] >> 8)]  ^ T2[byte(x[8] >> 16)]  ^ T3[byte(x[7] >> 24)]  ^ T4[byte(x[6] >> 32)]  ^ T5[byte(x[5] >> 40)]  ^ T6[byte(x[4] >> 48)]  ^ T7[byte(x[15] >> 56)]
    y[11] = T0[byte(x[11])] ^ T1[byte(x[10] >> 8)] ^ T2[byte(x[9] >> 16)]  ^ T3[byte(x[8] >> 24)]  ^ T4[byte(x[7] >> 32)]  ^ T5[byte(x[6] >> 40)]  ^ T6[byte(x[5] >> 48)]  ^ T7[byte(x[0] >> 56)]
    y[12] = T0[byte(x[12])] ^ T1[byte(x[11] >> 8)] ^ T2[byte(x[10] >> 16)] ^ T3[byte(x[9] >> 24)]  ^ T4[byte(x[8] >> 32)]  ^ T5[byte(x[7] >> 40)]  ^ T6[byte(x[6] >> 48)]  ^ T7[byte(x[1] >> 56)]
    y[13] = T0[byte(x[13])] ^ T1[byte(x[12] >> 8)] ^ T2[byte(x[11] >> 16)] ^ T3[byte(x[10] >> 24)] ^ T4[byte(x[9] >> 32)]  ^ T5[byte(x[8] >> 40)]  ^ T6[byte(x[7] >> 48)]  ^ T7[byte(x[2] >> 56)]
    y[14] = T0[byte(x[14])] ^ T1[byte(x[13] >> 8)] ^ T2[byte(x[12] >> 16)] ^ T3[byte(x[11] >> 24)] ^ T4[byte(x[10] >> 32)] ^ T5[byte(x[9] >> 40)]  ^ T6[byte(x[8] >> 48)]  ^ T7[byte(x[3] >> 56)]
    y[15] = T0[byte(x[15])] ^ T1[byte(x[14] >> 8)] ^ T2[byte(x[13] >> 16)] ^ T3[byte(x[12] >> 24)] ^ T4[byte(x[11] >> 32)] ^ T5[byte(x[10] >> 40)] ^ T6[byte(x[9] >> 48)]  ^ T7[byte(x[4] >> 56)]
}

func (d *digest512) G1(x [16]uint64, y *[16]uint64, round uint64) {
    y[0]  = T0[byte(x[0])]  ^ T1[byte(x[15] >> 8)] ^ T2[byte(x[14] >> 16)] ^ T3[byte(x[13] >> 24)] ^ T4[byte(x[12] >> 32)] ^ T5[byte(x[11] >> 40)] ^ T6[byte(x[10] >> 48)] ^ T7[byte(x[5] >> 56)]  ^ (0 << 4) ^ round
    y[1]  = T0[byte(x[1])]  ^ T1[byte(x[0] >> 8)]  ^ T2[byte(x[15] >> 16)] ^ T3[byte(x[14] >> 24)] ^ T4[byte(x[13] >> 32)] ^ T5[byte(x[12] >> 40)] ^ T6[byte(x[11] >> 48)] ^ T7[byte(x[6] >> 56)]  ^ (1 << 4) ^ round
    y[2]  = T0[byte(x[2])]  ^ T1[byte(x[1] >> 8)]  ^ T2[byte(x[0] >> 16)]  ^ T3[byte(x[15] >> 24)] ^ T4[byte(x[14] >> 32)] ^ T5[byte(x[13] >> 40)] ^ T6[byte(x[12] >> 48)] ^ T7[byte(x[7] >> 56)]  ^ (2 << 4) ^ round
    y[3]  = T0[byte(x[3])]  ^ T1[byte(x[2] >> 8)]  ^ T2[byte(x[1] >> 16)]  ^ T3[byte(x[0] >> 24)]  ^ T4[byte(x[15] >> 32)] ^ T5[byte(x[14] >> 40)] ^ T6[byte(x[13] >> 48)] ^ T7[byte(x[8] >> 56)]  ^ (3 << 4) ^ round
    y[4]  = T0[byte(x[4])]  ^ T1[byte(x[3] >> 8)]  ^ T2[byte(x[2] >> 16)]  ^ T3[byte(x[1] >> 24)]  ^ T4[byte(x[0] >> 32)]  ^ T5[byte(x[15] >> 40)] ^ T6[byte(x[14] >> 48)] ^ T7[byte(x[9] >> 56)]  ^ (4 << 4) ^ round
    y[5]  = T0[byte(x[5])]  ^ T1[byte(x[4] >> 8)]  ^ T2[byte(x[3] >> 16)]  ^ T3[byte(x[2] >> 24)]  ^ T4[byte(x[1] >> 32)]  ^ T5[byte(x[0] >> 40)]  ^ T6[byte(x[15] >> 48)] ^ T7[byte(x[10] >> 56)] ^ (5 << 4) ^ round
    y[6]  = T0[byte(x[6])]  ^ T1[byte(x[5] >> 8)]  ^ T2[byte(x[4] >> 16)]  ^ T3[byte(x[3] >> 24)]  ^ T4[byte(x[2] >> 32)]  ^ T5[byte(x[1] >> 40)]  ^ T6[byte(x[0] >> 48)]  ^ T7[byte(x[11] >> 56)] ^ (6 << 4) ^ round
    y[7]  = T0[byte(x[7])]  ^ T1[byte(x[6] >> 8)]  ^ T2[byte(x[5] >> 16)]  ^ T3[byte(x[4] >> 24)]  ^ T4[byte(x[3] >> 32)]  ^ T5[byte(x[2] >> 40)]  ^ T6[byte(x[1] >> 48)]  ^ T7[byte(x[12] >> 56)] ^ (7 << 4) ^ round
    y[8]  = T0[byte(x[8])]  ^ T1[byte(x[7] >> 8)]  ^ T2[byte(x[6] >> 16)]  ^ T3[byte(x[5] >> 24)]  ^ T4[byte(x[4] >> 32)]  ^ T5[byte(x[3] >> 40)]  ^ T6[byte(x[2] >> 48)]  ^ T7[byte(x[13] >> 56)] ^ (8 << 4) ^ round
    y[9]  = T0[byte(x[9])]  ^ T1[byte(x[8] >> 8)]  ^ T2[byte(x[7] >> 16)]  ^ T3[byte(x[6] >> 24)]  ^ T4[byte(x[5] >> 32)]  ^ T5[byte(x[4] >> 40)]  ^ T6[byte(x[3] >> 48)]  ^ T7[byte(x[14] >> 56)] ^ (9 << 4) ^ round
    y[10] = T0[byte(x[10])] ^ T1[byte(x[9] >> 8)]  ^ T2[byte(x[8] >> 16)]  ^ T3[byte(x[7] >> 24)]  ^ T4[byte(x[6] >> 32)]  ^ T5[byte(x[5] >> 40)]  ^ T6[byte(x[4] >> 48)]  ^ T7[byte(x[15] >> 56)] ^ (10 << 4) ^ round
    y[11] = T0[byte(x[11])] ^ T1[byte(x[10] >> 8)] ^ T2[byte(x[9] >> 16)]  ^ T3[byte(x[8] >> 24)]  ^ T4[byte(x[7] >> 32)]  ^ T5[byte(x[6] >> 40)]  ^ T6[byte(x[5] >> 48)]  ^ T7[byte(x[0] >> 56)]  ^ (11 << 4) ^ round
    y[12] = T0[byte(x[12])] ^ T1[byte(x[11] >> 8)] ^ T2[byte(x[10] >> 16)] ^ T3[byte(x[9] >> 24)]  ^ T4[byte(x[8] >> 32)]  ^ T5[byte(x[7] >> 40)]  ^ T6[byte(x[6] >> 48)]  ^ T7[byte(x[1] >> 56)]  ^ (12 << 4) ^ round
    y[13] = T0[byte(x[13])] ^ T1[byte(x[12] >> 8)] ^ T2[byte(x[11] >> 16)] ^ T3[byte(x[10] >> 24)] ^ T4[byte(x[9] >> 32)]  ^ T5[byte(x[8] >> 40)]  ^ T6[byte(x[7] >> 48)]  ^ T7[byte(x[2] >> 56)]  ^ (13 << 4) ^ round
    y[14] = T0[byte(x[14])] ^ T1[byte(x[13] >> 8)] ^ T2[byte(x[12] >> 16)] ^ T3[byte(x[11] >> 24)] ^ T4[byte(x[10] >> 32)] ^ T5[byte(x[9] >> 40)]  ^ T6[byte(x[8] >> 48)]  ^ T7[byte(x[3] >> 56)]  ^ (14 << 4) ^ round
    y[15] = T0[byte(x[15])] ^ T1[byte(x[14] >> 8)] ^ T2[byte(x[13] >> 16)] ^ T3[byte(x[12] >> 24)] ^ T4[byte(x[11] >> 32)] ^ T5[byte(x[10] >> 40)] ^ T6[byte(x[9] >> 48)]  ^ T7[byte(x[4] >> 56)]  ^ (15 << 4) ^ round
}

func (d *digest512) G2(x [16]uint64, y *[16]uint64, round uint64) {
    var r uint64 = 0x00F0F0F0F0F0F0F3

    y[0]  = (T0[byte(x[0])]  ^ T1[byte(x[15] >> 8)] ^ T2[byte(x[14] >> 16)] ^ T3[byte(x[13] >> 24)] ^ T4[byte(x[12] >> 32)] ^ T5[byte(x[11] >> 40)] ^ T6[byte(x[10] >> 48)] ^ T7[byte(x[5] >> 56)])  + (r ^ ((((15 - 0)  * 0x10) ^ round) << 56))
    y[1]  = (T0[byte(x[1])]  ^ T1[byte(x[0] >> 8)]  ^ T2[byte(x[15] >> 16)] ^ T3[byte(x[14] >> 24)] ^ T4[byte(x[13] >> 32)] ^ T5[byte(x[12] >> 40)] ^ T6[byte(x[11] >> 48)] ^ T7[byte(x[6] >> 56)])  + (r ^ ((((15 - 1)  * 0x10) ^ round) << 56))
    y[2]  = (T0[byte(x[2])]  ^ T1[byte(x[1] >> 8)]  ^ T2[byte(x[0] >> 16)]  ^ T3[byte(x[15] >> 24)] ^ T4[byte(x[14] >> 32)] ^ T5[byte(x[13] >> 40)] ^ T6[byte(x[12] >> 48)] ^ T7[byte(x[7] >> 56)])  + (r ^ ((((15 - 2)  * 0x10) ^ round) << 56))
    y[3]  = (T0[byte(x[3])]  ^ T1[byte(x[2] >> 8)]  ^ T2[byte(x[1] >> 16)]  ^ T3[byte(x[0] >> 24)]  ^ T4[byte(x[15] >> 32)] ^ T5[byte(x[14] >> 40)] ^ T6[byte(x[13] >> 48)] ^ T7[byte(x[8] >> 56)])  + (r ^ ((((15 - 3)  * 0x10) ^ round) << 56))
    y[4]  = (T0[byte(x[4])]  ^ T1[byte(x[3] >> 8)]  ^ T2[byte(x[2] >> 16)]  ^ T3[byte(x[1] >> 24)]  ^ T4[byte(x[0] >> 32)]  ^ T5[byte(x[15] >> 40)] ^ T6[byte(x[14] >> 48)] ^ T7[byte(x[9] >> 56)])  + (r ^ ((((15 - 4)  * 0x10) ^ round) << 56))
    y[5]  = (T0[byte(x[5])]  ^ T1[byte(x[4] >> 8)]  ^ T2[byte(x[3] >> 16)]  ^ T3[byte(x[2] >> 24)]  ^ T4[byte(x[1] >> 32)]  ^ T5[byte(x[0] >> 40)]  ^ T6[byte(x[15] >> 48)] ^ T7[byte(x[10] >> 56)]) + (r ^ ((((15 - 5)  * 0x10) ^ round) << 56))
    y[6]  = (T0[byte(x[6])]  ^ T1[byte(x[5] >> 8)]  ^ T2[byte(x[4] >> 16)]  ^ T3[byte(x[3] >> 24)]  ^ T4[byte(x[2] >> 32)]  ^ T5[byte(x[1] >> 40)]  ^ T6[byte(x[0] >> 48)]  ^ T7[byte(x[11] >> 56)]) + (r ^ ((((15 - 6)  * 0x10) ^ round) << 56))
    y[7]  = (T0[byte(x[7])]  ^ T1[byte(x[6] >> 8)]  ^ T2[byte(x[5] >> 16)]  ^ T3[byte(x[4] >> 24)]  ^ T4[byte(x[3] >> 32)]  ^ T5[byte(x[2] >> 40)]  ^ T6[byte(x[1] >> 48)]  ^ T7[byte(x[12] >> 56)]) + (r ^ ((((15 - 7)  * 0x10) ^ round) << 56))
    y[8]  = (T0[byte(x[8])]  ^ T1[byte(x[7] >> 8)]  ^ T2[byte(x[6] >> 16)]  ^ T3[byte(x[5] >> 24)]  ^ T4[byte(x[4] >> 32)]  ^ T5[byte(x[3] >> 40)]  ^ T6[byte(x[2] >> 48)]  ^ T7[byte(x[13] >> 56)]) + (r ^ ((((15 - 8)  * 0x10) ^ round) << 56))
    y[9]  = (T0[byte(x[9])]  ^ T1[byte(x[8] >> 8)]  ^ T2[byte(x[7] >> 16)]  ^ T3[byte(x[6] >> 24)]  ^ T4[byte(x[5] >> 32)]  ^ T5[byte(x[4] >> 40)]  ^ T6[byte(x[3] >> 48)]  ^ T7[byte(x[14] >> 56)]) + (r ^ ((((15 - 9)  * 0x10) ^ round) << 56))
    y[10] = (T0[byte(x[10])] ^ T1[byte(x[9] >> 8)]  ^ T2[byte(x[8] >> 16)]  ^ T3[byte(x[7] >> 24)]  ^ T4[byte(x[6] >> 32)]  ^ T5[byte(x[5] >> 40)]  ^ T6[byte(x[4] >> 48)]  ^ T7[byte(x[15] >> 56)]) + (r ^ ((((15 - 10) * 0x10) ^ round) << 56))
    y[11] = (T0[byte(x[11])] ^ T1[byte(x[10] >> 8)] ^ T2[byte(x[9] >> 16)]  ^ T3[byte(x[8] >> 24)]  ^ T4[byte(x[7] >> 32)]  ^ T5[byte(x[6] >> 40)]  ^ T6[byte(x[5] >> 48)]  ^ T7[byte(x[0] >> 56)])  + (r ^ ((((15 - 11) * 0x10) ^ round) << 56))
    y[12] = (T0[byte(x[12])] ^ T1[byte(x[11] >> 8)] ^ T2[byte(x[10] >> 16)] ^ T3[byte(x[9] >> 24)]  ^ T4[byte(x[8] >> 32)]  ^ T5[byte(x[7] >> 40)]  ^ T6[byte(x[6] >> 48)]  ^ T7[byte(x[1] >> 56)])  + (r ^ ((((15 - 12) * 0x10) ^ round) << 56))
    y[13] = (T0[byte(x[13])] ^ T1[byte(x[12] >> 8)] ^ T2[byte(x[11] >> 16)] ^ T3[byte(x[10] >> 24)] ^ T4[byte(x[9] >> 32)]  ^ T5[byte(x[8] >> 40)]  ^ T6[byte(x[7] >> 48)]  ^ T7[byte(x[2] >> 56)])  + (r ^ ((((15 - 13) * 0x10) ^ round) << 56))
    y[14] = (T0[byte(x[14])] ^ T1[byte(x[13] >> 8)] ^ T2[byte(x[12] >> 16)] ^ T3[byte(x[11] >> 24)] ^ T4[byte(x[10] >> 32)] ^ T5[byte(x[9] >> 40)]  ^ T6[byte(x[8] >> 48)]  ^ T7[byte(x[3] >> 56)])  + (r ^ ((((15 - 14) * 0x10) ^ round) << 56))
    y[15] = (T0[byte(x[15])] ^ T1[byte(x[14] >> 8)] ^ T2[byte(x[13] >> 16)] ^ T3[byte(x[12] >> 24)] ^ T4[byte(x[11] >> 32)] ^ T5[byte(x[10] >> 40)] ^ T6[byte(x[9] >> 48)]  ^ T7[byte(x[4] >> 56)])  + (r ^ ((((15 - 15) * 0x10) ^ round) << 56))
}

func (d *digest512) P(x *[16]uint64, y *[16]uint64, round uint64) {
    var idx uint64
    for idx = 0; idx < 16; idx++ {
        x[idx] ^= (idx << 4) ^ round
    }

    d.G1(*x, y, round + 1)
    d.G(*y, x)
}

func (d *digest512) Q(x *[16]uint64, y *[16]uint64, round uint64) {
    var r uint64 = 0x00F0F0F0F0F0F0F3

    var j uint64
    for j = 0; j < 16; j++ {
        x[j] += (r ^ ((((15 - j) * 0x10) ^ round) << 56))
    }

    d.G2(*x, y, round + 1)
    d.G(*y, x)
}

func (d *digest512) outputTransform() {
    var t1, t2 [16]uint64

    copy(t1[:], d.s[:])

    var r uint64
    for r = 0; r < 14; r += 2 {
        d.P(&t1, &t2, r)
    }

    var column uint32
    for column = 0; column < 16; column++ {
        d.s[column] ^= t1[column]
    }
}

func (d *digest512) transform(b []uint64) {
    var AQ1, AP1, tmp [16]uint64

    var column uint32
    for column = 0; column < 16; column++ {
        AP1[column] = d.s[column] ^ b[column]
        AQ1[column] = b[column]
    }

    var r uint64
    for r = 0; r < 14; r += 2 {
        d.P(&AP1, &tmp, r)
        d.Q(&AQ1, &tmp, r)
    }

    for column = 0; column < 16; column++ {
        d.s[column] ^= AP1[column] ^ AQ1[column]
    }
}

func (d *digest512) block(b []byte) {
    d.transform(bytesToUint64s(b))
}
