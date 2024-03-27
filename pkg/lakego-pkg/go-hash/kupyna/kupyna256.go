package kupyna

import (
    "hash"
)

// The size of an kupyna256 checksum in bytes.
const Size256 = 32

// The blocksize of kupyna256 in bytes.
const BlockSize256 = 64

// digest256 represents the partial evaluation of a checksum.
type digest256 struct {
    s   [8]uint64
    x   [BlockSize256]byte
    nx  int
    len uint64
}

// New256 returns a new hash.Hash computing the kupyna256 checksum
func New256() hash.Hash {
    d := new(digest256)
    d.Reset()

    return d
}

func (d *digest256) Reset() {
    // h
    d.s = [8]uint64{}
    // m
    d.x = [BlockSize256]byte{}
    d.nx = 0
    d.len = 0

    s1 := [8]byte{}
    s1[0] = 64

    d.s[0] = GETU64(s1[:])
}

func (d *digest256) Size() int {
    return Size256
}

func (d *digest256) BlockSize() int {
    return BlockSize256
}

func (d *digest256) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)
    if d.nx > 0 {
        n := copy(d.x[d.nx:], p)
        d.nx += n
        if d.nx == BlockSize256 {
            d.block(d.x[:])
            d.nx = 0
        }

        p = p[n:]
    }

    for ; len(p) >= BlockSize256; p = p[BlockSize256:] {
        d.block(p)
        d.nx = 0
    }

    if len(p) > 0 {
        d.nx = copy(d.x[:], p)
    }

    return
}

func (d *digest256) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest256) checkSum() []byte {
    d.x[d.nx] = 0x80
    d.nx++

    tmp := make([]byte, BlockSize256)

    if d.nx > 52 {
        copy(d.x[d.nx:], tmp)

        d.block(d.x[:])
        d.nx = 0
    }

    copy(d.x[d.nx:], tmp)

    PUTU64(d.x[52:], d.len * 8)
    d.block(d.x[:])

    d.outputTransform()

    ss := uint64sToBytes(d.s[:])
    return ss[32:]
}

func (d *digest256) G(x [8]uint64, y *[8]uint64) {
    y[0] = T0[byte(x[0])] ^ T1[byte(x[7] >> 8)] ^ T2[byte(x[6] >> 16)] ^ T3[byte(x[5] >> 24)] ^ T4[byte(x[4] >> 32)] ^ T5[byte(x[3] >> 40)] ^ T6[byte(x[2] >> 48)] ^ T7[byte(x[1] >> 56)]
    y[1] = T0[byte(x[1])] ^ T1[byte(x[0] >> 8)] ^ T2[byte(x[7] >> 16)] ^ T3[byte(x[6] >> 24)] ^ T4[byte(x[5] >> 32)] ^ T5[byte(x[4] >> 40)] ^ T6[byte(x[3] >> 48)] ^ T7[byte(x[2] >> 56)]
    y[2] = T0[byte(x[2])] ^ T1[byte(x[1] >> 8)] ^ T2[byte(x[0] >> 16)] ^ T3[byte(x[7] >> 24)] ^ T4[byte(x[6] >> 32)] ^ T5[byte(x[5] >> 40)] ^ T6[byte(x[4] >> 48)] ^ T7[byte(x[3] >> 56)]
    y[3] = T0[byte(x[3])] ^ T1[byte(x[2] >> 8)] ^ T2[byte(x[1] >> 16)] ^ T3[byte(x[0] >> 24)] ^ T4[byte(x[7] >> 32)] ^ T5[byte(x[6] >> 40)] ^ T6[byte(x[5] >> 48)] ^ T7[byte(x[4] >> 56)]
    y[4] = T0[byte(x[4])] ^ T1[byte(x[3] >> 8)] ^ T2[byte(x[2] >> 16)] ^ T3[byte(x[1] >> 24)] ^ T4[byte(x[0] >> 32)] ^ T5[byte(x[7] >> 40)] ^ T6[byte(x[6] >> 48)] ^ T7[byte(x[5] >> 56)]
    y[5] = T0[byte(x[5])] ^ T1[byte(x[4] >> 8)] ^ T2[byte(x[3] >> 16)] ^ T3[byte(x[2] >> 24)] ^ T4[byte(x[1] >> 32)] ^ T5[byte(x[0] >> 40)] ^ T6[byte(x[7] >> 48)] ^ T7[byte(x[6] >> 56)]
    y[6] = T0[byte(x[6])] ^ T1[byte(x[5] >> 8)] ^ T2[byte(x[4] >> 16)] ^ T3[byte(x[3] >> 24)] ^ T4[byte(x[2] >> 32)] ^ T5[byte(x[1] >> 40)] ^ T6[byte(x[0] >> 48)] ^ T7[byte(x[7] >> 56)]
    y[7] = T0[byte(x[7])] ^ T1[byte(x[6] >> 8)] ^ T2[byte(x[5] >> 16)] ^ T3[byte(x[4] >> 24)] ^ T4[byte(x[3] >> 32)] ^ T5[byte(x[2] >> 40)] ^ T6[byte(x[1] >> 48)] ^ T7[byte(x[0] >> 56)]
}

func (d *digest256) G1(x [8]uint64, y *[8]uint64, round uint64) {
    y[0] = T0[byte(x[0])] ^ T1[byte(x[7] >> 8)] ^ T2[byte(x[6] >> 16)] ^ T3[byte(x[5] >> 24)] ^ T4[byte(x[4] >> 32)] ^ T5[byte(x[3] >> 40)] ^ T6[byte(x[2] >> 48)] ^ T7[byte(x[1] >> 56)] ^ (0 << 4) ^ round
    y[1] = T0[byte(x[1])] ^ T1[byte(x[0] >> 8)] ^ T2[byte(x[7] >> 16)] ^ T3[byte(x[6] >> 24)] ^ T4[byte(x[5] >> 32)] ^ T5[byte(x[4] >> 40)] ^ T6[byte(x[3] >> 48)] ^ T7[byte(x[2] >> 56)] ^ (1 << 4) ^ round
    y[2] = T0[byte(x[2])] ^ T1[byte(x[1] >> 8)] ^ T2[byte(x[0] >> 16)] ^ T3[byte(x[7] >> 24)] ^ T4[byte(x[6] >> 32)] ^ T5[byte(x[5] >> 40)] ^ T6[byte(x[4] >> 48)] ^ T7[byte(x[3] >> 56)] ^ (2 << 4) ^ round
    y[3] = T0[byte(x[3])] ^ T1[byte(x[2] >> 8)] ^ T2[byte(x[1] >> 16)] ^ T3[byte(x[0] >> 24)] ^ T4[byte(x[7] >> 32)] ^ T5[byte(x[6] >> 40)] ^ T6[byte(x[5] >> 48)] ^ T7[byte(x[4] >> 56)] ^ (3 << 4) ^ round
    y[4] = T0[byte(x[4])] ^ T1[byte(x[3] >> 8)] ^ T2[byte(x[2] >> 16)] ^ T3[byte(x[1] >> 24)] ^ T4[byte(x[0] >> 32)] ^ T5[byte(x[7] >> 40)] ^ T6[byte(x[6] >> 48)] ^ T7[byte(x[5] >> 56)] ^ (4 << 4) ^ round
    y[5] = T0[byte(x[5])] ^ T1[byte(x[4] >> 8)] ^ T2[byte(x[3] >> 16)] ^ T3[byte(x[2] >> 24)] ^ T4[byte(x[1] >> 32)] ^ T5[byte(x[0] >> 40)] ^ T6[byte(x[7] >> 48)] ^ T7[byte(x[6] >> 56)] ^ (5 << 4) ^ round
    y[6] = T0[byte(x[6])] ^ T1[byte(x[5] >> 8)] ^ T2[byte(x[4] >> 16)] ^ T3[byte(x[3] >> 24)] ^ T4[byte(x[2] >> 32)] ^ T5[byte(x[1] >> 40)] ^ T6[byte(x[0] >> 48)] ^ T7[byte(x[7] >> 56)] ^ (6 << 4) ^ round
    y[7] = T0[byte(x[7])] ^ T1[byte(x[6] >> 8)] ^ T2[byte(x[5] >> 16)] ^ T3[byte(x[4] >> 24)] ^ T4[byte(x[3] >> 32)] ^ T5[byte(x[2] >> 40)] ^ T6[byte(x[1] >> 48)] ^ T7[byte(x[0] >> 56)] ^ (7 << 4) ^ round
}

func (d *digest256) G2(x [8]uint64, y *[8]uint64, round uint64) {
    var r uint64 = 0x00F0F0F0F0F0F0F3

    y[0] = (T0[byte(x[0])] ^ T1[byte(x[7] >> 8)] ^ T2[byte(x[6] >> 16)] ^ T3[byte(x[5] >> 24)] ^ T4[byte(x[4] >> 32)] ^ T5[byte(x[3] >> 40)] ^ T6[byte(x[2] >> 48)] ^ T7[byte(x[1] >> 56)]) + (r ^ ((((7 - 0) * 0x10) ^ round) << 56))
    y[1] = (T0[byte(x[1])] ^ T1[byte(x[0] >> 8)] ^ T2[byte(x[7] >> 16)] ^ T3[byte(x[6] >> 24)] ^ T4[byte(x[5] >> 32)] ^ T5[byte(x[4] >> 40)] ^ T6[byte(x[3] >> 48)] ^ T7[byte(x[2] >> 56)]) + (r ^ ((((7 - 1) * 0x10) ^ round) << 56))
    y[2] = (T0[byte(x[2])] ^ T1[byte(x[1] >> 8)] ^ T2[byte(x[0] >> 16)] ^ T3[byte(x[7] >> 24)] ^ T4[byte(x[6] >> 32)] ^ T5[byte(x[5] >> 40)] ^ T6[byte(x[4] >> 48)] ^ T7[byte(x[3] >> 56)]) + (r ^ ((((7 - 2) * 0x10) ^ round) << 56))
    y[3] = (T0[byte(x[3])] ^ T1[byte(x[2] >> 8)] ^ T2[byte(x[1] >> 16)] ^ T3[byte(x[0] >> 24)] ^ T4[byte(x[7] >> 32)] ^ T5[byte(x[6] >> 40)] ^ T6[byte(x[5] >> 48)] ^ T7[byte(x[4] >> 56)]) + (r ^ ((((7 - 3) * 0x10) ^ round) << 56))
    y[4] = (T0[byte(x[4])] ^ T1[byte(x[3] >> 8)] ^ T2[byte(x[2] >> 16)] ^ T3[byte(x[1] >> 24)] ^ T4[byte(x[0] >> 32)] ^ T5[byte(x[7] >> 40)] ^ T6[byte(x[6] >> 48)] ^ T7[byte(x[5] >> 56)]) + (r ^ ((((7 - 4) * 0x10) ^ round) << 56))
    y[5] = (T0[byte(x[5])] ^ T1[byte(x[4] >> 8)] ^ T2[byte(x[3] >> 16)] ^ T3[byte(x[2] >> 24)] ^ T4[byte(x[1] >> 32)] ^ T5[byte(x[0] >> 40)] ^ T6[byte(x[7] >> 48)] ^ T7[byte(x[6] >> 56)]) + (r ^ ((((7 - 5) * 0x10) ^ round) << 56))
    y[6] = (T0[byte(x[6])] ^ T1[byte(x[5] >> 8)] ^ T2[byte(x[4] >> 16)] ^ T3[byte(x[3] >> 24)] ^ T4[byte(x[2] >> 32)] ^ T5[byte(x[1] >> 40)] ^ T6[byte(x[0] >> 48)] ^ T7[byte(x[7] >> 56)]) + (r ^ ((((7 - 6) * 0x10) ^ round) << 56))
    y[7] = (T0[byte(x[7])] ^ T1[byte(x[6] >> 8)] ^ T2[byte(x[5] >> 16)] ^ T3[byte(x[4] >> 24)] ^ T4[byte(x[3] >> 32)] ^ T5[byte(x[2] >> 40)] ^ T6[byte(x[1] >> 48)] ^ T7[byte(x[0] >> 56)]) + (r ^ ((((7 - 7) * 0x10) ^ round) << 56))
}

func (d *digest256) P(x *[8]uint64, y *[8]uint64, round uint64) {
    var idx uint64
    for idx = 0; idx < 8; idx++ {
        x[idx] ^= (idx << 4) ^ round
    }

    d.G1(*x, y, round + 1)
    d.G(*y, x)
}

func (d *digest256) Q(x *[8]uint64, y *[8]uint64, round uint64) {
    var r uint64 = 0x00F0F0F0F0F0F0F3

    var j uint64
    for j = 0; j < 8; j++ {
        x[j] += (r ^ ((((7 - j) * 0x10) ^ round) << 56))
    }

    d.G2(*x, y, round + 1)
    d.G(*y, x)
}

func (d *digest256) outputTransform() {
    var t1, t2 [8]uint64

    copy(t1[:], d.s[:])

    var r uint64
    for r = 0; r < 10; r += 2 {
        d.P(&t1, &t2, r)
    }

    var column uint32
    for column = 0; column < 8; column++ {
        d.s[column] ^= t1[column]
    }
}

func (d *digest256) transform(b []uint64) {
    var AQ1, AP1, tmp [8]uint64

    var column uint32
    for column = 0; column < 8; column++ {
        AP1[column] = d.s[column] ^ b[column]
        AQ1[column] = b[column]
    }

    var r uint64
    for r = 0; r < 10; r += 2 {
        d.P(&AP1, &tmp, r)
        d.Q(&AQ1, &tmp, r)
    }

    for column = 0; column < 8; column++ {
        d.s[column] ^= AP1[column] ^ AQ1[column]
    }
}

func (d *digest256) block(b []byte) {
    d.transform(bytesToUint64s(b))
}
