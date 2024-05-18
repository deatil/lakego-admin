package fugue

const (
    // hash size
    Size224 = 28
    Size256 = 32
    Size384 = 48
    Size512 = 64

    BlockSize = 4
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [36]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    partial    uint32
    partialLen int
    rshift     uint32
    tmpS       [36]uint32

    initVal []uint32
    hs      int
}

// newDigest returns a new *digest computing the bmw checksum
func newDigest(initVal []uint32, hs int) *digest {
    d := new(digest)

    d.initVal = make([]uint32, len(initVal))
    copy(d.initVal, initVal)

    d.hs = hs
    d.Reset()

    return d
}

func (d *digest) Reset() {
    d.x = [BlockSize]byte{}
    d.s = [36]uint32{}

    d.nx = 0
    d.len = 0

    d.partial = 0
    d.partialLen = 0
    d.rshift = 0
    d.tmpS = [36]uint32{}

    var zlen int
    if d.hs <= 32 {
        zlen = 30 - len(d.initVal)
    } else {
        zlen = 36 - len(d.initVal)
    }

    copy(d.s[zlen:], d.initVal[:])
}

func (d *digest) Size() int {
    return d.hs
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn) << 3

    plen := len(p)
    off := 0
    for d.partialLen < 4 && plen > 0 {
        d.partial = (d.partial << 8) | uint32(p[off] & 0xFF)
        d.partialLen++
        off++
        plen--
    }

    if d.partialLen == 4 || plen > 0 {
        zlen := plen & ^3
        d.process(d.partial, p[off:], zlen >> 2)

        off += zlen
        plen -= zlen

        d.partial = 0
        d.partialLen = plen

        for plen > 0 {
            d.partial = (d.partial << 8) | uint32(p[off] & 0xFF)
            off++
            plen--
        }
    }

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() []byte {
    if d.partialLen != 0 {
        for d.partialLen < 4 {
            d.partial <<= 8
            d.partialLen++
        }

        d.processBlock(d.partial)
    }

    d.processBlock(uint32(d.len >> 32))
    d.processBlock(uint32(d.len))

    return d.processFinal()
}

func (d *digest) processBlock(w uint32) {
    d.process(w, nil, 0)
}

func (d *digest) process(w uint32, buf []byte, num int) {
    switch d.hs {
        case 28, 32:
            d.process2(w, buf, num)
        case 48:
            d.process384(w, buf, num)
        case 64:
            d.process512(w, buf, num)
    }
}

func (d *digest) processFinal() []byte {
    switch d.hs {
        case 28, 32:
            return d.processFinal2()
        case 48:
            return d.processFinal384()
        case 64:
            return d.processFinal512()
    }

    return nil
}

func (d *digest) ror(rc uint32, len uint32) {
    copy(d.tmpS[0:], d.s[len - rc:len])
    copy(d.s[rc:], d.s[0:len - rc])
    copy(d.s[0:], d.tmpS[0:rc])
}

// ========

func (d *digest) process2(w uint32, buf []byte, num int) {
    S := &d.s

    off := 0

    switch d.rshift {
    case 1:
        S[ 4] ^= S[24]
        S[24] = w
        S[ 2] ^= S[24]
        S[25] ^= S[18]
        S[21] ^= S[25]
        S[22] ^= S[26]
        S[23] ^= S[27]
        S[ 6] ^= S[25]
        S[ 7] ^= S[26]
        S[ 8] ^= S[27]
        smix(S[:], 21, 22, 23, 24)
        S[18] ^= S[22]
        S[19] ^= S[23]
        S[20] ^= S[24]
        S[ 3] ^= S[22]
        S[ 4] ^= S[23]
        S[ 5] ^= S[24]
        smix(S[:], 18, 19, 20, 21)
        if num <= 0 {
            d.rshift = 2
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        fallthrough
        /* fall through */
    case 2:
        S[28] ^= S[18]
        S[18] = w
        S[26] ^= S[18]
        S[19] ^= S[12]
        S[15] ^= S[19]
        S[16] ^= S[20]
        S[17] ^= S[21]
        S[ 0] ^= S[19]
        S[ 1] ^= S[20]
        S[ 2] ^= S[21]
        smix(S[:], 15, 16, 17, 18)
        S[12] ^= S[16]
        S[13] ^= S[17]
        S[14] ^= S[18]
        S[27] ^= S[16]
        S[28] ^= S[17]
        S[29] ^= S[18]
        smix(S[:], 12, 13, 14, 15)
        if num <= 0 {
            d.rshift = 3
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        fallthrough
        /* fall through */
    case 3:
        S[22] ^= S[12]
        S[12] = w
        S[20] ^= S[12]
        S[13] ^= S[ 6]
        S[ 9] ^= S[13]
        S[10] ^= S[14]
        S[11] ^= S[15]
        S[24] ^= S[13]
        S[25] ^= S[14]
        S[26] ^= S[15]
        smix(S[:],  9, 10, 11, 12)
        S[ 6] ^= S[10]
        S[ 7] ^= S[11]
        S[ 8] ^= S[12]
        S[21] ^= S[10]
        S[22] ^= S[11]
        S[23] ^= S[12]
        smix(S[:],  6,  7,  8,  9)
        if num <= 0 {
            d.rshift = 4
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        fallthrough
        /* fall through */
    case 4:
        S[16] ^= S[ 6]
        S[ 6] = w
        S[14] ^= S[ 6]
        S[ 7] ^= S[ 0]
        S[ 3] ^= S[ 7]
        S[ 4] ^= S[ 8]
        S[ 5] ^= S[ 9]
        S[18] ^= S[ 7]
        S[19] ^= S[ 8]
        S[20] ^= S[ 9]
        smix(S[:],  3,  4,  5,  6)
        S[ 0] ^= S[ 4]
        S[ 1] ^= S[ 5]
        S[ 2] ^= S[ 6]
        S[15] ^= S[ 4]
        S[16] ^= S[ 5]
        S[17] ^= S[ 6]
        smix(S[:],  0,  1,  2,  3)
        if num <= 0 {
            d.rshift = 0
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4
    }

    for {
        /* ================ */
        S[10] ^= S[ 0]
        S[ 0] = w
        S[ 8] ^= S[ 0]
        S[ 1] ^= S[24]
        S[27] ^= S[ 1]
        S[28] ^= S[ 2]
        S[29] ^= S[ 3]
        S[12] ^= S[ 1]
        S[13] ^= S[ 2]
        S[14] ^= S[ 3]
        smix(S[:], 27, 28, 29,  0)
        S[24] ^= S[28]
        S[25] ^= S[29]
        S[26] ^= S[ 0]
        S[ 9] ^= S[28]
        S[10] ^= S[29]
        S[11] ^= S[ 0]
        smix(S[:], 24, 25, 26, 27)
        if num <= 0 {
            d.rshift = 1
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[ 4] ^= S[24]
        S[24] = w
        S[ 2] ^= S[24]
        S[25] ^= S[18]
        S[21] ^= S[25]
        S[22] ^= S[26]
        S[23] ^= S[27]
        S[ 6] ^= S[25]
        S[ 7] ^= S[26]
        S[ 8] ^= S[27]
        smix(S[:], 21, 22, 23, 24)
        S[18] ^= S[22]
        S[19] ^= S[23]
        S[20] ^= S[24]
        S[ 3] ^= S[22]
        S[ 4] ^= S[23]
        S[ 5] ^= S[24]
        smix(S[:], 18, 19, 20, 21)
        if num <= 0 {
            d.rshift = 2
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[28] ^= S[18]
        S[18] = w
        S[26] ^= S[18]
        S[19] ^= S[12]
        S[15] ^= S[19]
        S[16] ^= S[20]
        S[17] ^= S[21]
        S[ 0] ^= S[19]
        S[ 1] ^= S[20]
        S[ 2] ^= S[21]
        smix(S[:], 15, 16, 17, 18)
        S[12] ^= S[16]
        S[13] ^= S[17]
        S[14] ^= S[18]
        S[27] ^= S[16]
        S[28] ^= S[17]
        S[29] ^= S[18]
        smix(S[:], 12, 13, 14, 15)
        if num <= 0 {
            d.rshift = 3
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[22] ^= S[12]
        S[12] = w
        S[20] ^= S[12]
        S[13] ^= S[ 6]
        S[ 9] ^= S[13]
        S[10] ^= S[14]
        S[11] ^= S[15]
        S[24] ^= S[13]
        S[25] ^= S[14]
        S[26] ^= S[15]
        smix(S[:],  9, 10, 11, 12)
        S[ 6] ^= S[10]
        S[ 7] ^= S[11]
        S[ 8] ^= S[12]
        S[21] ^= S[10]
        S[22] ^= S[11]
        S[23] ^= S[12]
        smix(S[:],  6,  7,  8,  9)
        if num <= 0 {
            d.rshift = 4
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[16] ^= S[ 6]
        S[ 6] = w
        S[14] ^= S[ 6]
        S[ 7] ^= S[ 0]
        S[ 3] ^= S[ 7]
        S[ 4] ^= S[ 8]
        S[ 5] ^= S[ 9]
        S[18] ^= S[ 7]
        S[19] ^= S[ 8]
        S[20] ^= S[ 9]
        smix(S[:],  3,  4,  5,  6)
        S[ 0] ^= S[ 4]
        S[ 1] ^= S[ 5]
        S[ 2] ^= S[ 6]
        S[15] ^= S[ 4]
        S[16] ^= S[ 5]
        S[17] ^= S[ 6]
        smix(S[:], 0,  1,  2,  3)
        if num <= 0 {
            d.rshift = 0
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4
    }
}

func (d *digest) processFinal2() (out []byte) {
    S := &d.s

    d.ror(6 * d.rshift, 30)

    for i := 0; i < 10; i++ {
        d.ror(3, 30)
        cmix30(S[:])
        smix(S[:], 0, 1, 2, 3)
    }

    for i := 0; i < 13; i++ {
        S[ 4] ^= S[ 0]
        S[15] ^= S[ 0]
        d.ror(15, 30)
        smix(S[:], 0, 1, 2, 3)
        S[ 4] ^= S[ 0]
        S[16] ^= S[ 0]
        d.ror(14, 30)
        smix(S[:], 0, 1, 2, 3)
    }

    S[ 4] ^= S[ 0]
    S[15] ^= S[ 0]

    if d.hs >= 32 {
        out = make([]byte, 32)
    } else {
        out = make([]byte, 28)
    }

    putu32(out[0:], S[1])
    putu32(out[4:], S[2])
    putu32(out[8:], S[3])
    putu32(out[12:], S[4])
    putu32(out[16:], S[15])
    putu32(out[20:], S[16])
    putu32(out[24:], S[17])

    if d.hs >= 32 {
        putu32(out[28:], S[18])
    }

    return out
}

// ========

func (d *digest) process384(w uint32, buf []byte, num int) {
    S := &d.s

    off := 0

    switch d.rshift {
    case 1:
        S[ 7] ^= S[27]
        S[27] = w
        S[35] ^= S[27]
        S[28] ^= S[18]
        S[31] ^= S[21]
        S[24] ^= S[28]
        S[25] ^= S[29]
        S[26] ^= S[30]
        S[ 6] ^= S[28]
        S[ 7] ^= S[29]
        S[ 8] ^= S[30]
        smix(S[:], 24, 25, 26, 27)
        S[21] ^= S[25]
        S[22] ^= S[26]
        S[23] ^= S[27]
        S[ 3] ^= S[25]
        S[ 4] ^= S[26]
        S[ 5] ^= S[27]
        smix(S[:], 21, 22, 23, 24)
        S[18] ^= S[22]
        S[19] ^= S[23]
        S[20] ^= S[24]
        S[ 0] ^= S[22]
        S[ 1] ^= S[23]
        S[ 2] ^= S[24]
        smix(S[:], 18, 19, 20, 21)

        if num <= 0 {
            d.rshift = 2
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        fallthrough
        /* fall through */
    case 2:
        S[34] ^= S[18]
        S[18] = w
        S[26] ^= S[18]
        S[19] ^= S[ 9]
        S[22] ^= S[12]
        S[15] ^= S[19]
        S[16] ^= S[20]
        S[17] ^= S[21]
        S[33] ^= S[19]
        S[34] ^= S[20]
        S[35] ^= S[21]
        smix(S[:], 15, 16, 17, 18)
        S[12] ^= S[16]
        S[13] ^= S[17]
        S[14] ^= S[18]
        S[30] ^= S[16]
        S[31] ^= S[17]
        S[32] ^= S[18]
        smix(S[:], 12, 13, 14, 15)
        S[ 9] ^= S[13]
        S[10] ^= S[14]
        S[11] ^= S[15]
        S[27] ^= S[13]
        S[28] ^= S[14]
        S[29] ^= S[15]
        smix(S[:],  9, 10, 11, 12)
        if num <= 0 {
            d.rshift = 3
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        fallthrough
        /* fall through */
    case 3:
        S[25] ^= S[ 9]
        S[ 9] = w
        S[17] ^= S[ 9]
        S[10] ^= S[ 0]
        S[13] ^= S[ 3]
        S[ 6] ^= S[10]
        S[ 7] ^= S[11]
        S[ 8] ^= S[12]
        S[24] ^= S[10]
        S[25] ^= S[11]
        S[26] ^= S[12]
        smix(S[:],  6,  7,  8,  9)
        S[ 3] ^= S[ 7]
        S[ 4] ^= S[ 8]
        S[ 5] ^= S[ 9]
        S[21] ^= S[ 7]
        S[22] ^= S[ 8]
        S[23] ^= S[ 9]
        smix(S[:],  3,  4,  5,  6)
        S[ 0] ^= S[ 4]
        S[ 1] ^= S[ 5]
        S[ 2] ^= S[ 6]
        S[18] ^= S[ 4]
        S[19] ^= S[ 5]
        S[20] ^= S[ 6]
        smix(S[:],  0,  1,  2,  3)
        if num <= 0 {
            d.rshift = 0
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4
    }

    for {
        /* ================ */
        S[16] ^= S[ 0]
        S[ 0] = w
        S[ 8] ^= S[ 0]
        S[ 1] ^= S[27]
        S[ 4] ^= S[30]
        S[33] ^= S[ 1]
        S[34] ^= S[ 2]
        S[35] ^= S[ 3]
        S[15] ^= S[ 1]
        S[16] ^= S[ 2]
        S[17] ^= S[ 3]
        smix(S[:], 33, 34, 35,  0)
        S[30] ^= S[34]
        S[31] ^= S[35]
        S[32] ^= S[ 0]
        S[12] ^= S[34]
        S[13] ^= S[35]
        S[14] ^= S[ 0]
        smix(S[:], 30, 31, 32, 33)
        S[27] ^= S[31]
        S[28] ^= S[32]
        S[29] ^= S[33]
        S[ 9] ^= S[31]
        S[10] ^= S[32]
        S[11] ^= S[33]
        smix(S[:], 27, 28, 29, 30)
        if num <= 0 {
            d.rshift = 1
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[ 7] ^= S[27]
        S[27] = w
        S[35] ^= S[27]
        S[28] ^= S[18]
        S[31] ^= S[21]
        S[24] ^= S[28]
        S[25] ^= S[29]
        S[26] ^= S[30]
        S[ 6] ^= S[28]
        S[ 7] ^= S[29]
        S[ 8] ^= S[30]
        smix(S[:], 24, 25, 26, 27)
        S[21] ^= S[25]
        S[22] ^= S[26]
        S[23] ^= S[27]
        S[ 3] ^= S[25]
        S[ 4] ^= S[26]
        S[ 5] ^= S[27]
        smix(S[:], 21, 22, 23, 24)
        S[18] ^= S[22]
        S[19] ^= S[23]
        S[20] ^= S[24]
        S[ 0] ^= S[22]
        S[ 1] ^= S[23]
        S[ 2] ^= S[24]
        smix(S[:], 18, 19, 20, 21)
        if num <= 0 {
            d.rshift = 2
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[34] ^= S[18]
        S[18] = w
        S[26] ^= S[18]
        S[19] ^= S[ 9]
        S[22] ^= S[12]
        S[15] ^= S[19]
        S[16] ^= S[20]
        S[17] ^= S[21]
        S[33] ^= S[19]
        S[34] ^= S[20]
        S[35] ^= S[21]
        smix(S[:], 15, 16, 17, 18)
        S[12] ^= S[16]
        S[13] ^= S[17]
        S[14] ^= S[18]
        S[30] ^= S[16]
        S[31] ^= S[17]
        S[32] ^= S[18]
        smix(S[:], 12, 13, 14, 15)
        S[ 9] ^= S[13]
        S[10] ^= S[14]
        S[11] ^= S[15]
        S[27] ^= S[13]
        S[28] ^= S[14]
        S[29] ^= S[15]
        smix(S[:],  9, 10, 11, 12)
        if num <= 0 {
            d.rshift = 3
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[25] ^= S[ 9]
        S[ 9] = w
        S[17] ^= S[ 9]
        S[10] ^= S[ 0]
        S[13] ^= S[ 3]
        S[ 6] ^= S[10]
        S[ 7] ^= S[11]
        S[ 8] ^= S[12]
        S[24] ^= S[10]
        S[25] ^= S[11]
        S[26] ^= S[12]
        smix(S[:],  6,  7,  8,  9)
        S[ 3] ^= S[ 7]
        S[ 4] ^= S[ 8]
        S[ 5] ^= S[ 9]
        S[21] ^= S[ 7]
        S[22] ^= S[ 8]
        S[23] ^= S[ 9]
        smix(S[:],  3,  4,  5,  6)
        S[ 0] ^= S[ 4]
        S[ 1] ^= S[ 5]
        S[ 2] ^= S[ 6]
        S[18] ^= S[ 4]
        S[19] ^= S[ 5]
        S[20] ^= S[ 6]
        smix(S[:],  0,  1,  2,  3)
        if num <= 0 {
            d.rshift = 0
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4
    }
}

func (d *digest) processFinal384() (out []byte) {
    S := &d.s

    d.ror(9 * d.rshift, 36)

    for i := 0; i < 18; i++ {
        d.ror(3, 36)
        cmix36(S[:])
        smix(S[:], 0, 1, 2, 3)
    }

    for i := 0; i < 13; i++ {
        S[ 4] ^= S[ 0]
        S[12] ^= S[ 0]
        S[24] ^= S[ 0]
        d.ror(12, 36)
        smix(S[:], 0, 1, 2, 3)
        S[ 4] ^= S[ 0]
        S[13] ^= S[ 0]
        S[24] ^= S[ 0]
        d.ror(12, 36)
        smix(S[:], 0, 1, 2, 3)
        S[ 4] ^= S[ 0]
        S[13] ^= S[ 0]
        S[25] ^= S[ 0]
        d.ror(11, 36)
        smix(S[:], 0, 1, 2, 3)
    }

    S[ 4] ^= S[ 0]
    S[12] ^= S[ 0]
    S[24] ^= S[ 0]

    out = make([]byte, 48)

    putu32(out[0:], S[1])
    putu32(out[4:], S[2])
    putu32(out[8:], S[3])
    putu32(out[12:], S[4])
    putu32(out[16:], S[12])
    putu32(out[20:], S[13])
    putu32(out[24:], S[14])
    putu32(out[28:], S[15])
    putu32(out[32:], S[24])
    putu32(out[36:], S[25])
    putu32(out[40:], S[26])
    putu32(out[44:], S[27])

    return
}

// ========

func (d *digest) process512(w uint32, buf []byte, num int) {
    S := &d.s

    off := 0

    switch d.rshift {
    case 1:
        S[10] ^= S[24]
        S[24] = w
        S[32] ^= S[24]
        S[25] ^= S[12]
        S[28] ^= S[15]
        S[31] ^= S[18]
        S[21] ^= S[25]
        S[22] ^= S[26]
        S[23] ^= S[27]
        S[ 3] ^= S[25]
        S[ 4] ^= S[26]
        S[ 5] ^= S[27]
        smix(S[:], 21, 22, 23, 24)
        S[18] ^= S[22]
        S[19] ^= S[23]
        S[20] ^= S[24]
        S[ 0] ^= S[22]
        S[ 1] ^= S[23]
        S[ 2] ^= S[24]
        smix(S[:], 18, 19, 20, 21)
        S[15] ^= S[19]
        S[16] ^= S[20]
        S[17] ^= S[21]
        S[33] ^= S[19]
        S[34] ^= S[20]
        S[35] ^= S[21]
        smix(S[:], 15, 16, 17, 18)
        S[12] ^= S[16]
        S[13] ^= S[17]
        S[14] ^= S[18]
        S[30] ^= S[16]
        S[31] ^= S[17]
        S[32] ^= S[18]
        smix(S[:], 12, 13, 14, 15)
        if num <= 0 {
            d.rshift = 2
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        fallthrough
        /* fall through */
    case 2:
        S[34] ^= S[12]
        S[12] = w
        S[20] ^= S[12]
        S[13] ^= S[ 0]
        S[16] ^= S[ 3]
        S[19] ^= S[ 6]
        S[ 9] ^= S[13]
        S[10] ^= S[14]
        S[11] ^= S[15]
        S[27] ^= S[13]
        S[28] ^= S[14]
        S[29] ^= S[15]
        smix(S[:],  9, 10, 11, 12)
        S[ 6] ^= S[10]
        S[ 7] ^= S[11]
        S[ 8] ^= S[12]
        S[24] ^= S[10]
        S[25] ^= S[11]
        S[26] ^= S[12]
        smix(S[:],  6,  7,  8,  9)
        S[ 3] ^= S[ 7]
        S[ 4] ^= S[ 8]
        S[ 5] ^= S[ 9]
        S[21] ^= S[ 7]
        S[22] ^= S[ 8]
        S[23] ^= S[ 9]
        smix(S[:],  3,  4,  5,  6)
        S[ 0] ^= S[ 4]
        S[ 1] ^= S[ 5]
        S[ 2] ^= S[ 6]
        S[18] ^= S[ 4]
        S[19] ^= S[ 5]
        S[20] ^= S[ 6]
        smix(S[:],  0,  1,  2,  3)
        if num <= 0 {
            d.rshift = 0
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4
    }

    for {
        /* ================ */
        S[22] ^= S[ 0]
        S[ 0] = w
        S[ 8] ^= S[ 0]
        S[ 1] ^= S[24]
        S[ 4] ^= S[27]
        S[ 7] ^= S[30]
        S[33] ^= S[ 1]
        S[34] ^= S[ 2]
        S[35] ^= S[ 3]
        S[15] ^= S[ 1]
        S[16] ^= S[ 2]
        S[17] ^= S[ 3]
        smix(S[:], 33, 34, 35,  0)
        S[30] ^= S[34]
        S[31] ^= S[35]
        S[32] ^= S[ 0]
        S[12] ^= S[34]
        S[13] ^= S[35]
        S[14] ^= S[ 0]
        smix(S[:], 30, 31, 32, 33)
        S[27] ^= S[31]
        S[28] ^= S[32]
        S[29] ^= S[33]
        S[ 9] ^= S[31]
        S[10] ^= S[32]
        S[11] ^= S[33]
        smix(S[:], 27, 28, 29, 30)
        S[24] ^= S[28]
        S[25] ^= S[29]
        S[26] ^= S[30]
        S[ 6] ^= S[28]
        S[ 7] ^= S[29]
        S[ 8] ^= S[30]
        smix(S[:], 24, 25, 26, 27)
        if num <= 0 {
            d.rshift = 1
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[10] ^= S[24]
        S[24] = w
        S[32] ^= S[24]
        S[25] ^= S[12]
        S[28] ^= S[15]
        S[31] ^= S[18]
        S[21] ^= S[25]
        S[22] ^= S[26]
        S[23] ^= S[27]
        S[ 3] ^= S[25]
        S[ 4] ^= S[26]
        S[ 5] ^= S[27]
        smix(S[:], 21, 22, 23, 24)
        S[18] ^= S[22]
        S[19] ^= S[23]
        S[20] ^= S[24]
        S[ 0] ^= S[22]
        S[ 1] ^= S[23]
        S[ 2] ^= S[24]
        smix(S[:], 18, 19, 20, 21)
        S[15] ^= S[19]
        S[16] ^= S[20]
        S[17] ^= S[21]
        S[33] ^= S[19]
        S[34] ^= S[20]
        S[35] ^= S[21]
        smix(S[:], 15, 16, 17, 18)
        S[12] ^= S[16]
        S[13] ^= S[17]
        S[14] ^= S[18]
        S[30] ^= S[16]
        S[31] ^= S[17]
        S[32] ^= S[18]
        smix(S[:], 12, 13, 14, 15)
        if num <= 0 {
            d.rshift = 2
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4

        /* ================ */
        S[34] ^= S[12]
        S[12] = w
        S[20] ^= S[12]
        S[13] ^= S[ 0]
        S[16] ^= S[ 3]
        S[19] ^= S[ 6]
        S[ 9] ^= S[13]
        S[10] ^= S[14]
        S[11] ^= S[15]
        S[27] ^= S[13]
        S[28] ^= S[14]
        S[29] ^= S[15]
        smix(S[:],  9, 10, 11, 12)
        S[ 6] ^= S[10]
        S[ 7] ^= S[11]
        S[ 8] ^= S[12]
        S[24] ^= S[10]
        S[25] ^= S[11]
        S[26] ^= S[12]
        smix(S[:],  6,  7,  8,  9)
        S[ 3] ^= S[ 7]
        S[ 4] ^= S[ 8]
        S[ 5] ^= S[ 9]
        S[21] ^= S[ 7]
        S[22] ^= S[ 8]
        S[23] ^= S[ 9]
        smix(S[:],  3,  4,  5,  6)
        S[ 0] ^= S[ 4]
        S[ 1] ^= S[ 5]
        S[ 2] ^= S[ 6]
        S[18] ^= S[ 4]
        S[19] ^= S[ 5]
        S[20] ^= S[ 6]
        smix(S[:],  0,  1,  2,  3)
        if num <= 0 {
            d.rshift = 0
            return
        }
        num--

        w = getu32(buf[off:])
        off += 4
    }
}

func (d *digest) processFinal512() (out []byte) {
    S := &d.s

    d.ror(12 * d.rshift, 36)

    for i := 0; i < 32; i++ {
        d.ror(3, 36)
        cmix36(S[:])
        smix(S[:], 0, 1, 2, 3)
    }

    for i := 0; i < 13; i++ {
        S[ 4] ^= S[ 0]
        S[ 9] ^= S[ 0]
        S[18] ^= S[ 0]
        S[27] ^= S[ 0]
        d.ror(9, 36)
        smix(S[:], 0, 1, 2, 3)
        S[ 4] ^= S[ 0]
        S[10] ^= S[ 0]
        S[18] ^= S[ 0]
        S[27] ^= S[ 0]
        d.ror(9, 36)
        smix(S[:], 0, 1, 2, 3)
        S[ 4] ^= S[ 0]
        S[10] ^= S[ 0]
        S[19] ^= S[ 0]
        S[27] ^= S[ 0]
        d.ror(9, 36)
        smix(S[:], 0, 1, 2, 3)
        S[ 4] ^= S[ 0]
        S[10] ^= S[ 0]
        S[19] ^= S[ 0]
        S[28] ^= S[ 0]
        d.ror(8, 36)
        smix(S[:], 0, 1, 2, 3)
    }
    S[ 4] ^= S[ 0]
    S[ 9] ^= S[ 0]
    S[18] ^= S[ 0]
    S[27] ^= S[ 0]

    out = make([]byte, 64)

    putu32(out[0:], S[1])
    putu32(out[4:], S[2])
    putu32(out[8:], S[3])
    putu32(out[12:], S[4])
    putu32(out[16:], S[9])
    putu32(out[20:], S[10])
    putu32(out[24:], S[11])
    putu32(out[28:], S[12])
    putu32(out[32:], S[18])
    putu32(out[36:], S[19])
    putu32(out[40:], S[20])
    putu32(out[44:], S[21])
    putu32(out[48:], S[27])
    putu32(out[52:], S[28])
    putu32(out[56:], S[29])
    putu32(out[60:], S[30])

    return
}

