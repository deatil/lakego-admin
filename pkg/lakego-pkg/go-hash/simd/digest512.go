package simd

const (
    // hash size
    Size384 = 48
    Size512 = 64

    BlockSize512 = 128
)

// digest512 represents the partial evaluation of a checksum.
type digest512 struct {
    s   [32]uint32
    x   [BlockSize512]byte
    nx  int
    len uint64

    state    [32]uint32
    q        [256]int32
    w        [64]uint32
    tmpState [32]uint32
    tA       [8]uint32

    hs      int
    initVal [32]uint32
}

// newDigest512 returns a new hash.Hash computing the checksum
func newDigest512(hs int, initVal [32]uint32) *digest512 {
    d := new(digest512)
    d.hs = hs
    d.initVal = initVal
    d.Reset()

    return d
}

func (d *digest512) Reset() {
    d.s = d.initVal
    d.x = [BlockSize512]byte{}

    d.nx = 0
    d.len = 0

    d.state = d.initVal
    d.q = [256]int32{}
    d.w = [64]uint32{}
    d.tmpState = [32]uint32{}
    d.tA = [8]uint32{}
}

func (d *digest512) Size() int {
    return d.hs
}

func (d *digest512) BlockSize() int {
    return BlockSize512
}

func (d *digest512) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)
    for d.nx + plen >= BlockSize512 {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        xx := BlockSize512 - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest512) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest512) checkSum() (out []byte) {
    ptr := d.nx

    var buf = d.x
    if ptr != 0 {
        for i := ptr; i < 128; i++ {
            buf[i] = 0x00
        }

        d.compress(buf[:], false)
    }

    var count = ((d.len / BlockSize512) << 10) + uint64(ptr << 3)

    putu32(buf[0:], uint32(count))
    putu32(buf[4:], uint32(count >> 32))

    for i := 8; i < 128; i++ {
        buf[i] = 0x00
    }

    d.compress(buf[:], true)

    var n = d.hs >> 2

    out = make([]byte, d.hs)
    for i := 0; i < n; i++ {
        putu32(out[(i << 2):], d.state[i])
    }

    return
}

func (d *digest512) processBlock(data []byte) {
    d.compress(data, false)
}

func (d *digest512) compress(x []byte, last bool) {
    w := &d.w
    q := &d.q
    state := &d.state
    tmpState := &d.tmpState

    var tmp uint32
    d.fft64(x, 0 + (1 * 0), 1 << 2, 0 + 0)
    d.fft64(x, 0 + (1 * 2), 1 << 2, 0 + 64)

    var m = q[0]
    var n = q[0 + 64]

    q[0] = m + n
    q[0 + 64] = m - n

    for u, v := 0, 0; u < 64; u, v = u + 4, v + 4 * 2 {
        var t int32
        if u != 0 {
            m = q[0 + u + 0]
            n = q[0 + u + 0 + 64]
            t = ((n * alphaTab512[v + 0 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 0 * 2]) >> 16)
            q[0 + u + 0] = m + t
            q[0 + u + 0 + 64] = m - t
        }

        m = q[0 + u + 1]
        n = q[0 + u + 1 + 64]
        t = ((n * alphaTab512[v + 1 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 1 * 2]) >> 16)
        q[0 + u + 1] = m + t
        q[0 + u + 1 + 64] = m - t

        m = q[0 + u + 2]
        n = q[0 + u + 2 + 64]
        t = ((n * alphaTab512[v + 2 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 2 * 2]) >> 16)
        q[0 + u + 2] = m + t
        q[0 + u + 2 + 64] = m - t

        m = q[0 + u + 3]
        n = q[0 + u + 3 + 64]
        t = ((n * alphaTab512[v + 3 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 3 * 2]) >> 16)
        q[0 + u + 3] = m + t
        q[0 + u + 3 + 64] = m - t
    }

    d.fft64(x, 0 + (1 * 1), 1 << 2, 0 + 128)
    d.fft64(x, 0 + (1 * 3), 1 << 2, 0 + 192)

    m = q[0 + 128]
    n = q[0 + 128 + 64]

    q[0 + 128] = m + n
    q[0 + 128 + 64] = m - n

    for u, v := 0, 0; u < 64; u, v = u + 4, v + 4 * 2 {
        var t int32
        if u != 0 {
            m = q[(0 + 128) + u + 0]
            n = q[(0 + 128) + u + 0 + 64]
            t = ((n * alphaTab512[v + 0 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 0 * 2]) >> 16)
            q[(0 + 128) + u + 0] = m + t
            q[(0 + 128) + u + 0 + 64] = m - t
        }

        m = q[(0 + 128) + u + 1]
        n = q[(0 + 128) + u + 1 + 64]
        t = ((n * alphaTab512[v + 1 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 1 * 2]) >> 16)
        q[(0 + 128) + u + 1] = m + t
        q[(0 + 128) + u + 1 + 64] = m - t

        m = q[(0 + 128) + u + 2]
        n = q[(0 + 128) + u + 2 + 64]
        t = ((n * alphaTab512[v + 2 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 2 * 2]) >> 16)
        q[(0 + 128) + u + 2] = m + t
        q[(0 + 128) + u + 2 + 64] = m - t

        m = q[(0 + 128) + u + 3]
        n = q[(0 + 128) + u + 3 + 64]
        t = ((n * alphaTab512[v + 3 * 2]) & 0xFFFF) + ((n * alphaTab512[v + 3 * 2]) >> 16)
        q[(0 + 128) + u + 3] = m + t
        q[(0 + 128) + u + 3 + 64] = m - t
    }

    m = q[0]
    n = q[0 + 128]

    q[0] = m + n
    q[0 + 128] = m - n

    for u, v := 0, 0; u < 128; u, v = u + 4, v + 4 * 1 {
        var t int32
        if u != 0 {
            m = q[0 + u + 0]
            n = q[0 + u + 0 + 128]
            t = ((n * alphaTab512[v + 0 * 1]) & 0xFFFF) + ((n * alphaTab512[v + 0 * 1]) >> 16)
            q[0 + u + 0] = m + t
            q[0 + u + 0 + 128] = m - t
        }

        m = q[0 + u + 1]
        n = q[0 + u + 1 + 128]
        t = ((n * alphaTab512[v + 1 * 1]) & 0xFFFF) + ((n * alphaTab512[v + 1 * 1]) >> 16)
        q[0 + u + 1] = m + t
        q[0 + u + 1 + 128] = m - t

        m = q[0 + u + 2]
        n = q[0 + u + 2 + 128]
        t = ((n * alphaTab512[v + 2 * 1]) & 0xFFFF) + ((n * alphaTab512[v + 2 * 1]) >> 16)
        q[0 + u + 2] = m + t
        q[0 + u + 2 + 128] = m - t

        m = q[0 + u + 3]
        n = q[0 + u + 3 + 128]
        t = ((n * alphaTab512[v + 3 * 1]) & 0xFFFF) + ((n * alphaTab512[v + 3 * 1]) >> 16)
        q[0 + u + 3] = m + t
        q[0 + u + 3 + 128] = m - t
    }

    if last {
        for i := 0; i < 256; i++ {
            var tq = q[i] + yoffF512[i]
            tq = ((tq & 0xFFFF) + (tq >> 16))
            tq = ((tq & 0xFF) - (tq >> 8))
            tq = ((tq & 0xFF) - (tq >> 8))

            if tq <= 128 {
                q[i] = tq
            } else {
                q[i] = tq - 257
            }
        }
    } else {
        for i := 0; i < 256; i++ {
            var tq = q[i] + yoffN512[i]
            tq = ((tq & 0xFFFF) + (tq >> 16))
            tq = ((tq & 0xFF) - (tq >> 8))
            tq = ((tq & 0xFF) - (tq >> 8))

            if tq <= 128 {
                q[i] = tq
            } else {
                q[i] = tq - 257
            }
        }
    }

    copy(tmpState[:], state[:])

    for i := 0; i < 32; i += 8 {
        state[i + 0] ^= getu32(x[4 * (i + 0):])
        state[i + 1] ^= getu32(x[4 * (i + 1):])
        state[i + 2] ^= getu32(x[4 * (i + 2):])
        state[i + 3] ^= getu32(x[4 * (i + 3):])
        state[i + 4] ^= getu32(x[4 * (i + 4):])
        state[i + 5] ^= getu32(x[4 * (i + 5):])
        state[i + 6] ^= getu32(x[4 * (i + 6):])
        state[i + 7] ^= getu32(x[4 * (i + 7):])
    }

    for u := 0; u < 64; u += 8 {
        var v = wbp512[(u >> 3) + 0]
        w[u + 0] = (uint32((q[v + 2 * 0 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 0 + 1]) * 185) << 16)
        w[u + 1] = (uint32((q[v + 2 * 1 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 1 + 1]) * 185) << 16)
        w[u + 2] = (uint32((q[v + 2 * 2 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 2 + 1]) * 185) << 16)
        w[u + 3] = (uint32((q[v + 2 * 3 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 3 + 1]) * 185) << 16)
        w[u + 4] = (uint32((q[v + 2 * 4 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 4 + 1]) * 185) << 16)
        w[u + 5] = (uint32((q[v + 2 * 5 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 5 + 1]) * 185) << 16)
        w[u + 6] = (uint32((q[v + 2 * 6 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 6 + 1]) * 185) << 16)
        w[u + 7] = (uint32((q[v + 2 * 7 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 7 + 1]) * 185) << 16)
    }
    d.oneRound(0, 3, 23, 17, 27)

    for u := 0; u < 64; u += 8 {
        var v = wbp512[(u >> 3) + 8]
        w[u + 0] = (uint32((q[v + 2 * 0 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 0 + 1]) * 185) << 16)
        w[u + 1] = (uint32((q[v + 2 * 1 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 1 + 1]) * 185) << 16)
        w[u + 2] = (uint32((q[v + 2 * 2 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 2 + 1]) * 185) << 16)
        w[u + 3] = (uint32((q[v + 2 * 3 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 3 + 1]) * 185) << 16)
        w[u + 4] = (uint32((q[v + 2 * 4 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 4 + 1]) * 185) << 16)
        w[u + 5] = (uint32((q[v + 2 * 5 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 5 + 1]) * 185) << 16)
        w[u + 6] = (uint32((q[v + 2 * 6 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 6 + 1]) * 185) << 16)
        w[u + 7] = (uint32((q[v + 2 * 7 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 7 + 1]) * 185) << 16)
    }
    d.oneRound(1, 28, 19, 22, 7)

    for u := 0; u < 64; u += 8 {
        var v = wbp512[(u >> 3) + 16]
        w[u + 0] = (uint32((q[v + 2 * 0 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 0 + (-128)]) * 233) << 16)
        w[u + 1] = (uint32((q[v + 2 * 1 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 1 + (-128)]) * 233) << 16)
        w[u + 2] = (uint32((q[v + 2 * 2 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 2 + (-128)]) * 233) << 16)
        w[u + 3] = (uint32((q[v + 2 * 3 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 3 + (-128)]) * 233) << 16)
        w[u + 4] = (uint32((q[v + 2 * 4 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 4 + (-128)]) * 233) << 16)
        w[u + 5] = (uint32((q[v + 2 * 5 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 5 + (-128)]) * 233) << 16)
        w[u + 6] = (uint32((q[v + 2 * 6 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 6 + (-128)]) * 233) << 16)
        w[u + 7] = (uint32((q[v + 2 * 7 + (-256)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 7 + (-128)]) * 233) << 16)
    }
    d.oneRound(2, 29, 9, 15, 5)

    for u := 0; u < 64; u += 8 {
        var v = wbp512[(u >> 3) + 24]
        w[u + 0] = (uint32((q[v + 2 * 0 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 0 + (-255)]) * 233) << 16)
        w[u + 1] = (uint32((q[v + 2 * 1 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 1 + (-255)]) * 233) << 16)
        w[u + 2] = (uint32((q[v + 2 * 2 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 2 + (-255)]) * 233) << 16)
        w[u + 3] = (uint32((q[v + 2 * 3 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 3 + (-255)]) * 233) << 16)
        w[u + 4] = (uint32((q[v + 2 * 4 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 4 + (-255)]) * 233) << 16)
        w[u + 5] = (uint32((q[v + 2 * 5 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 5 + (-255)]) * 233) << 16)
        w[u + 6] = (uint32((q[v + 2 * 6 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 6 + (-255)]) * 233) << 16)
        w[u + 7] = (uint32((q[v + 2 * 7 + (-383)]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 7 + (-255)]) * 233) << 16)
    }
    d.oneRound(3, 4, 13, 10, 25)

    {
        var tA0 = circularLeft(state[0], 4)
        var tA1 = circularLeft(state[1], 4)
        var tA2 = circularLeft(state[2], 4)
        var tA3 = circularLeft(state[3], 4)
        var tA4 = circularLeft(state[4], 4)
        var tA5 = circularLeft(state[5], 4)
        var tA6 = circularLeft(state[6], 4)
        var tA7 = circularLeft(state[7], 4)

        tmp = state[24] + (tmpState[0]) + (((state[8] ^ state[16]) & state[0]) ^ state[16])
        state[0] = circularLeft(tmp, 13) + tA5
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA0

        tmp = state[25] + (tmpState[1]) + (((state[9] ^ state[17]) & state[1]) ^ state[17])
        state[1] = circularLeft(tmp, 13) + tA4
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA1

        tmp = state[26] + (tmpState[2]) + (((state[10] ^ state[18]) & state[2]) ^ state[18])
        state[2] = circularLeft(tmp, 13) + tA7
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA2

        tmp = state[27] + (tmpState[3]) + (((state[11] ^ state[19]) & state[3]) ^ state[19])
        state[3] = circularLeft(tmp, 13) + tA6
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA3

        tmp = state[28] + (tmpState[4]) + (((state[12] ^ state[20]) & state[4]) ^ state[20])
        state[4] = circularLeft(tmp, 13) + tA1
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA4

        tmp = state[29] + (tmpState[5]) + (((state[13] ^ state[21]) & state[5]) ^ state[21])
        state[5] = circularLeft(tmp, 13) + tA0
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA5

        tmp = state[30] + (tmpState[6]) + (((state[14] ^ state[22]) & state[6]) ^ state[22])
        state[6] = circularLeft(tmp, 13) + tA3
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA6

        tmp = state[31] + (tmpState[7]) + (((state[15] ^ state[23]) & state[7]) ^ state[23])
        state[7] = circularLeft(tmp, 13) + tA2
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA7
    }
    {
        var tA0 = circularLeft(state[0], 13)
        var tA1 = circularLeft(state[1], 13)
        var tA2 = circularLeft(state[2], 13)
        var tA3 = circularLeft(state[3], 13)
        var tA4 = circularLeft(state[4], 13)
        var tA5 = circularLeft(state[5], 13)
        var tA6 = circularLeft(state[6], 13)
        var tA7 = circularLeft(state[7], 13)

        tmp = state[24] + (tmpState[8]) + (((state[8] ^ state[16]) & state[0]) ^ state[16])
        state[0] = circularLeft(tmp, 10) + tA7
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA0

        tmp = state[25] + (tmpState[9]) + (((state[9] ^ state[17]) & state[1]) ^ state[17])
        state[1] = circularLeft(tmp, 10) + tA6
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA1

        tmp = state[26] + (tmpState[10]) + (((state[10] ^ state[18]) & state[2]) ^ state[18])
        state[2] = circularLeft(tmp, 10) + tA5
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA2

        tmp = state[27] + (tmpState[11]) + (((state[11] ^ state[19]) & state[3]) ^ state[19])
        state[3] = circularLeft(tmp, 10) + tA4
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA3

        tmp = state[28] + (tmpState[12]) + (((state[12] ^ state[20]) & state[4]) ^ state[20])
        state[4] = circularLeft(tmp, 10) + tA3
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA4

        tmp = state[29] + (tmpState[13]) + (((state[13] ^ state[21]) & state[5]) ^ state[21])
        state[5] = circularLeft(tmp, 10) + tA2
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA5

        tmp = state[30] + (tmpState[14]) + (((state[14] ^ state[22]) & state[6]) ^ state[22])
        state[6] = circularLeft(tmp, 10) + tA1
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA6

        tmp = state[31] + (tmpState[15]) + (((state[15] ^ state[23]) & state[7]) ^ state[23])
        state[7] = circularLeft(tmp, 10) + tA0
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA7
    }
    {
        var tA0 = circularLeft(state[0], 10)
        var tA1 = circularLeft(state[1], 10)
        var tA2 = circularLeft(state[2], 10)
        var tA3 = circularLeft(state[3], 10)
        var tA4 = circularLeft(state[4], 10)
        var tA5 = circularLeft(state[5], 10)
        var tA6 = circularLeft(state[6], 10)
        var tA7 = circularLeft(state[7], 10)

        tmp = state[24] + (tmpState[16]) + (((state[8] ^ state[16]) & state[0]) ^ state[16])
        state[0] = circularLeft(tmp, 25) + tA4
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA0

        tmp = state[25] + (tmpState[17]) + (((state[9] ^ state[17]) & state[1]) ^ state[17])
        state[1] = circularLeft(tmp, 25) + tA5
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA1

        tmp = state[26] + (tmpState[18]) + (((state[10] ^ state[18]) & state[2]) ^ state[18])
        state[2] = circularLeft(tmp, 25) + tA6
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA2

        tmp = state[27] + (tmpState[19]) + (((state[11] ^ state[19]) & state[3]) ^ state[19])
        state[3] = circularLeft(tmp, 25) + tA7
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA3

        tmp = state[28] + (tmpState[20]) + (((state[12] ^ state[20]) & state[4]) ^ state[20])
        state[4] = circularLeft(tmp, 25) + tA0
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA4

        tmp = state[29] + (tmpState[21]) + (((state[13] ^ state[21]) & state[5]) ^ state[21])
        state[5] = circularLeft(tmp, 25) + tA1
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA5

        tmp = state[30] + (tmpState[22]) + (((state[14] ^ state[22]) & state[6]) ^ state[22])
        state[6] = circularLeft(tmp, 25) + tA2
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA6

        tmp = state[31] + (tmpState[23]) + (((state[15] ^ state[23]) & state[7]) ^ state[23])
        state[7] = circularLeft(tmp, 25) + tA3
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA7
    }
    {
        var tA0 = circularLeft(state[0], 25)
        var tA1 = circularLeft(state[1], 25)
        var tA2 = circularLeft(state[2], 25)
        var tA3 = circularLeft(state[3], 25)
        var tA4 = circularLeft(state[4], 25)
        var tA5 = circularLeft(state[5], 25)
        var tA6 = circularLeft(state[6], 25)
        var tA7 = circularLeft(state[7], 25)

        tmp = state[24] + (tmpState[24]) + (((state[8] ^ state[16]) & state[0]) ^ state[16])
        state[0] = circularLeft(tmp, 4) + tA1
        state[24] = state[16]
        state[16] = state[8]
        state[8] = tA0

        tmp = state[25] + (tmpState[25]) + (((state[9] ^ state[17]) & state[1]) ^ state[17])
        state[1] = circularLeft(tmp, 4) + tA0
        state[25] = state[17]
        state[17] = state[9]
        state[9] = tA1

        tmp = state[26] + (tmpState[26]) + (((state[10] ^ state[18]) & state[2]) ^ state[18])
        state[2] = circularLeft(tmp, 4) + tA3
        state[26] = state[18]
        state[18] = state[10]
        state[10] = tA2

        tmp = state[27] + (tmpState[27]) + (((state[11] ^ state[19]) & state[3]) ^ state[19])
        state[3] = circularLeft(tmp, 4) + tA2
        state[27] = state[19]
        state[19] = state[11]
        state[11] = tA3

        tmp = state[28] + (tmpState[28]) + (((state[12] ^ state[20]) & state[4]) ^ state[20])
        state[4] = circularLeft(tmp, 4) + tA5
        state[28] = state[20]
        state[20] = state[12]
        state[12] = tA4

        tmp = state[29] + (tmpState[29]) + (((state[13] ^ state[21]) & state[5]) ^ state[21])
        state[5] = circularLeft(tmp, 4) + tA4
        state[29] = state[21]
        state[21] = state[13]
        state[13] = tA5

        tmp = state[30] + (tmpState[30]) + (((state[14] ^ state[22]) & state[6]) ^ state[22])
        state[6] = circularLeft(tmp, 4) + tA7
        state[30] = state[22]
        state[22] = state[14]
        state[14] = tA6

        tmp = state[31] + (tmpState[31]) + (((state[15] ^ state[23]) & state[7]) ^ state[23])
        state[7] = circularLeft(tmp, 4) + tA6
        state[31] = state[23]
        state[23] = state[15]
        state[15] = tA7
    }
}

func (d *digest512) oneRound(isp, p0, p1, p2, p3 int) {
    state := &d.state
    w := &d.w
    tA := &d.tA

    var tmp uint32

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p0)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[i]) +
            (((state[8+i] ^ state[16+i]) &
                state[i]) ^ state[16+i])
        state[i] = circularLeft(tmp, p1) +
            tA[(pp8k512[isp + 0]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[i]
    }

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p1)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[8+i]) +
            (((state[8+i] ^ state[16+i]) &
                state[i]) ^ state[16+i])
        state[i] = circularLeft(tmp, p2) +
            tA[(pp8k512[isp + 1]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[i]
    }

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p2)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[16+i]) +
            (((state[8+i] ^ state[16+i]) &
                state[i]) ^ state[16+i])
        state[i] = circularLeft(tmp, p3) +
            tA[(pp8k512[isp + 2]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[i]
    }

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p3)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[24+i]) +
            (((state[8+i] ^ state[16+i]) &
                state[i]) ^ state[16+i])
        state[i] = circularLeft(tmp, p0) +
            tA[(pp8k512[isp + 3]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[i]
    }

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p0)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[32+i]) +
            ((state[0+i] & state[8+i]) | ((state[0+i] |
                state[8+i]) & state[16+i]))
        state[0+i] = circularLeft(tmp, p1) +
            tA[(pp8k512[isp + 4]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[0+i]
    }

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p1)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[40+i]) +
            ((state[0+i] & state[8+i]) | ((state[0+i] |
                state[8+i]) & state[16+i]))
        state[0+i] = circularLeft(tmp, p2) +
            tA[(pp8k512[isp + 5]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[0+i]
    }

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p2)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[48+i]) +
            ((state[0+i] & state[8+i]) | ((state[0+i] |
                state[8+i]) & state[16+i]))
        state[0+i] = circularLeft(tmp, p3) +
            tA[(pp8k512[isp + 6]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[0+i]
    }

    for i := 0; i < 8; i++ {
        tA[i] = circularLeft(state[i], p3)
    }

    for i := 0; i < 8; i++ {
        tmp = state[24+i] + (w[56+i]) +
            ((state[0+i] & state[8+i]) | ((state[0+i] |
                state[8+i]) & state[16+i]))
        state[0+i] = circularLeft(tmp, p0) +
            tA[(pp8k512[isp + 7]) ^ i]
        state[24+i] = state[16+i]
        state[16+i] = state[8+i]
        state[8+i] = tA[0+i]
    }
}

func (d *digest512) fft64(x []byte, xb, xs, qoff int) {
    q := &d.q

    var xd = xs << 1
    {
        var d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7 int32
        var d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7 int32
        {
            var x0 = int32(x[xb +  0 * xd] & 0xFF)
            var x1 = int32(x[xb +  4 * xd] & 0xFF)
            var x2 = int32(x[xb +  8 * xd] & 0xFF)
            var x3 = int32(x[xb + 12 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d1_0 = a0 + b0
            d1_1 = a1 + b1
            d1_2 = a2 + b2
            d1_3 = a3 + b3
            d1_4 = a0 - b0
            d1_5 = a1 - b1
            d1_6 = a2 - b2
            d1_7 = a3 - b3
        }
        {
            var x0 = int32(x[xb +  2 * xd] & 0xFF)
            var x1 = int32(x[xb +  6 * xd] & 0xFF)
            var x2 = int32(x[xb + 10 * xd] & 0xFF)
            var x3 = int32(x[xb + 14 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d2_0 = a0 + b0
            d2_1 = a1 + b1
            d2_2 = a2 + b2
            d2_3 = a3 + b3
            d2_4 = a0 - b0
            d2_5 = a1 - b1
            d2_6 = a2 - b2
            d2_7 = a3 - b3
        }

        q[qoff +  0] = d1_0 + d2_0
        q[qoff +  1] = d1_1 + (d2_1 << 1)
        q[qoff +  2] = d1_2 + (d2_2 << 2)
        q[qoff +  3] = d1_3 + (d2_3 << 3)
        q[qoff +  4] = d1_4 + (d2_4 << 4)
        q[qoff +  5] = d1_5 + (d2_5 << 5)
        q[qoff +  6] = d1_6 + (d2_6 << 6)
        q[qoff +  7] = d1_7 + (d2_7 << 7)
        q[qoff +  8] = d1_0 - d2_0
        q[qoff +  9] = d1_1 - (d2_1 << 1)
        q[qoff + 10] = d1_2 - (d2_2 << 2)
        q[qoff + 11] = d1_3 - (d2_3 << 3)
        q[qoff + 12] = d1_4 - (d2_4 << 4)
        q[qoff + 13] = d1_5 - (d2_5 << 5)
        q[qoff + 14] = d1_6 - (d2_6 << 6)
        q[qoff + 15] = d1_7 - (d2_7 << 7)
    }
    {
        var d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7 int32
        var d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7 int32
        {
            var x0 = int32(x[xb +  1 * xd] & 0xFF)
            var x1 = int32(x[xb +  5 * xd] & 0xFF)
            var x2 = int32(x[xb +  9 * xd] & 0xFF)
            var x3 = int32(x[xb + 13 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d1_0 = a0 + b0
            d1_1 = a1 + b1
            d1_2 = a2 + b2
            d1_3 = a3 + b3
            d1_4 = a0 - b0
            d1_5 = a1 - b1
            d1_6 = a2 - b2
            d1_7 = a3 - b3
        }
        {
            var x0 = int32(x[xb +  3 * xd] & 0xFF)
            var x1 = int32(x[xb +  7 * xd] & 0xFF)
            var x2 = int32(x[xb + 11 * xd] & 0xFF)
            var x3 = int32(x[xb + 15 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d2_0 = a0 + b0
            d2_1 = a1 + b1
            d2_2 = a2 + b2
            d2_3 = a3 + b3
            d2_4 = a0 - b0
            d2_5 = a1 - b1
            d2_6 = a2 - b2
            d2_7 = a3 - b3
        }

        q[qoff + 16 +  0] = d1_0 + d2_0
        q[qoff + 16 +  1] = d1_1 + (d2_1 << 1)
        q[qoff + 16 +  2] = d1_2 + (d2_2 << 2)
        q[qoff + 16 +  3] = d1_3 + (d2_3 << 3)
        q[qoff + 16 +  4] = d1_4 + (d2_4 << 4)
        q[qoff + 16 +  5] = d1_5 + (d2_5 << 5)
        q[qoff + 16 +  6] = d1_6 + (d2_6 << 6)
        q[qoff + 16 +  7] = d1_7 + (d2_7 << 7)
        q[qoff + 16 +  8] = d1_0 - d2_0
        q[qoff + 16 +  9] = d1_1 - (d2_1 << 1)
        q[qoff + 16 + 10] = d1_2 - (d2_2 << 2)
        q[qoff + 16 + 11] = d1_3 - (d2_3 << 3)
        q[qoff + 16 + 12] = d1_4 - (d2_4 << 4)
        q[qoff + 16 + 13] = d1_5 - (d2_5 << 5)
        q[qoff + 16 + 14] = d1_6 - (d2_6 << 6)
        q[qoff + 16 + 15] = d1_7 - (d2_7 << 7)
    }

    var m = q[qoff]
    var n = q[qoff + 16]

    q[qoff] = m + n
    q[qoff + 16] = m - n

    for u, v := 0, 0; u < 16; u, v = u + 4, v + 4 * 8 {
        var t int32
        if u != 0 {
            m = q[qoff + u + 0]
            n = q[qoff + u + 0 + 16]
            t = ((n * alphaTab512[v + 0 * 8]) & 0xFFFF) + ((n * alphaTab512[v + 0 * 8]) >> 16)
            q[qoff + u + 0] = m + t
            q[qoff + u + 0 + 16] = m - t
        }

        for j := 1; j < 4; j++ {
            m = q[qoff + u + j]
            n = q[qoff + u + j + 16]
            t = ((n * alphaTab512[v + j * 8]) & 0xFFFF) +
                ((n * alphaTab512[v + j * 8]) >> 16)
            q[qoff + u + j] = m + t
            q[qoff + u + j + 16] = m - t
        }
    }
    {
        var d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7 int32
        var d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7 int32
        {
            var x0 = int32(x[xb + xs +  0 * xd] & 0xFF)
            var x1 = int32(x[xb + xs +  4 * xd] & 0xFF)
            var x2 = int32(x[xb + xs +  8 * xd] & 0xFF)
            var x3 = int32(x[xb + xs + 12 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d1_0 = a0 + b0
            d1_1 = a1 + b1
            d1_2 = a2 + b2
            d1_3 = a3 + b3
            d1_4 = a0 - b0
            d1_5 = a1 - b1
            d1_6 = a2 - b2
            d1_7 = a3 - b3
        }
        {
            var x0 = int32(x[xb + xs +  2 * xd] & 0xFF)
            var x1 = int32(x[xb + xs +  6 * xd] & 0xFF)
            var x2 = int32(x[xb + xs + 10 * xd] & 0xFF)
            var x3 = int32(x[xb + xs + 14 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d2_0 = a0 + b0
            d2_1 = a1 + b1
            d2_2 = a2 + b2
            d2_3 = a3 + b3
            d2_4 = a0 - b0
            d2_5 = a1 - b1
            d2_6 = a2 - b2
            d2_7 = a3 - b3
        }

        q[qoff + 32 +  0] = d1_0 + d2_0
        q[qoff + 32 +  1] = d1_1 + (d2_1 << 1)
        q[qoff + 32 +  2] = d1_2 + (d2_2 << 2)
        q[qoff + 32 +  3] = d1_3 + (d2_3 << 3)
        q[qoff + 32 +  4] = d1_4 + (d2_4 << 4)
        q[qoff + 32 +  5] = d1_5 + (d2_5 << 5)
        q[qoff + 32 +  6] = d1_6 + (d2_6 << 6)
        q[qoff + 32 +  7] = d1_7 + (d2_7 << 7)
        q[qoff + 32 +  8] = d1_0 - d2_0
        q[qoff + 32 +  9] = d1_1 - (d2_1 << 1)
        q[qoff + 32 + 10] = d1_2 - (d2_2 << 2)
        q[qoff + 32 + 11] = d1_3 - (d2_3 << 3)
        q[qoff + 32 + 12] = d1_4 - (d2_4 << 4)
        q[qoff + 32 + 13] = d1_5 - (d2_5 << 5)
        q[qoff + 32 + 14] = d1_6 - (d2_6 << 6)
        q[qoff + 32 + 15] = d1_7 - (d2_7 << 7)
    }
    {
        var d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7 int32
        var d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7 int32
        {
            var x0 = int32(x[xb + xs +  1 * xd] & 0xFF)
            var x1 = int32(x[xb + xs +  5 * xd] & 0xFF)
            var x2 = int32(x[xb + xs +  9 * xd] & 0xFF)
            var x3 = int32(x[xb + xs + 13 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d1_0 = a0 + b0
            d1_1 = a1 + b1
            d1_2 = a2 + b2
            d1_3 = a3 + b3
            d1_4 = a0 - b0
            d1_5 = a1 - b1
            d1_6 = a2 - b2
            d1_7 = a3 - b3
        }
        {
            var x0 = int32(x[xb + xs +  3 * xd] & 0xFF)
            var x1 = int32(x[xb + xs +  7 * xd] & 0xFF)
            var x2 = int32(x[xb + xs + 11 * xd] & 0xFF)
            var x3 = int32(x[xb + xs + 15 * xd] & 0xFF)

            var a0 = x0 + x2
            var a1 = x0 + (x2 << 4)
            var a2 = x0 - x2
            var a3 = x0 - (x2 << 4)
            var b0 = x1 + x3
            var b1 = REDS1((x1 << 2) + (x3 << 6))
            var b2 = (x1 << 4) - (x3 << 4)
            var b3 = REDS1((x1 << 6) + (x3 << 2))

            d2_0 = a0 + b0
            d2_1 = a1 + b1
            d2_2 = a2 + b2
            d2_3 = a3 + b3
            d2_4 = a0 - b0
            d2_5 = a1 - b1
            d2_6 = a2 - b2
            d2_7 = a3 - b3
        }

        q[qoff + 32 + 16 +  0] = d1_0 + d2_0
        q[qoff + 32 + 16 +  1] = d1_1 + (d2_1 << 1)
        q[qoff + 32 + 16 +  2] = d1_2 + (d2_2 << 2)
        q[qoff + 32 + 16 +  3] = d1_3 + (d2_3 << 3)
        q[qoff + 32 + 16 +  4] = d1_4 + (d2_4 << 4)
        q[qoff + 32 + 16 +  5] = d1_5 + (d2_5 << 5)
        q[qoff + 32 + 16 +  6] = d1_6 + (d2_6 << 6)
        q[qoff + 32 + 16 +  7] = d1_7 + (d2_7 << 7)
        q[qoff + 32 + 16 +  8] = d1_0 - d2_0
        q[qoff + 32 + 16 +  9] = d1_1 - (d2_1 << 1)
        q[qoff + 32 + 16 + 10] = d1_2 - (d2_2 << 2)
        q[qoff + 32 + 16 + 11] = d1_3 - (d2_3 << 3)
        q[qoff + 32 + 16 + 12] = d1_4 - (d2_4 << 4)
        q[qoff + 32 + 16 + 13] = d1_5 - (d2_5 << 5)
        q[qoff + 32 + 16 + 14] = d1_6 - (d2_6 << 6)
        q[qoff + 32 + 16 + 15] = d1_7 - (d2_7 << 7)
    }

    m = q[qoff + 32]
    n = q[qoff + 32 + 16]
    q[qoff + 32] = m + n
    q[qoff + 32 + 16] = m - n

    for u, v := 0, 0; u < 16; u, v = u + 4, v + 4 * 8 {
        var t int32
        if u != 0 {
            m = q[(qoff + 32) + u + 0]
            n = q[(qoff + 32) + u + 0 + 16]
            t = ((n * alphaTab512[v + 0 * 8]) & 0xFFFF) + ((n * alphaTab512[v + 0 * 8]) >> 16)
            q[(qoff + 32) + u + 0] = m + t
            q[(qoff + 32) + u + 0 + 16] = m - t
        }

        for j := 1; j < 4; j++ {
            m = q[(qoff + 32) + u + j]
            n = q[(qoff + 32) + u + j + 16]
            t = ((n * alphaTab512[v + j * 8]) & 0xFFFF) +
                ((n * alphaTab512[v + j * 8]) >> 16)
            q[(qoff + 32) + u + j] = m + t
            q[(qoff + 32) + u + j + 16] = m - t
        }
    }

    m = q[qoff]
    n = q[qoff + 32]
    q[qoff] = m + n
    q[qoff + 32] = m - n

    for u, v := 0, 0; u < 32; u, v = u + 4, v + 4 * 4 {
        var t int32
        if u != 0 {
            m = q[qoff + u + 0]
            n = q[qoff + u + 0 + 32]
            t = ((n * alphaTab512[v + 0 * 4]) & 0xFFFF) + ((n * alphaTab512[v + 0 * 4]) >> 16)
            q[qoff + u + 0] = m + t
            q[qoff + u + 0 + 32] = m - t
        }

        for j := 1; j < 4; j++ {
            m = q[qoff + u + j]
            n = q[qoff + u + j + 32]
            t = ((n * alphaTab512[v + j * 4]) & 0xFFFF) +
                ((n * alphaTab512[v + j * 4]) >> 16)
            q[qoff + u + j] = m + t
            q[qoff + u + j + 32] = m - t
        }
    }
}
