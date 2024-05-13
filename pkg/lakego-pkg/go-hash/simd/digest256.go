package simd

const (
    // hash size
    Size224 = 28
    Size256 = 32

    BlockSize256 = 64
)

// digest256 represents the partial evaluation of a checksum.
type digest256 struct {
    s   [16]uint32
    x   [BlockSize256]byte
    nx  int
    len uint64

    state    [16]uint32
    q        [128]int32
    w        [32]uint32
    tmpState [16]uint32
    tA       [4]uint32

    hs      int
    initVal [16]uint32
}

// newDigest256 returns a new hash.Hash computing the checksum
func newDigest256(hs int, initVal [16]uint32) *digest256 {
    d := new(digest256)
    d.hs = hs
    d.initVal = initVal
    d.Reset()

    return d
}

func (d *digest256) Reset() {
    d.s = d.initVal
    d.x = [BlockSize256]byte{}

    d.nx = 0
    d.len = 0

    d.state = d.initVal
    d.q = [128]int32{}
    d.w = [32]uint32{}
    d.tmpState = [16]uint32{}
    d.tA = [4]uint32{}
}

func (d *digest256) Size() int {
    return d.hs
}

func (d *digest256) BlockSize() int {
    return BlockSize256
}

func (d *digest256) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)
    for d.nx + plen >= BlockSize256 {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        xx := BlockSize256 - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest256) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest256) checkSum() (out []byte) {
    ptr := d.nx

    var buf = d.x
    if ptr != 0 {
        for i := ptr; i < 64; i++ {
            buf[i] = 0x00
        }
        d.compress(buf[:], false)
    }

    var count = ((d.len / BlockSize256) << 9) + (uint64(ptr) << 3)

    putu32(buf[0:], uint32(count))
    putu32(buf[4:], uint32(count >> 32))

    for i := 8; i < 64; i++ {
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

func (d *digest256) processBlock(data []byte) {
    d.compress(data, false)
}

func (d *digest256) compress(x []byte, last bool) {
    w := &d.w
    q := &d.q
    state := &d.state
    tmpState := &d.tmpState

    d.fft32(x, 0 + (1 * 0), 1 << 2, 0 + 0)
    d.fft32(x, 0 + (1 * 2), 1 << 2, 0 + 32)

    var m = q[0]
    var n = q[0 + 32]

    q[0] = m + n
    q[0 + 32] = m - n

    for u, v := 0, 0; u < 32; u, v = u + 4, v + 4 * 4 {
        var t int32
        if u != 0 {
            m = q[0 + u + 0]
            n = q[0 + u + 0 + 32]
            t = (((n * alphaTab256[v + 0 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 0 * 4]) >> 16))
            q[0 + u + 0] = m + t
            q[0 + u + 0 + 32] = m - t
        }

        m = q[0 + u + 1]
        n = q[0 + u + 1 + 32]
        t = (((n * alphaTab256[v + 1 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 1 * 4]) >> 16))
        q[0 + u + 1] = m + t
        q[0 + u + 1 + 32] = m - t

        m = q[0 + u + 2]
        n = q[0 + u + 2 + 32]
        t = (((n * alphaTab256[v + 2 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 2 * 4]) >> 16))
        q[0 + u + 2] = m + t
        q[0 + u + 2 + 32] = m - t

        m = q[0 + u + 3]
        n = q[0 + u + 3 + 32]
        t = (((n * alphaTab256[v + 3 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 3 * 4]) >> 16))
        q[0 + u + 3] = m + t
        q[0 + u + 3 + 32] = m - t
    }

    d.fft32(x, 0 + (1 * 1), 1 << 2, 0 + 64)
    d.fft32(x, 0 + (1 * 3), 1 << 2, 0 + 96)

    m = q[(0 + 64)]
    n = q[(0 + 64) + 32]

    q[(0 + 64)] = m + n
    q[(0 + 64) + 32] = m - n

    for u, v := 0, 0; u < 32; u, v = u + 4, v + 4 * 4 {
        var t int32
        if u != 0 {
            m = q[(0 + 64) + u + 0]
            n = q[(0 + 64) + u + 0 + 32]
            t = (((n * alphaTab256[v + 0 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 0 * 4]) >> 16))
            q[(0 + 64) + u + 0] = m + t
            q[(0 + 64) + u + 0 + 32] = m - t
        }

        m = q[(0 + 64) + u + 1]
        n = q[(0 + 64) + u + 1 + 32]
        t = (((n * alphaTab256[v + 1 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 1 * 4]) >> 16))
        q[(0 + 64) + u + 1] = m + t
        q[(0 + 64) + u + 1 + 32] = m - t

        m = q[(0 + 64) + u + 2]
        n = q[(0 + 64) + u + 2 + 32]
        t = (((n * alphaTab256[v + 2 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 2 * 4]) >> 16))
        q[(0 + 64) + u + 2] = m + t
        q[(0 + 64) + u + 2 + 32] = m - t

        m = q[(0 + 64) + u + 3]
        n = q[(0 + 64) + u + 3 + 32]
        t = (((n * alphaTab256[v + 3 * 4]) & 0xFFFF) + ((n * alphaTab256[v + 3 * 4]) >> 16))
        q[(0 + 64) + u + 3] = m + t
        q[(0 + 64) + u + 3 + 32] = m - t
    }

    m = q[0]
    n = q[0 + 64]
    q[0] = m + n
    q[0 + 64] = m - n

    for u, v := 0, 0; u < 64; u, v = u + 4, v + 4 * 2 {
        var t int32
        if u != 0 {
            m = q[0 + u + 0]
            n = q[0 + u + 0 + 64]
            t = (((n * alphaTab256[v + 0 * 2]) & 0xFFFF) + ((n * alphaTab256[v + 0 * 2]) >> 16))
            q[0 + u + 0] = m + t
            q[0 + u + 0 + 64] = m - t
        }

        m = q[0 + u + 1]
        n = q[0 + u + 1 + 64]
        t = (((n * alphaTab256[v + 1 * 2]) & 0xFFFF) + ((n * alphaTab256[v + 1 * 2]) >> 16))
        q[0 + u + 1] = m + t
        q[0 + u + 1 + 64] = m - t

        m = q[0 + u + 2]
        n = q[0 + u + 2 + 64]
        t = (((n * alphaTab256[v + 2 * 2]) & 0xFFFF) + ((n * alphaTab256[v + 2 * 2]) >> 16))
        q[0 + u + 2] = m + t
        q[0 + u + 2 + 64] = m - t

        m = q[0 + u + 3]
        n = q[0 + u + 3 + 64]
        t = (((n * alphaTab256[v + 3 * 2]) & 0xFFFF) + ((n * alphaTab256[v + 3 * 2]) >> 16))
        q[0 + u + 3] = m + t
        q[0 + u + 3 + 64] = m - t
    }

    if last {
        for i := 0; i < 128; i++ {
            var tq = q[i] + yoffF256[i]
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
        for i := 0; i < 128; i++ {
            var tq = q[i] + yoffN256[i]
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

    for i := 0; i < 16; i += 4 {
        state[i + 0] ^= getu32(x[4 * (i + 0):])
        state[i + 1] ^= getu32(x[4 * (i + 1):])
        state[i + 2] ^= getu32(x[4 * (i + 2):])
        state[i + 3] ^= getu32(x[4 * (i + 3):])
    }

    for u := 0; u < 32; u += 4 {
        var v = wsp256[(u >> 2) + 0]
        w[u + 0] = ((uint32((q[v + 2 * 0 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 0 + 1]) * 185) << 16))
        w[u + 1] = ((uint32((q[v + 2 * 1 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 1 + 1]) * 185) << 16))
        w[u + 2] = ((uint32((q[v + 2 * 2 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 2 + 1]) * 185) << 16))
        w[u + 3] = ((uint32((q[v + 2 * 3 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 3 + 1]) * 185) << 16))
    }
    d.oneRound(0, 3, 23, 17, 27)

    for u := 0; u < 32; u += 4 {
        var v = wsp256[(u >> 2) + 8]
        w[u + 0] = ((uint32((q[v + 2 * 0 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 0 + 1]) * 185) << 16))
        w[u + 1] = ((uint32((q[v + 2 * 1 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 1 + 1]) * 185) << 16))
        w[u + 2] = ((uint32((q[v + 2 * 2 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 2 + 1]) * 185) << 16))
        w[u + 3] = ((uint32((q[v + 2 * 3 + 0]) * 185) & 0xFFFF) + (uint32((q[v + 2 * 3 + 1]) * 185) << 16))
    }
    d.oneRound(2, 28, 19, 22, 7)

    for u := 0; u < 32; u += 4 {
        var v = wsp256[(u >> 2) + 16]
        w[u + 0] = ((uint32((q[v + 2 * 0 + -128]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 0 + -64]) * 233) << 16))
        w[u + 1] = ((uint32((q[v + 2 * 1 + -128]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 1 + -64]) * 233) << 16))
        w[u + 2] = ((uint32((q[v + 2 * 2 + -128]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 2 + -64]) * 233) << 16))
        w[u + 3] = ((uint32((q[v + 2 * 3 + -128]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 3 + -64]) * 233) << 16))
    }
    d.oneRound(1, 29, 9, 15, 5)

    for u := 0; u < 32; u += 4 {
        var v = wsp256[(u >> 2) + 24]
        w[u + 0] = ((uint32((q[v + 2 * 0 + -191]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 0 + -127]) * 233) << 16))
        w[u + 1] = ((uint32((q[v + 2 * 1 + -191]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 1 + -127]) * 233) << 16))
        w[u + 2] = ((uint32((q[v + 2 * 2 + -191]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 2 + -127]) * 233) << 16))
        w[u + 3] = ((uint32((q[v + 2 * 3 + -191]) * 233) & 0xFFFF) + (uint32((q[v + 2 * 3 + -127]) * 233) << 16))
    }
    d.oneRound(0, 4, 13, 10, 25)

    {
        var tA0 = circularLeft(state[0], 4)
        var tA1 = circularLeft(state[1], 4)
        var tA2 = circularLeft(state[2], 4)
        var tA3 = circularLeft(state[3], 4)
        var tmp uint32

        tmp = state[12] + (tmpState[0]) + (((state[4] ^ state[8]) & state[0]) ^ state[8])
        state[0] = circularLeft(tmp, 13) + tA3
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA0

        tmp = state[13] + (tmpState[1]) + (((state[5] ^ state[9]) & state[1]) ^ state[9])
        state[1] = circularLeft(tmp, 13) + tA2
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA1

        tmp = state[14] + (tmpState[2]) + (((state[6] ^ state[10]) & state[2]) ^ state[10])
        state[2] = circularLeft(tmp, 13) + tA1
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA2

        tmp = state[15] + (tmpState[3]) + (((state[7] ^ state[11]) & state[3]) ^ state[11])
        state[3] = circularLeft(tmp, 13) + tA0
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA3
    }
    {
        var tA0 = circularLeft(state[0], 13)
        var tA1 = circularLeft(state[1], 13)
        var tA2 = circularLeft(state[2], 13)
        var tA3 = circularLeft(state[3], 13)
        var tmp uint32

        tmp = state[12] + (tmpState[4]) + (((state[4] ^ state[8]) & state[0]) ^ state[8])
        state[0] = circularLeft(tmp, 10) + tA1
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA0

        tmp = state[13] + (tmpState[5]) + (((state[5] ^ state[9]) & state[1]) ^ state[9])
        state[1] = circularLeft(tmp, 10) + tA0
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA1

        tmp = state[14] + (tmpState[6]) + (((state[6] ^ state[10]) & state[2]) ^ state[10])
        state[2] = circularLeft(tmp, 10) + tA3
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA2

        tmp = state[15] + (tmpState[7]) + (((state[7] ^ state[11]) & state[3]) ^ state[11])
        state[3] = circularLeft(tmp, 10) + tA2
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA3
    }
    {
        var tA0 = circularLeft(state[0], 10)
        var tA1 = circularLeft(state[1], 10)
        var tA2 = circularLeft(state[2], 10)
        var tA3 = circularLeft(state[3], 10)
        var tmp uint32

        tmp = state[12] + (tmpState[8]) + (((state[4] ^ state[8]) & state[0]) ^ state[8])
        state[0] = circularLeft(tmp, 25) + tA2
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA0

        tmp = state[13] + (tmpState[9]) + (((state[5] ^ state[9]) & state[1]) ^ state[9])
        state[1] = circularLeft(tmp, 25) + tA3
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA1

        tmp = state[14] + (tmpState[10]) + (((state[6] ^ state[10]) & state[2]) ^ state[10])
        state[2] = circularLeft(tmp, 25) + tA0
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA2

        tmp = state[15] + (tmpState[11]) + (((state[7] ^ state[11]) & state[3]) ^ state[11])
        state[3] = circularLeft(tmp, 25) + tA1
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA3
    }
    {
        var tA0 = circularLeft(state[0], 25)
        var tA1 = circularLeft(state[1], 25)
        var tA2 = circularLeft(state[2], 25)
        var tA3 = circularLeft(state[3], 25)
        var tmp uint32

        tmp = state[12] + (tmpState[12]) + (((state[4] ^ state[8]) & state[0]) ^ state[8])
        state[0] = circularLeft(tmp, 4) + tA3
        state[12] = state[8]
        state[8] = state[4]
        state[4] = tA0

        tmp = state[13] + (tmpState[13]) + (((state[5] ^ state[9]) & state[1]) ^ state[9])
        state[1] = circularLeft(tmp, 4) + tA2
        state[13] = state[9]
        state[9] = state[5]
        state[5] = tA1

        tmp = state[14] + (tmpState[14]) + (((state[6] ^ state[10]) & state[2]) ^ state[10])
        state[2] = circularLeft(tmp, 4) + tA1
        state[14] = state[10]
        state[10] = state[6]
        state[6] = tA2

        tmp = state[15] + (tmpState[15]) + (((state[7] ^ state[11]) & state[3]) ^ state[11])
        state[3] = circularLeft(tmp, 4) + tA0
        state[15] = state[11]
        state[11] = state[7]
        state[7] = tA3
    }
}

func (d *digest256) oneRound(isp, p0, p1, p2, p3 int) {
    state := &d.state
    w := &d.w
    tA := &d.tA

    var tmp uint32

    tA[0] = circularLeft(state[0], p0)
    tA[1] = circularLeft(state[1], p0)
    tA[2] = circularLeft(state[2], p0)
    tA[3] = circularLeft(state[3], p0)

    tmp = state[12] + w[0] + (((state[4] ^ state[8]) & state[0]) ^ state[8])
    state[0] = circularLeft(tmp, p1) + tA[pp4k256[isp + 0] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[1] + (((state[5] ^ state[9]) & state[1]) ^ state[9])
    state[1] = circularLeft(tmp, p1) + tA[pp4k256[isp + 0] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[2] + (((state[6] ^ state[10]) & state[2]) ^ state[10])
    state[2] = circularLeft(tmp, p1) + tA[pp4k256[isp + 0] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[3] + (((state[7] ^ state[11]) & state[3]) ^ state[11])
    state[3] = circularLeft(tmp, p1) + tA[pp4k256[isp + 0] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]

    tA[0] = circularLeft(state[0], p1)
    tA[1] = circularLeft(state[1], p1)
    tA[2] = circularLeft(state[2], p1)
    tA[3] = circularLeft(state[3], p1)

    tmp = state[12] + w[4] + (((state[4] ^ state[8]) & state[0]) ^ state[8])
    state[0] = circularLeft(tmp, p2) + tA[pp4k256[isp + 1] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[5] + (((state[5] ^ state[9]) & state[1]) ^ state[9])
    state[1] = circularLeft(tmp, p2) + tA[pp4k256[isp + 1] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[6] + (((state[6] ^ state[10]) & state[2]) ^ state[10])
    state[2] = circularLeft(tmp, p2) + tA[pp4k256[isp + 1] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[7] + (((state[7] ^ state[11]) & state[3]) ^ state[11])
    state[3] = circularLeft(tmp, p2) + tA[pp4k256[isp + 1] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]

    tA[0] = circularLeft(state[0], p2)
    tA[1] = circularLeft(state[1], p2)
    tA[2] = circularLeft(state[2], p2)
    tA[3] = circularLeft(state[3], p2)

    tmp = state[12] + w[8] + (((state[4] ^ state[8]) & state[0]) ^ state[8])
    state[0] = circularLeft(tmp, p3) + tA[pp4k256[isp + 2] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[9] + (((state[5] ^ state[9]) & state[1]) ^ state[9])
    state[1] = circularLeft(tmp, p3) + tA[pp4k256[isp + 2] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[10] + (((state[6] ^ state[10]) & state[2]) ^ state[10])
    state[2] = circularLeft(tmp, p3) + tA[pp4k256[isp + 2] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[11] + (((state[7] ^ state[11]) & state[3]) ^ state[11])
    state[3] = circularLeft(tmp, p3) + tA[pp4k256[isp + 2] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]

    tA[0] = circularLeft(state[0], p3)
    tA[1] = circularLeft(state[1], p3)
    tA[2] = circularLeft(state[2], p3)
    tA[3] = circularLeft(state[3], p3)

    tmp = state[12] + w[12] + (((state[4] ^ state[8]) & state[0]) ^ state[8])
    state[0] = circularLeft(tmp, p0) + tA[pp4k256[isp + 3] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[13] + (((state[5] ^ state[9]) & state[1]) ^ state[9])
    state[1] = circularLeft(tmp, p0) + tA[pp4k256[isp + 3] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[14] + (((state[6] ^ state[10]) & state[2]) ^ state[10])
    state[2] = circularLeft(tmp, p0) + tA[pp4k256[isp + 3] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[15] + (((state[7] ^ state[11]) & state[3]) ^ state[11])
    state[3] = circularLeft(tmp, p0) + tA[pp4k256[isp + 3] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]

    tA[0] = circularLeft(state[0], p0)
    tA[1] = circularLeft(state[1], p0)
    tA[2] = circularLeft(state[2], p0)
    tA[3] = circularLeft(state[3], p0)

    tmp = state[12] + w[16] + ((state[0] & state[4]) | ((state[0] | state[4]) & state[8]))
    state[0] = circularLeft(tmp, p1) + tA[pp4k256[isp + 4] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[17] + ((state[1] & state[5]) | ((state[1] | state[5]) & state[9]))
    state[1] = circularLeft(tmp, p1) + tA[pp4k256[isp + 4] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[18] + ((state[2] & state[6]) | ((state[2] | state[6]) & state[10]))
    state[2] = circularLeft(tmp, p1) + tA[pp4k256[isp + 4] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[19] + ((state[3] & state[7]) | ((state[3] | state[7]) & state[11]))
    state[3] = circularLeft(tmp, p1) + tA[pp4k256[isp + 4] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]

    tA[0] = circularLeft(state[0], p1)
    tA[1] = circularLeft(state[1], p1)
    tA[2] = circularLeft(state[2], p1)
    tA[3] = circularLeft(state[3], p1)

    tmp = state[12] + w[20] + ((state[0] & state[4]) | ((state[0] | state[4]) & state[8]))
    state[0] = circularLeft(tmp, p2) + tA[pp4k256[isp + 5] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[21] + ((state[1] & state[5]) | ((state[1] | state[5]) & state[9]))
    state[1] = circularLeft(tmp, p2) + tA[pp4k256[isp + 5] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[22] + ((state[2] & state[6]) | ((state[2] | state[6]) & state[10]))
    state[2] = circularLeft(tmp, p2) + tA[pp4k256[isp + 5] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[23] + ((state[3] & state[7]) | ((state[3] | state[7]) & state[11]))
    state[3] = circularLeft(tmp, p2) + tA[pp4k256[isp + 5] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]

    tA[0] = circularLeft(state[0], p2)
    tA[1] = circularLeft(state[1], p2)
    tA[2] = circularLeft(state[2], p2)
    tA[3] = circularLeft(state[3], p2)

    tmp = state[12] + w[24] + ((state[0] & state[4]) | ((state[0] | state[4]) & state[8]))
    state[0] = circularLeft(tmp, p3) + tA[pp4k256[isp + 6] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[25] + ((state[1] & state[5]) | ((state[1] | state[5]) & state[9]))
    state[1] = circularLeft(tmp, p3) + tA[pp4k256[isp + 6] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[26] + ((state[2] & state[6]) | ((state[2] | state[6]) & state[10]))
    state[2] = circularLeft(tmp, p3) + tA[pp4k256[isp + 6] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[27] + ((state[3] & state[7]) | ((state[3] | state[7]) & state[11]))
    state[3] = circularLeft(tmp, p3) + tA[pp4k256[isp + 6] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]

    tA[0] = circularLeft(state[0], p3)
    tA[1] = circularLeft(state[1], p3)
    tA[2] = circularLeft(state[2], p3)
    tA[3] = circularLeft(state[3], p3)

    tmp = state[12] + w[28] + ((state[0] & state[4]) | ((state[0] | state[4]) & state[8]))
    state[0] = circularLeft(tmp, p0) + tA[pp4k256[isp + 7] ^ 0]
    state[12] = state[8]
    state[8] = state[4]
    state[4] = tA[0]

    tmp = state[13] + w[29] + ((state[1] & state[5]) | ((state[1] | state[5]) & state[9]))
    state[1] = circularLeft(tmp, p0) + tA[pp4k256[isp + 7] ^ 1]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = tA[1]

    tmp = state[14] + w[30] + ((state[2] & state[6]) | ((state[2] | state[6]) & state[10]))
    state[2] = circularLeft(tmp, p0) + tA[pp4k256[isp + 7] ^ 2]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = tA[2]

    tmp = state[15] + w[31] + ((state[3] & state[7]) | ((state[3] | state[7]) & state[11]))
    state[3] = circularLeft(tmp, p0) + tA[pp4k256[isp + 7] ^ 3]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tA[3]
}

func (d *digest256) fft32(x []byte, xb, xs, qoff int) {
    q := &d.q

    var xd = xs << 1
    {
        var d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7 int32
        var d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7 int32
        {
            var x0 = int32(x[xb] & 0xFF)
            var x1 = int32(x[xb + 2 * xd] & 0xFF)
            var x2 = int32(x[xb + 4 * xd] & 0xFF)
            var x3 = int32(x[xb + 6 * xd] & 0xFF)

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
            var x0 = int32(x[xb + xd] & 0xFF)
            var x1 = int32(x[xb + 3 * xd] & 0xFF)
            var x2 = int32(x[xb + 5 * xd] & 0xFF)
            var x3 = int32(x[xb + 7 * xd] & 0xFF)

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
            var x0 = int32(x[xb + xs] & 0xFF)
            var x1 = int32(x[xb + xs + 2 * xd] & 0xFF)
            var x2 = int32(x[xb + xs + 4 * xd] & 0xFF)
            var x3 = int32(x[xb + xs + 6 * xd] & 0xFF)

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
            var x0 = int32(x[xb + xs + xd] & 0xFF)
            var x1 = int32(x[xb + xs + 3 * xd] & 0xFF)
            var x2 = int32(x[xb + xs + 5 * xd] & 0xFF)
            var x3 = int32(x[xb + xs + 7 * xd] & 0xFF)

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
            t = ((n * alphaTab256[v + 0 * 8]) & 0xFFFF) + ((n * alphaTab256[v + 0 * 8]) >> 16)
            q[qoff + u + 0] = m + t
            q[qoff + u + 0 + 16] = m - t
        }

        for j := 1; j < 4; j++ {
            m = q[qoff + u + j]
            n = q[qoff + u + j + 16]
            t = (((n * alphaTab256[v + j * (8)]) & 0xFFFF) +
                ((n * alphaTab256[v + j * (8)]) >> 16))
            q[qoff + u + j] = m + t
            q[qoff + u + j + 16] = m - t
        }
    }
}
