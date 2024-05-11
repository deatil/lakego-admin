package bmw

const (
    // hash size
    Size384 = 48
    Size512 = 64

    BlockSize512 = 128
)

// digest512 represents the partial evaluation of a checksum.
type digest512 struct {
    s   [16]uint64
    x   [BlockSize512]byte
    nx  int
    len uint64

    h2 [16]uint64
    q  [32]uint64
    w  [16]uint64

    initVal [16]uint64
    hs int
}

// newDigest512 returns a new *digest512 computing the bmw checksum
func newDigest512(initVal []uint64, hs int) *digest512 {
    d := new(digest512)
    copy(d.initVal[:], initVal)
    d.hs = hs
    d.Reset()

    return d
}

func (d *digest512) Reset() {
    // m
    d.x = [BlockSize512]byte{}

    // h
    d.s = [16]uint64{}

    d.nx = 0
    d.len = 0

    d.h2 = [16]uint64{}
    d.q = [32]uint64{}

    copy(d.s[:], d.initVal[:])
}

func (d *digest512) Size() int {
    return d.hs
}

func (d *digest512) BlockSize() int {
    return BlockSize512
}

func (d *digest512) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize512
    for d.nx + plen >= limit {
        xx := limit - d.nx

        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        plen -= xx
        d.len += uint64(xx) * 8

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen
    d.len += uint64(plen) * 8

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

    var limit = BlockSize512

    zeros := make([]byte, limit)

    if d.nx > limit - 8 {
        copy(d.x[d.nx:], zeros)
        d.processBlock(d.x[:])
        d.nx = 0
    }

    copy(d.x[d.nx:], zeros)

    putu64(d.x[limit - 8:], d.len)
    d.processBlock(d.x[:])

    d.s, d.h2 = d.h2, d.s
    copy(d.s[:], final512)

    d.compress(d.h2[:])

    outLen := d.hs >> 3
    ss := uint64sToBytes(d.s[16 - outLen:])

    return ss
}

func (d *digest512) processBlock(mm []byte) {
    m := bytesToUint64s(mm)
    d.compress(m)
}

func (d *digest512) compress(m []uint64) {
    h := &d.s
    q := &d.q
    w := &d.w

    w[0] = (m[5] ^ h[5]) - (m[7] ^ h[7]) + (m[10] ^ h[10]) + (m[13] ^ h[13]) + (m[14] ^ h[14])
    w[1] = (m[6] ^ h[6]) - (m[8] ^ h[8]) + (m[11] ^ h[11]) + (m[14] ^ h[14]) - (m[15] ^ h[15])
    w[2] = (m[0] ^ h[0]) + (m[7] ^ h[7]) + (m[9] ^ h[9]) - (m[12] ^ h[12]) + (m[15] ^ h[15])
    w[3] = (m[0] ^ h[0]) - (m[1] ^ h[1]) + (m[8] ^ h[8]) - (m[10] ^ h[10]) + (m[13] ^ h[13])
    w[4] = (m[1] ^ h[1]) + (m[2] ^ h[2]) + (m[9] ^ h[9]) - (m[11] ^ h[11]) - (m[14] ^ h[14])
    w[5] = (m[3] ^ h[3]) - (m[2] ^ h[2]) + (m[10] ^ h[10]) - (m[12] ^ h[12]) + (m[15] ^ h[15])
    w[6] = (m[4] ^ h[4]) - (m[0] ^ h[0]) - (m[3] ^ h[3]) - (m[11] ^ h[11]) + (m[13] ^ h[13])
    w[7] = (m[1] ^ h[1]) - (m[4] ^ h[4]) - (m[5] ^ h[5]) - (m[12] ^ h[12]) - (m[14] ^ h[14])
    w[8] = (m[2] ^ h[2]) - (m[5] ^ h[5]) - (m[6] ^ h[6]) + (m[13] ^ h[13]) - (m[15] ^ h[15])
    w[9] = (m[0] ^ h[0]) - (m[3] ^ h[3]) + (m[6] ^ h[6]) - (m[7] ^ h[7]) + (m[14] ^ h[14])
    w[10] = (m[8] ^ h[8]) - (m[1] ^ h[1]) - (m[4] ^ h[4]) - (m[7] ^ h[7]) + (m[15] ^ h[15])
    w[11] = (m[8] ^ h[8]) - (m[0] ^ h[0]) - (m[2] ^ h[2]) - (m[5] ^ h[5]) + (m[9] ^ h[9])
    w[12] = (m[1] ^ h[1]) + (m[3] ^ h[3]) - (m[6] ^ h[6]) - (m[9] ^ h[9]) + (m[10] ^ h[10])
    w[13] = (m[2] ^ h[2]) + (m[4] ^ h[4]) + (m[7] ^ h[7]) + (m[10] ^ h[10]) + (m[11] ^ h[11])
    w[14] = (m[3] ^ h[3]) - (m[5] ^ h[5]) + (m[8] ^ h[8]) - (m[11] ^ h[11]) - (m[12] ^ h[12])
    w[15] = (m[12] ^ h[12]) - (m[4] ^ h[4]) - (m[6] ^ h[6]) - (m[9] ^ h[9]) + (m[13] ^ h[13])

    for u := 0; u < 15; u += 5 {
        q[u + 0] = ((w[u + 0] >> 1) ^ (w[u + 0] << 3) ^ circularLeft64(w[u + 0], 4) ^ circularLeft64(w[u + 0], 37)) + h[u + 1]
        q[u + 1] = ((w[u + 1] >> 1) ^ (w[u + 1] << 2) ^ circularLeft64(w[u + 1], 13) ^ circularLeft64(w[u + 1], 43)) + h[u + 2]
        q[u + 2] = ((w[u + 2] >> 2) ^ (w[u + 2] << 1) ^ circularLeft64(w[u + 2], 19) ^ circularLeft64(w[u + 2], 53)) + h[u + 3]
        q[u + 3] = ((w[u + 3] >> 2) ^ (w[u + 3] << 2) ^ circularLeft64(w[u + 3], 28) ^ circularLeft64(w[u + 3], 59)) + h[u + 4]
        q[u + 4] = ((w[u + 4] >> 1) ^ w[u + 4]) + h[u + 5]
    }

    q[15] = ((w[15] >> 1) ^ (w[15] << 3) ^
        circularLeft64(w[15], 4) ^ circularLeft64(w[15], 37)) +
        h[0]

    for u := 16; u < 18; u++ {
        q[u] = ((q[u - 16] >> 1) ^ (q[u - 16] << 2) ^
            circularLeft64(q[u - 16], 13) ^
            circularLeft64(q[u - 16], 43)) +
            ((q[u - 15] >> 2) ^ (q[u - 15] << 1) ^
            circularLeft64(q[u - 15], 19) ^
            circularLeft64(q[u - 15], 53)) +
            ((q[u - 14] >> 2) ^ (q[u - 14] << 2) ^
            circularLeft64(q[u - 14], 28) ^
            circularLeft64(q[u - 14], 59)) +
            ((q[u - 13] >> 1) ^ (q[u - 13] << 3) ^
            circularLeft64(q[u - 13], 4) ^
            circularLeft64(q[u - 13], 37)) +
            ((q[u - 12] >> 1) ^ (q[u - 12] << 2) ^
            circularLeft64(q[u - 12], 13) ^
            circularLeft64(q[u - 12], 43)) +
            ((q[u - 11] >> 2) ^ (q[u - 11] << 1) ^
            circularLeft64(q[u - 11], 19) ^
            circularLeft64(q[u - 11], 53)) +
            ((q[u - 10] >> 2) ^ (q[u - 10] << 2) ^
            circularLeft64(q[u - 10], 28) ^
            circularLeft64(q[u - 10], 59)) +
            ((q[u - 9] >> 1) ^ (q[u - 9] << 3) ^
            circularLeft64(q[u - 9], 4) ^
            circularLeft64(q[u - 9], 37)) +
            ((q[u - 8] >> 1) ^ (q[u - 8] << 2) ^
            circularLeft64(q[u - 8], 13) ^
            circularLeft64(q[u - 8], 43)) +
            ((q[u - 7] >> 2) ^ (q[u - 7] << 1) ^
            circularLeft64(q[u - 7], 19) ^
            circularLeft64(q[u - 7], 53)) +
            ((q[u - 6] >> 2) ^ (q[u - 6] << 2) ^
            circularLeft64(q[u - 6], 28) ^
            circularLeft64(q[u - 6], 59)) +
            ((q[u - 5] >> 1) ^ (q[u - 5] << 3) ^
            circularLeft64(q[u - 5], 4) ^
            circularLeft64(q[u - 5], 37)) +
            ((q[u - 4] >> 1) ^ (q[u - 4] << 2) ^
            circularLeft64(q[u - 4], 13) ^
            circularLeft64(q[u - 4], 43)) +
            ((q[u - 3] >> 2) ^ (q[u - 3] << 1) ^
            circularLeft64(q[u - 3], 19) ^
            circularLeft64(q[u - 3], 53)) +
            ((q[u - 2] >> 2) ^ (q[u - 2] << 2) ^
            circularLeft64(q[u - 2], 28) ^
            circularLeft64(q[u - 2], 59)) +
            ((q[u - 1] >> 1) ^ (q[u - 1] << 3) ^
            circularLeft64(q[u - 1], 4) ^
            circularLeft64(q[u - 1], 37)) +
            ((circularLeft64(m[(u - 16 + 0) & 15], ((u - 16 + 0) & 15) + 1) +
            circularLeft64(m[(u - 16 + 3) & 15], ((u - 16 + 3) & 15) + 1) -
            circularLeft64(m[(u - 16 + 10) & 15], ((u - 16 + 10) & 15) + 1) +
            K512[u - 16]) ^ h[(u - 16 + 7) & 15])
    }

    for u := 18; u < 32; u++ {
        q[u] = q[u - 16] + circularLeft64(q[u - 15], 5) +
            q[u - 14] + circularLeft64(q[u - 13], 11) +
            q[u - 12] + circularLeft64(q[u - 11], 27) +
            q[u - 10] + circularLeft64(q[u - 9], 32) +
            q[u - 8] + circularLeft64(q[u - 7], 37) +
            q[u - 6] + circularLeft64(q[u - 5], 43) +
            q[u - 4] + circularLeft64(q[u - 3], 53) +
            ((q[u - 2] >> 1) ^ q[u - 2]) +
            ((q[u - 1] >> 2) ^ q[u - 1]) +
            ((circularLeft64(m[(u - 16 + 0) & 15], ((u - 16 + 0) & 15) + 1) +
            circularLeft64(m[(u - 16 + 3) & 15], ((u - 16 + 3) & 15) + 1) -
            circularLeft64(m[(u - 16 + 10) & 15], ((u - 16 + 10) & 15) + 1) +
            K512[u - 16]) ^ h[(u - 16 + 7) & 15])
    }

    xl := q[16] ^ q[17] ^ q[18] ^ q[19] ^
        q[20] ^ q[21] ^ q[22] ^ q[23]
    xh := xl ^ q[24] ^ q[25] ^ q[26] ^ q[27] ^
        q[28] ^ q[29] ^ q[30] ^ q[31]
    h[0] = ((xh << 5) ^ (q[16] >> 5) ^ m[0]) + (xl ^ q[24] ^ q[0])
    h[1] = ((xh >> 7) ^ (q[17] << 8) ^ m[1]) + (xl ^ q[25] ^ q[1])
    h[2] = ((xh >> 5) ^ (q[18] << 5) ^ m[2]) + (xl ^ q[26] ^ q[2])
    h[3] = ((xh >> 1) ^ (q[19] << 5) ^ m[3]) + (xl ^ q[27] ^ q[3])
    h[4] = ((xh >> 3) ^ (q[20] << 0) ^ m[4]) + (xl ^ q[28] ^ q[4])
    h[5] = ((xh << 6) ^ (q[21] >> 6) ^ m[5]) + (xl ^ q[29] ^ q[5])
    h[6] = ((xh >> 4) ^ (q[22] << 6) ^ m[6]) + (xl ^ q[30] ^ q[6])
    h[7] = ((xh >> 11) ^ (q[23] << 2) ^ m[7]) +
        (xl ^ q[31] ^ q[7])
    h[8] = circularLeft64(h[4], 9) + (xh ^ q[24] ^ m[8]) +
        ((xl << 8) ^ q[23] ^ q[8])
    h[9] = circularLeft64(h[5], 10) + (xh ^ q[25] ^ m[9]) +
        ((xl >> 6) ^ q[16] ^ q[9])
    h[10] = circularLeft64(h[6], 11) + (xh ^ q[26] ^ m[10]) +
        ((xl << 6) ^ q[17] ^ q[10])
    h[11] = circularLeft64(h[7], 12) + (xh ^ q[27] ^ m[11]) +
        ((xl << 4) ^ q[18] ^ q[11])
    h[12] = circularLeft64(h[0], 13) + (xh ^ q[28] ^ m[12]) +
        ((xl >> 3) ^ q[19] ^ q[12])
    h[13] = circularLeft64(h[1], 14) + (xh ^ q[29] ^ m[13]) +
        ((xl >> 4) ^ q[20] ^ q[13])
    h[14] = circularLeft64(h[2], 15) + (xh ^ q[30] ^ m[14]) +
        ((xl >> 7) ^ q[21] ^ q[14])
    h[15] = circularLeft64(h[3], 16) + (xh ^ q[31] ^ m[15]) +
        ((xl >> 2) ^ q[22] ^ q[15])
}
