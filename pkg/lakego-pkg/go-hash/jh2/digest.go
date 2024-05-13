package jh2

const (
    // hash size
    Size224 = 28
    Size256 = 32
    Size384 = 48
    Size512 = 64

    BlockSize = 64
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [16]uint64
    x   [BlockSize]byte
    nx  int
    len uint64

    hs      int
    initVal [16]uint64
}

// newDigest returns a new *digest computing the checksum
func newDigest(hs int, initVal [16]uint64) *digest {
    d := new(digest)
    d.hs = hs
    d.initVal = initVal
    d.Reset()

    return d
}

func (d *digest) Reset() {
    d.s = d.initVal
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0
}

func (d *digest) Size() int {
    return d.hs
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)
    for d.nx + plen >= BlockSize {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        xx := BlockSize - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() (out []byte) {
    var rem = d.nx
    var bc = d.len / BlockSize

    var numz int
    if rem == 0 {
        numz = 47
    } else {
        numz = 111 - rem
    }

    var tmpBuf [128]byte

    tmpBuf[0] = 0x80
    for i := 1; i <= numz; i++ {
        tmpBuf[i] = 0x00
    }

    putu64(tmpBuf[numz + 1:], bc >> 55)
    putu64(tmpBuf[numz + 9:], (bc << 9) + (uint64(rem) << 3))

    d.Write(tmpBuf[0:numz + 17])

    for i := 0; i < 8; i++ {
        putu64(tmpBuf[i << 3:], d.s[i + 8])
    }

    var dlen = d.hs

    out = make([]byte, dlen)
    copy(out, tmpBuf[64 - dlen:])

    return
}

func (d *digest) processBlock(data []byte) {
    h := &d.s

    var m0h = getu64(data[ 0:])
    var m0l = getu64(data[ 8:])
    var m1h = getu64(data[16:])
    var m1l = getu64(data[24:])
    var m2h = getu64(data[32:])
    var m2l = getu64(data[40:])
    var m3h = getu64(data[48:])
    var m3l = getu64(data[56:])

    h[0] ^= m0h
    h[1] ^= m0l
    h[2] ^= m1h
    h[3] ^= m1l
    h[4] ^= m2h
    h[5] ^= m2l
    h[6] ^= m3h
    h[7] ^= m3l

    for r := 0; r < 42; r += 7 {
        d.doS(r + 0)
        d.doL()
        d.doWgen(0x5555555555555555,  1)
        d.doS(r + 1)
        d.doL()
        d.doWgen(0x3333333333333333,  2)
        d.doS(r + 2)
        d.doL()
        d.doWgen(0x0F0F0F0F0F0F0F0F,  4)
        d.doS(r + 3)
        d.doL()
        d.doWgen(0x00FF00FF00FF00FF,  8)
        d.doS(r + 4)
        d.doL()
        d.doWgen(0x0000FFFF0000FFFF, 16)
        d.doS(r + 5)
        d.doL()
        d.doWgen(0x00000000FFFFFFFF, 32)
        d.doS(r + 6)
        d.doL()
        d.doW6()
    }

    h[ 8] ^= m0h
    h[ 9] ^= m0l
    h[10] ^= m1h
    h[11] ^= m1l
    h[12] ^= m2h
    h[13] ^= m2l
    h[14] ^= m3h
    h[15] ^= m3l
}

func (d *digest) doS(r int) {
    h := &d.s

    var x0, x1, x2, x3, cc, tmp uint64

    cc = C[(r << 2) + 0]
    x0 = h[ 0]
    x1 = h[ 4]
    x2 = h[ 8]
    x3 = h[12]
    x3 = ^x3
    x0 ^= cc & ^x2
    tmp = cc ^ (x0 & x1)
    x0 ^= x2 & x3
    x3 ^= ^x1 & x2
    x1 ^= x0 & x2
    x2 ^= x0 & ^x3
    x0 ^= x1 | x3
    x3 ^= x1 & x2
    x1 ^= tmp & x0
    x2 ^= tmp
    h[ 0] = x0
    h[ 4] = x1
    h[ 8] = x2
    h[12] = x3

    cc = C[(r << 2) + 1]
    x0 = h[ 1]
    x1 = h[ 5]
    x2 = h[ 9]
    x3 = h[13]
    x3 = ^x3
    x0 ^= cc & ^x2
    tmp = cc ^ (x0 & x1)
    x0 ^= x2 & x3
    x3 ^= ^x1 & x2
    x1 ^= x0 & x2
    x2 ^= x0 & ^x3
    x0 ^= x1 | x3
    x3 ^= x1 & x2
    x1 ^= tmp & x0
    x2 ^= tmp
    h[ 1] = x0
    h[ 5] = x1
    h[ 9] = x2
    h[13] = x3

    cc = C[(r << 2) + 2]
    x0 = h[ 2]
    x1 = h[ 6]
    x2 = h[10]
    x3 = h[14]
    x3 = ^x3
    x0 ^= cc & ^x2
    tmp = cc ^ (x0 & x1)
    x0 ^= x2 & x3
    x3 ^= ^x1 & x2
    x1 ^= x0 & x2
    x2 ^= x0 & ^x3
    x0 ^= x1 | x3
    x3 ^= x1 & x2
    x1 ^= tmp & x0
    x2 ^= tmp
    h[ 2] = x0
    h[ 6] = x1
    h[10] = x2
    h[14] = x3

    cc = C[(r << 2) + 3]
    x0 = h[ 3]
    x1 = h[ 7]
    x2 = h[11]
    x3 = h[15]
    x3 = ^x3
    x0 ^= cc & ^x2
    tmp = cc ^ (x0 & x1)
    x0 ^= x2 & x3
    x3 ^= ^x1 & x2
    x1 ^= x0 & x2
    x2 ^= x0 & ^x3
    x0 ^= x1 | x3
    x3 ^= x1 & x2
    x1 ^= tmp & x0
    x2 ^= tmp
    h[ 3] = x0
    h[ 7] = x1
    h[11] = x2
    h[15] = x3
}

func (d *digest) doL() {
    h := &d.s

    var x0, x1, x2, x3, x4, x5, x6, x7 uint64

    x0 = h[ 0]
    x1 = h[ 4]
    x2 = h[ 8]
    x3 = h[12]
    x4 = h[ 2]
    x5 = h[ 6]
    x6 = h[10]
    x7 = h[14]
    x4 ^= x1
    x5 ^= x2
    x6 ^= x3 ^ x0
    x7 ^= x0
    x0 ^= x5
    x1 ^= x6
    x2 ^= x7 ^ x4
    x3 ^= x4
    h[ 0] = x0
    h[ 4] = x1
    h[ 8] = x2
    h[12] = x3
    h[ 2] = x4
    h[ 6] = x5
    h[10] = x6
    h[14] = x7

    x0 = h[ 1]
    x1 = h[ 5]
    x2 = h[ 9]
    x3 = h[13]
    x4 = h[ 3]
    x5 = h[ 7]
    x6 = h[11]
    x7 = h[15]
    x4 ^= x1
    x5 ^= x2
    x6 ^= x3 ^ x0
    x7 ^= x0
    x0 ^= x5
    x1 ^= x6
    x2 ^= x7 ^ x4
    x3 ^= x4
    h[ 1] = x0
    h[ 5] = x1
    h[ 9] = x2
    h[13] = x3
    h[ 3] = x4
    h[ 7] = x5
    h[11] = x6
    h[15] = x7
}

func (d *digest) doWgen(c uint64, n int) {
    h := &d.s

    h[ 2] = ((h[ 2] & c) << n) | ((h[ 2] >> n) & c)
    h[ 3] = ((h[ 3] & c) << n) | ((h[ 3] >> n) & c)
    h[ 6] = ((h[ 6] & c) << n) | ((h[ 6] >> n) & c)
    h[ 7] = ((h[ 7] & c) << n) | ((h[ 7] >> n) & c)
    h[10] = ((h[10] & c) << n) | ((h[10] >> n) & c)
    h[11] = ((h[11] & c) << n) | ((h[11] >> n) & c)
    h[14] = ((h[14] & c) << n) | ((h[14] >> n) & c)
    h[15] = ((h[15] & c) << n) | ((h[15] >> n) & c)
}

func (d *digest) doW6() {
    h := &d.s

    var t uint64
    t = h[ 2]; h[ 2] = h[ 3]; h[ 3] = t
    t = h[ 6]; h[ 6] = h[ 7]; h[ 7] = t
    t = h[10]; h[10] = h[11]; h[11] = t
    t = h[14]; h[14] = h[15]; h[15] = t
}
