package skeins

const (
    // hash size
    Size384 = 48
    Size512 = 64

    BlockSize512 = 64
)

// digest512 represents the partial evaluation of a checksum.
type digest512 struct {
    s   [27]uint64
    x   [BlockSize512]byte
    nx  int
    len uint64

    bcount uint64

    hs      int
    initVal [8]uint64
}

// newDigest512 returns a new hash.Hash computing the checksum
func newDigest512(hs int, initVal [8]uint64) *digest512 {
    d := new(digest512)
    d.hs = hs
    d.initVal = initVal
    d.Reset()

    return d
}

func (d *digest512) Reset() {
    copy(d.s[:], d.initVal[:])

    d.x = [BlockSize512]byte{}
    d.nx = 0
    d.len = 0

    d.bcount = 0
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

    var etype int

    plen := len(p)
    for d.nx + plen >= BlockSize512 {
        copy(d.x[d.nx:], p)

        if d.bcount == 0 {
            etype = 224
        } else {
            etype = 96
        }
        d.bcount++

        d.ubi(etype, 0)

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

    for i := ptr; i < BlockSize512; i++ {
        d.x[i] = 0x00
    }

    if d.bcount == 0 {
        d.ubi(480, ptr)
    } else {
        d.ubi(352, ptr)
    }

    for i := 0; i < BlockSize512; i++ {
        d.x[i] = 0x00
    }

    d.bcount = 0
    d.ubi(510, 8)

    buf := make([]byte, BlockSize512)
    for i := 0; i < 8; i++ {
        putu64(buf[8*i:], d.s[i])
    }

    out = make([]byte, d.hs)
    copy(out, buf)

    return
}

func (d *digest512) ubi(etype int, extra int) {
    var m0 = getu64(d.x[0:])
    var m1 = getu64(d.x[8:])
    var m2 = getu64(d.x[16:])
    var m3 = getu64(d.x[24:])
    var m4 = getu64(d.x[32:])
    var m5 = getu64(d.x[40:])
    var m6 = getu64(d.x[48:])
    var m7 = getu64(d.x[56:])

    h := &d.s

    var p0 = m0
    var p1 = m1
    var p2 = m2
    var p3 = m3
    var p4 = m4
    var p5 = m5
    var p6 = m6
    var p7 = m7

    h[8] = ((h[0] ^ h[1]) ^ (h[2] ^ h[3])) ^
           ((h[4] ^ h[5]) ^ (h[6] ^ h[7])) ^ 0x1BD11BDAA9FC1A22
    var t0 = (d.bcount << 6) + uint64(extra)
    var t1 = (d.bcount >> 58) + (uint64(etype) << 55)
    var t2 = t0 ^ t1

    for u := 0; u <= 15; u += 3 {
        h[u + 9] = h[u + 0]
        h[u + 10] = h[u + 1]
        h[u + 11] = h[u + 2]
    }

    for u := 0; u < 9; u++ {
        s := u << 1
        p0 += h[s + 0]
        p1 += h[s + 1]
        p2 += h[s + 2]
        p3 += h[s + 3]
        p4 += h[s + 4]
        p5 += h[s + 5] + t0
        p6 += h[s + 6] + t1
        p7 += h[s + 7] + uint64(s)
        p0 += p1
        p1 = (p1 << 46) ^ (p1 >> (64 - 46)) ^ p0
        p2 += p3
        p3 = (p3 << 36) ^ (p3 >> (64 - 36)) ^ p2
        p4 += p5
        p5 = (p5 << 19) ^ (p5 >> (64 - 19)) ^ p4
        p6 += p7
        p7 = (p7 << 37) ^ (p7 >> (64 - 37)) ^ p6
        p2 += p1
        p1 = (p1 << 33) ^ (p1 >> (64 - 33)) ^ p2
        p4 += p7
        p7 = (p7 << 27) ^ (p7 >> (64 - 27)) ^ p4
        p6 += p5
        p5 = (p5 << 14) ^ (p5 >> (64 - 14)) ^ p6
        p0 += p3
        p3 = (p3 << 42) ^ (p3 >> (64 - 42)) ^ p0
        p4 += p1
        p1 = (p1 << 17) ^ (p1 >> (64 - 17)) ^ p4
        p6 += p3
        p3 = (p3 << 49) ^ (p3 >> (64 - 49)) ^ p6
        p0 += p5
        p5 = (p5 << 36) ^ (p5 >> (64 - 36)) ^ p0
        p2 += p7
        p7 = (p7 << 39) ^ (p7 >> (64 - 39)) ^ p2
        p6 += p1
        p1 = (p1 << 44) ^ (p1 >> (64 - 44)) ^ p6
        p0 += p7
        p7 = (p7 << 9) ^ (p7 >> (64 - 9)) ^ p0
        p2 += p5
        p5 = (p5 << 54) ^ (p5 >> (64 - 54)) ^ p2
        p4 += p3
        p3 = (p3 << 56) ^ (p3 >> (64 - 56)) ^ p4
        p0 += h[s + 1 + 0]
        p1 += h[s + 1 + 1]
        p2 += h[s + 1 + 2]
        p3 += h[s + 1 + 3]
        p4 += h[s + 1 + 4]
        p5 += h[s + 1 + 5] + t1
        p6 += h[s + 1 + 6] + t2
        p7 += h[s + 1 + 7] + uint64(s) + 1
        p0 += p1
        p1 = (p1 << 39) ^ (p1 >> (64 - 39)) ^ p0
        p2 += p3
        p3 = (p3 << 30) ^ (p3 >> (64 - 30)) ^ p2
        p4 += p5
        p5 = (p5 << 34) ^ (p5 >> (64 - 34)) ^ p4
        p6 += p7
        p7 = (p7 << 24) ^ (p7 >> (64 - 24)) ^ p6
        p2 += p1
        p1 = (p1 << 13) ^ (p1 >> (64 - 13)) ^ p2
        p4 += p7
        p7 = (p7 << 50) ^ (p7 >> (64 - 50)) ^ p4
        p6 += p5
        p5 = (p5 << 10) ^ (p5 >> (64 - 10)) ^ p6
        p0 += p3
        p3 = (p3 << 17) ^ (p3 >> (64 - 17)) ^ p0
        p4 += p1
        p1 = (p1 << 25) ^ (p1 >> (64 - 25)) ^ p4
        p6 += p3
        p3 = (p3 << 29) ^ (p3 >> (64 - 29)) ^ p6
        p0 += p5
        p5 = (p5 << 39) ^ (p5 >> (64 - 39)) ^ p0
        p2 += p7
        p7 = (p7 << 43) ^ (p7 >> (64 - 43)) ^ p2
        p6 += p1
        p1 = (p1 << 8) ^ (p1 >> (64 - 8)) ^ p6
        p0 += p7
        p7 = (p7 << 35) ^ (p7 >> (64 - 35)) ^ p0
        p2 += p5
        p5 = (p5 << 56) ^ (p5 >> (64 - 56)) ^ p2
        p4 += p3
        p3 = (p3 << 22) ^ (p3 >> (64 - 22)) ^ p4

        var tmp = t2
        t2 = t1
        t1 = t0
        t0 = tmp
    }

    p0 += h[18 + 0]
    p1 += h[18 + 1]
    p2 += h[18 + 2]
    p3 += h[18 + 3]
    p4 += h[18 + 4]
    p5 += h[18 + 5] + t0
    p6 += h[18 + 6] + t1
    p7 += h[18 + 7] + 18

    h[0] = m0 ^ p0
    h[1] = m1 ^ p1
    h[2] = m2 ^ p2
    h[3] = m3 ^ p3
    h[4] = m4 ^ p4
    h[5] = m5 ^ p5
    h[6] = m6 ^ p6
    h[7] = m7 ^ p7
}

