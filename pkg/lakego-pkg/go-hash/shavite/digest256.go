package shavite

const (
    // hash size
    Size224 = 28
    Size256 = 32

    BlockSize256 = 64
)

// digest256 represents the partial evaluation of a checksum.
type digest256 struct {
    s   [8]uint32
    x   [BlockSize256]byte
    nx  int
    len uint64

    rk [144]uint32

    hs      int
    initVal [8]uint32
}

// newDigest256 returns a new hash.Hash computing the checksum
func newDigest256(hs int, initVal [8]uint32) *digest256 {
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

    d.rk = [144]uint32{}
}

func (d *digest256) Size() int {
    return d.hs
}

func (d *digest256) BlockSize() int {
    return BlockSize256
}

func (d *digest256) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    for d.nx + plen >= BlockSize256 {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        d.len += uint64(BlockSize256)

        xx := BlockSize256 - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    d.len += uint64(plen)

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

    bc := d.len / BlockSize256

    bitLen := (bc << 9) + uint64(ptr << 3)

    var cnt0 = uint32(bitLen)
    var cnt1 = uint32(bitLen >> 32)

    var buf = d.x

    if ptr == 0 {
        buf[0] = 0x80
        for i := 1; i < 54; i++ {
            buf[i] = 0
        }
        cnt0 = 0
        cnt1 = 0
    } else if ptr < 54 {
        buf[ptr] = 0x80
        ptr++

        for ptr < 54 {
            buf[ptr] = 0
            ptr++
        }
    } else {
        buf[ptr] = 0x80
        ptr++

        for ptr < 64 {
            buf[ptr] = 0
            ptr++
        }

        d.process(buf[:], cnt0, cnt1)

        for i := 0; i < 54; i++ {
            buf[i] = 0
        }
        cnt0 = 0
        cnt1 = 0
    }

    putu32(buf[54:], uint32(bitLen))
    putu32(buf[58:], uint32(bitLen >> 32))

    dlen := d.hs
    buf[62] = byte(dlen << 3)
    buf[63] = byte(dlen >> 5)
    d.process(buf[:], cnt0, cnt1)

    out = make([]byte, dlen)
    for i := 0; i < dlen; i += 4 {
        putu32(out[i:], d.s[i >> 2])
    }

    return
}

func (d *digest256) processBlock(data []byte) {
    var bitLen = ((d.len / BlockSize256) + 1) << 9

    d.process(data, uint32(bitLen), uint32(bitLen >> 32))
}

func (d *digest256) process(data []byte, cnt0, cnt1 uint32) {
    var p0, p1, p2, p3, p4, p5, p6, p7 uint32
    var u uint32

    h := &d.s
    rk := &d.rk

    for u = 0; u < 16; u += 4 {
        rk[u + 0] = getu32(data[(u << 2) +  0:])
        rk[u + 1] = getu32(data[(u << 2) +  4:])
        rk[u + 2] = getu32(data[(u << 2) +  8:])
        rk[u + 3] = getu32(data[(u << 2) + 12:])
    }

    for r := 0; r < 4; r++ {
        for s := 0; s < 2; s++ {
            var x0, x1, x2, x3 uint32
            var t0, t1, t2, t3 uint32

            x0 = rk[u - 15]
            x1 = rk[u - 14]
            x2 = rk[u - 13]
            x3 = rk[u - 16]
            t0 = AES0[x0 & 0xFF] ^
                AES1[(x1 >> 8) & 0xFF] ^
                AES2[(x2 >> 16) & 0xFF] ^
                AES3[x3 >> 24]
            t1 = AES0[x1 & 0xFF] ^
                AES1[(x2 >> 8) & 0xFF] ^
                AES2[(x3 >> 16) & 0xFF] ^
                AES3[x0 >> 24]
            t2 = AES0[x2 & 0xFF] ^
                AES1[(x3 >> 8) & 0xFF] ^
                AES2[(x0 >> 16) & 0xFF] ^
                AES3[x1 >> 24]
            t3 = AES0[x3 & 0xFF] ^
                AES1[(x0 >> 8) & 0xFF] ^
                AES2[(x1 >> 16) & 0xFF] ^
                AES3[x2 >> 24]
            rk[u + 0] = t0 ^ rk[u - 4]
            rk[u + 1] = t1 ^ rk[u - 3]
            rk[u + 2] = t2 ^ rk[u - 2]
            rk[u + 3] = t3 ^ rk[u - 1]
            if u == 16 {
                rk[ 16] ^= cnt0
                rk[ 17] ^= ^cnt1
            } else if (u == 56) {
                rk[ 57] ^= cnt1
                rk[ 58] ^= ^cnt0
            }
            u += 4

            x0 = rk[u - 15]
            x1 = rk[u - 14]
            x2 = rk[u - 13]
            x3 = rk[u - 16]
            t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
            t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
            t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
            t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
            rk[u + 0] = t0 ^ rk[u - 4]
            rk[u + 1] = t1 ^ rk[u - 3]
            rk[u + 2] = t2 ^ rk[u - 2]
            rk[u + 3] = t3 ^ rk[u - 1]
            if u == 84 {
                rk[ 86] ^= cnt1
                rk[ 87] ^= ^cnt0
            } else if (u == 124) {
                rk[124] ^= cnt0
                rk[127] ^= ^cnt1
            }
            u += 4
        }

        for s := 0; s < 4; s++ {
            rk[u + 0] = rk[u - 16] ^ rk[u - 3]
            rk[u + 1] = rk[u - 15] ^ rk[u - 2]
            rk[u + 2] = rk[u - 14] ^ rk[u - 1]
            rk[u + 3] = rk[u - 13] ^ rk[u - 0]
            u += 4
        }
    }

    p0 = h[0x0]
    p1 = h[0x1]
    p2 = h[0x2]
    p3 = h[0x3]
    p4 = h[0x4]
    p5 = h[0x5]
    p6 = h[0x6]
    p7 = h[0x7]
    u = 0

    for r := 0; r < 6; r++ {
        var x0, x1, x2, x3 uint32
        var t0, t1, t2, t3 uint32

        x0 = p4 ^ rk[u]; u++
        x1 = p5 ^ rk[u]; u++
        x2 = p6 ^ rk[u]; u++
        x3 = p7 ^ rk[u]; u++
        t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
        t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
        t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
        t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
        x0 = t0 ^ rk[u]; u++
        x1 = t1 ^ rk[u]; u++
        x2 = t2 ^ rk[u]; u++
        x3 = t3 ^ rk[u]; u++
        t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
        t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
        t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
        t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
        x0 = t0 ^ rk[u]; u++
        x1 = t1 ^ rk[u]; u++
        x2 = t2 ^ rk[u]; u++
        x3 = t3 ^ rk[u]; u++
        t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
        t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
        t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
        t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
        p0 ^= t0
        p1 ^= t1
        p2 ^= t2
        p3 ^= t3

        x0 = p0 ^ rk[u]; u++
        x1 = p1 ^ rk[u]; u++
        x2 = p2 ^ rk[u]; u++
        x3 = p3 ^ rk[u]; u++
        t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
        t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
        t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
        t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
        x0 = t0 ^ rk[u]; u++
        x1 = t1 ^ rk[u]; u++
        x2 = t2 ^ rk[u]; u++
        x3 = t3 ^ rk[u]; u++
        t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
        t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
        t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
        t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
        x0 = t0 ^ rk[u]; u++
        x1 = t1 ^ rk[u]; u++
        x2 = t2 ^ rk[u]; u++
        x3 = t3 ^ rk[u]; u++
        t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
        t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
        t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
        t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
        p4 ^= t0
        p5 ^= t1
        p6 ^= t2
        p7 ^= t3
    }

    h[0x0] ^= p0
    h[0x1] ^= p1
    h[0x2] ^= p2
    h[0x3] ^= p3
    h[0x4] ^= p4
    h[0x5] ^= p5
    h[0x6] ^= p6
    h[0x7] ^= p7
}

