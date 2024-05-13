package shavite

const (
    // hash size
    Size384 = 48
    Size512 = 64

    BlockSize512 = 128
)

// digest512 represents the partial evaluation of a checksum.
type digest512 struct {
    s   [16]uint32
    x   [BlockSize512]byte
    nx  int
    len uint64

    rk [448]uint32

    hs      int
    initVal [16]uint32
}

// newDigest512 returns a new hash.Hash computing the checksum
func newDigest512(hs int, initVal [16]uint32) *digest512 {
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

    d.rk = [448]uint32{}
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

    for d.nx + plen >= BlockSize512 {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        d.len += uint64(BlockSize512)

        xx := BlockSize512 - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    d.len += uint64(plen)

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

    bc := d.len / BlockSize512

    bitLen := (bc << 10) + uint64(ptr << 3)

    var cnt0 = uint32(bitLen)
    var cnt1 = uint32(bitLen >> 32)
    var cnt2 = uint32(bc >> 54)

    var buf = d.x

    if ptr == 0 {
        buf[0] = 0x80
        for i := 1; i < 110; i++ {
            buf[i] = 0
        }
        cnt0 = 0
        cnt1 = 0
        cnt2 = 0
    } else if ptr < 110 {
        buf[ptr] = 0x80
        ptr++

        for ptr < 110 {
            buf[ptr] = 0
            ptr++
        }
    } else {
        buf[ptr] = 0x80
        ptr++

        for ptr < 128 {
            buf[ptr] = 0
            ptr++
        }

        d.process(buf[:], cnt0, cnt1, cnt2)

        for i := 0; i < 110; i++ {
            buf[i] = 0
        }
        cnt0 = 0
        cnt1 = 0
        cnt2 = 0
    }

    putu32(buf[110:], uint32(bitLen))
    putu32(buf[114:], uint32(bitLen >> 32))
    putu32(buf[118:], uint32(bc >> 54))

    buf[122] = 0
    buf[123] = 0
    buf[124] = 0
    buf[125] = 0

    dlen := d.hs
    buf[126] = byte(dlen << 3)
    buf[127] = byte(dlen >> 5)
    d.process(buf[:], cnt0, cnt1, cnt2)

    out = make([]byte, dlen)

    for i := 0; i < dlen; i += 4 {
        putu32(out[i:], d.s[i >> 2])
    }

    return
}

func (d *digest512) processBlock(data []byte) {
    var bc = (d.len / BlockSize512) + 1
    var bitLen = bc << 10

    d.process(data, uint32(bitLen), uint32(bitLen >> 32), uint32(bc >> 54))
}

func (d *digest512) process(data []byte, cnt0, cnt1, cnt2 uint32) {
    var p0, p1, p2, p3, p4, p5, p6, p7 uint32
    var p8, p9, pA, pB, pC, pD, pE, pF uint32
    var u uint32

    h := &d.s
    rk := &d.rk

    for u = 0; u < 32; u += 4 {
        rk[u + 0] = getu32(data[(u << 2) +  0:])
        rk[u + 1] = getu32(data[(u << 2) +  4:])
        rk[u + 2] = getu32(data[(u << 2) +  8:])
        rk[u + 3] = getu32(data[(u << 2) + 12:])
    }

    for {
        for s := 0; s < 4; s++ {
            var x0, x1, x2, x3 uint32
            var t0, t1, t2, t3 uint32

            x0 = rk[u - 31]
            x1 = rk[u - 30]
            x2 = rk[u - 29]
            x3 = rk[u - 32]
            t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
            t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
            t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
            t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
            rk[u + 0] = t0 ^ rk[u - 4]
            rk[u + 1] = t1 ^ rk[u - 3]
            rk[u + 2] = t2 ^ rk[u - 2]
            rk[u + 3] = t3 ^ rk[u - 1]
            if u == 32 {
                rk[ 32] ^= cnt0
                rk[ 33] ^= cnt1
                rk[ 34] ^= cnt2
                // rk[ 35] ^= ^0
                tmp35 := ^0
                rk[ 35] ^= uint32(tmp35)
            } else if u == 440 {
                rk[440] ^= cnt1
                rk[441] ^= cnt0
                // rk[442] ^= 0
                rk[443] ^= ^cnt2
            }
            u += 4

            x0 = rk[u - 31]
            x1 = rk[u - 30]
            x2 = rk[u - 29]
            x3 = rk[u - 32]
            t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
            t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
            t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
            t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
            rk[u + 0] = t0 ^ rk[u - 4]
            rk[u + 1] = t1 ^ rk[u - 3]
            rk[u + 2] = t2 ^ rk[u - 2]
            rk[u + 3] = t3 ^ rk[u - 1]
            if u == 164 {
                // rk[164] ^= 0
                rk[165] ^= cnt2
                rk[166] ^= cnt1
                rk[167] ^= ^cnt0
            } else if u == 316 {
                rk[316] ^= cnt2
                //rk[317] ^= 0
                rk[318] ^= cnt0
                rk[319] ^= ^cnt1
            }
            u += 4
        }

        if u == 448 {
            break
        }

        for s := 0; s < 8; s++ {
            rk[u + 0] = rk[u - 32] ^ rk[u - 7]
            rk[u + 1] = rk[u - 31] ^ rk[u - 6]
            rk[u + 2] = rk[u - 30] ^ rk[u - 5]
            rk[u + 3] = rk[u - 29] ^ rk[u - 4]
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
    p8 = h[0x8]
    p9 = h[0x9]
    pA = h[0xA]
    pB = h[0xB]
    pC = h[0xC]
    pD = h[0xD]
    pE = h[0xE]
    pF = h[0xF]
    u = 0
    for r := 0; r < 14; r++ {
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

        x0 = pC ^ rk[u]; u++
        x1 = pD ^ rk[u]; u++
        x2 = pE ^ rk[u]; u++
        x3 = pF ^ rk[u]; u++
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
        x0 = t0 ^ rk[u]; u++
        x1 = t1 ^ rk[u]; u++
        x2 = t2 ^ rk[u]; u++
        x3 = t3 ^ rk[u]; u++
        t0 = AES0[x0 & 0xFF] ^ AES1[(x1 >> 8) & 0xFF] ^ AES2[(x2 >> 16) & 0xFF] ^ AES3[x3 >> 24]
        t1 = AES0[x1 & 0xFF] ^ AES1[(x2 >> 8) & 0xFF] ^ AES2[(x3 >> 16) & 0xFF] ^ AES3[x0 >> 24]
        t2 = AES0[x2 & 0xFF] ^ AES1[(x3 >> 8) & 0xFF] ^ AES2[(x0 >> 16) & 0xFF] ^ AES3[x1 >> 24]
        t3 = AES0[x3 & 0xFF] ^ AES1[(x0 >> 8) & 0xFF] ^ AES2[(x1 >> 16) & 0xFF] ^ AES3[x2 >> 24]
        p8 ^= t0
        p9 ^= t1
        pA ^= t2
        pB ^= t3

        var tmp = pC
        pC = p8
        p8 = p4
        p4 = p0
        p0 = tmp
        tmp = pD
        pD = p9
        p9 = p5
        p5 = p1
        p1 = tmp
        tmp = pE
        pE = pA
        pA = p6
        p6 = p2
        p2 = tmp
        tmp = pF
        pF = pB
        pB = p7
        p7 = p3
        p3 = tmp
    }
    h[0x0] ^= p0
    h[0x1] ^= p1
    h[0x2] ^= p2
    h[0x3] ^= p3
    h[0x4] ^= p4
    h[0x5] ^= p5
    h[0x6] ^= p6
    h[0x7] ^= p7
    h[0x8] ^= p8
    h[0x9] ^= p9
    h[0xA] ^= pA
    h[0xB] ^= pB
    h[0xC] ^= pC
    h[0xD] ^= pD
    h[0xE] ^= pE
    h[0xF] ^= pF
}

