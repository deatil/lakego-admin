package lsh256

import (
    "hash"
    "math/bits"
    "encoding/binary"
)

const (
    numStep = 26

    alphaEven = 29
    alphaOdd  = 5

    betaEven = 1
    betaOdd  = 17
)

type digest struct {
    s   [16]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    tcv [16]uint32
    msg [16 * (numStep + 1)]uint32

    hs int
}

func newDigest(size int) hash.Hash {
    ctx := new(digest)
    ctx.hs = size
    ctx.Reset()
    return ctx
}

func (d *digest) Size() int {
    return d.hs
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Reset() {
    d.tcv = [16]uint32{}
    d.msg = [16 * (numStep + 1)]uint32{}

    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0

    switch d.hs {
        case Size:
            d.s = iv256
        case Size224:
            d.s = iv224
    }
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize
    for d.nx + plen >= limit {
        xx := limit - d.nx

        copy(d.x[d.nx:], p)

        d.compress(d.x[:])

        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest) Sum(p []byte) []byte {
    d0 := *d
    hash := d0.checkSum()
    return append(p, hash[:d.Size()]...)
}

func (d *digest) checkSum() [Size]byte {
    d.x[d.nx] = 0x80

    zeros := make([]byte, BlockSize)

    copy(d.x[d.nx+1:], zeros)
    d.compress(d.x[:])

    var temp [8]uint32
    for i := 0; i < 8; i++ {
        temp[i] = d.s[i] ^ d.s[i+8]
    }

    var digest [Size]byte
    for i := 0; i < d.hs; i++ {
        digest[i] = byte(temp[i>>2] >> ((i << 3) & 0x1f))
    }

    return digest
}

func (d *digest) compress(data []byte) {
    d.msgExpansion(data)

    for i := 0; i < numStep/2; i++ {
        d.step(2*i+0, alphaEven, betaEven)
        d.step(2*i+1, alphaOdd, betaOdd)
    }

    for i := 0; i < 16; i++ {
        d.s[i] ^= d.msg[16*numStep+i]
    }
}

func (d *digest) msgExpansion(in []byte) {
    for i := 0; i < 32; i++ {
        d.msg[i] = binary.LittleEndian.Uint32(in[i*4:])
    }

    for i := 2; i <= numStep; i++ {
        idx := 16 * i
        d.msg[idx] = d.msg[idx-16] + d.msg[idx-29]
        d.msg[idx+1] = d.msg[idx-15] + d.msg[idx-30]
        d.msg[idx+2] = d.msg[idx-14] + d.msg[idx-32]
        d.msg[idx+3] = d.msg[idx-13] + d.msg[idx-31]
        d.msg[idx+4] = d.msg[idx-12] + d.msg[idx-25]
        d.msg[idx+5] = d.msg[idx-11] + d.msg[idx-28]
        d.msg[idx+6] = d.msg[idx-10] + d.msg[idx-27]
        d.msg[idx+7] = d.msg[idx-9] + d.msg[idx-26]
        d.msg[idx+8] = d.msg[idx-8] + d.msg[idx-21]
        d.msg[idx+9] = d.msg[idx-7] + d.msg[idx-22]
        d.msg[idx+10] = d.msg[idx-6] + d.msg[idx-24]
        d.msg[idx+11] = d.msg[idx-5] + d.msg[idx-23]
        d.msg[idx+12] = d.msg[idx-4] + d.msg[idx-17]
        d.msg[idx+13] = d.msg[idx-3] + d.msg[idx-20]
        d.msg[idx+14] = d.msg[idx-2] + d.msg[idx-19]
        d.msg[idx+15] = d.msg[idx-1] + d.msg[idx-18]
    }
}
func (d *digest) step(stepidx, alpha, beta int) {
    var vl, vr uint32

    for colidx := 0; colidx < 8; colidx++ {
        vl = d.s[colidx] ^ d.msg[16*stepidx+colidx]
        vr = d.s[colidx+8] ^ d.msg[16*stepidx+colidx+8]
        vl = bits.RotateLeft32(vl+vr, alpha) ^ step[8*stepidx+colidx]
        vr = bits.RotateLeft32(vl+vr, beta)
        d.tcv[colidx] = vr + vl
        d.tcv[colidx+8] = bits.RotateLeft32(vr, gamma[colidx])
    }

    // wordPermutation
    d.s[0] = d.tcv[6]
    d.s[1] = d.tcv[4]
    d.s[2] = d.tcv[5]
    d.s[3] = d.tcv[7]
    d.s[4] = d.tcv[12]
    d.s[5] = d.tcv[15]
    d.s[6] = d.tcv[14]
    d.s[7] = d.tcv[13]
    d.s[8] = d.tcv[2]
    d.s[9] = d.tcv[0]
    d.s[10] = d.tcv[1]
    d.s[11] = d.tcv[3]
    d.s[12] = d.tcv[8]
    d.s[13] = d.tcv[11]
    d.s[14] = d.tcv[10]
    d.s[15] = d.tcv[9]
}
